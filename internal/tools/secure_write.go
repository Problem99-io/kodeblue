package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/definitions"
	"golang.org/x/sys/unix"
)

// checkWrite stops a write once the run has been cancelled.
func checkWrite(ctx context.Context, path string) error {
	_ = path
	return ctx.Err()
}

// parentFD walks directory entries without following symlinks and retains an
// anchored descriptor. Swapping a parent path cannot redirect the final write.
func parentFD(root, path string, create bool) (int, string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return -1, "", fmt.Errorf("write target outside workspace")
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT && create {
			e = unix.Mkdirat(fd, part, 0o775)
			if e == nil || e == unix.EEXIST {
				next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		unix.Close(fd)
		if e != nil {
			return -1, "", e
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

// secureWrite replaces path with data so that a crash at any moment leaves
// either the old file or the new one, never an empty or partial one. The data
// goes to a fresh temporary file created through the anchored parent
// descriptor (so no symlink is followed), is fsynced and closed, and is then
// renamed over the target; the directory is fsynced last so the rename itself
// survives a crash. Without overwrite the rename refuses to replace a target
// that already exists. An existing target must be a regular, singly-linked
// file; its permission bits carry over to the new file.
func secureWrite(ctx context.Context, root, path string, data []byte, overwrite bool) error {
	if err := checkWrite(ctx, path); err != nil {
		return err
	}
	fd, leaf, err := parentFD(root, path, true)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	keepMode := false
	switch err := unix.Fstatat(fd, leaf, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		if !overwrite {
			return unix.EEXIST
		}
		if err := checkReplaceable(fd, leaf, &st, os.Geteuid()); err != nil {
			return err
		}
		keepMode = true
	case err != unix.ENOENT:
		return err
	}

	tmp, tmpFD, err := createTempAt(fd)
	if err != nil {
		return err
	}
	placed := false
	defer func() {
		if !placed {
			_ = unix.Unlinkat(fd, tmp, 0)
		}
	}()
	file := os.NewFile(uintptr(tmpFD), tmp)
	if keepMode {
		if err := unix.Fchmod(tmpFD, uint32(st.Mode)&0o777); err != nil {
			file.Close()
			return err
		}
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := checkWrite(ctx, path); err != nil {
		return err
	}
	if overwrite {
		err = unix.Renameat(fd, tmp, fd, leaf)
	} else {
		err = renameNoReplace(fd, tmp, leaf)
	}
	if err != nil {
		return err
	}
	placed = true
	return unix.Fsync(fd)
}

// checkReplaceable refuses to replace an existing file the engine could not
// have written in place. A rename needs write access only to the directory,
// so without this the engine could swap out, and take ownership of, a file
// that belongs to another user or that it may not write.
func checkReplaceable(dirFD int, leaf string, st *unix.Stat_t, euid int) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return fmt.Errorf("refusing non-regular or hard-linked write target")
	}
	if int(st.Uid) != euid {
		return fmt.Errorf("refusing to replace a file owned by another user (uid %d)", st.Uid)
	}
	probe, err := unix.Openat(dirFD, leaf, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("refusing to replace a file the engine cannot write: %w", err)
	}
	return unix.Close(probe)
}

// tempFilePattern matches the names createTempAt gives its files.
var tempFilePattern = regexp.MustCompile(`^\.kodeblue-[0-9a-f]{16}\.tmp$`)

// IsTempFile reports whether name is one of secureWrite's temporary files.
func IsTempFile(name string) bool { return tempFilePattern.MatchString(name) }

// RemoveTempFiles deletes temporary files that writes interrupted by a crash
// left behind: secureWrite's anywhere under root (symlinks are not followed),
// and the definitions store's in its directory. The engine calls it at
// startup, before it writes anything, with olderThan 0: it is the workspace's
// only writer, so every temporary file there is left over.
func RemoveTempFiles(root, definitionsRoot string, olderThan time.Duration) {
	seen := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if seen++; seen > maxTempWalk {
			return fs.SkipAll
		}
		if err != nil || d.IsDir() || !IsTempFile(d.Name()) {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) >= olderThan {
			_ = os.Remove(path)
		}
		return nil
	})
	definitions.NewStore(definitionsRoot).RemoveTempFiles(olderThan)
}

// maxTempWalk bounds the startup sweep, in case the project root is a large
// tree rather than kodeblue's small workspace.
const maxTempWalk = 100_000

// createTempAt creates a new, empty temporary file in the directory dirFD.
// The name starts with a dot and ends in .tmp, so listings and readers that
// look for real files skip a temporary one a crash left behind.
func createTempAt(dirFD int) (string, int, error) {
	for range 10 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", -1, err
		}
		name := ".kodeblue-" + hex.EncodeToString(b[:]) + ".tmp"
		fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o664)
		if err == unix.EEXIST {
			continue
		}
		return name, fd, err
	}
	return "", -1, fmt.Errorf("could not create a temporary file")
}

// linkNoReplace places from at to by hard-linking it, which fails if to
// exists, then removes from. It is the fallback for filesystems without an
// exclusive rename.
func linkNoReplace(dirFD int, from, to string) error {
	if err := unix.Linkat(dirFD, from, dirFD, to, 0); err != nil {
		return err
	}
	return unix.Unlinkat(dirFD, from, 0)
}
