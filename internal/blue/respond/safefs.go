package respond

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// The helper runs as root but acts on paths other users control: a home
// directory, ~/.ssh, a file dropped in /tmp. A plain open would follow a
// symlink planted there and let that user make root read or write any file
// (/etc/shadow, /etc/cron.d). So every path is walked one component at a time
// from a directory descriptor. A symlink is followed only when it sits in a
// directory that only root can change (/var -> /private/var, /home -> var/home
// on some distributions); everywhere else it is refused.
//
// A path under /proc/<pid>/root is walked inside that process's root (a
// container's filesystem, for one): the walk starts there, and a symlink in it
// resolves against that root, never the host's, so it cannot climb out.

const maxLinkDepth = 8

var errUnsafeLink = errors.New("refusing to follow a symlink in a directory another user can change")

var procRootRe = regexp.MustCompile(`^(/proc/[0-9]+/root)(/.*)?$`)

// splitProcRoot returns the /proc/<pid>/root prefix of path ("" if none) and
// the path inside it.
func splitProcRoot(path string) (base, inner string) {
	if m := procRootRe.FindStringSubmatch(path); m != nil {
		if m[2] == "" {
			return m[1], "/"
		}
		return m[1], m[2]
	}
	return "", path
}

// openDir opens directory path. The result is a descriptor the caller closes
// with unix.Close.
func openDir(path string) (int, error) {
	fd, _, err := walkDir(path, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fd, nil
}

func walkDir(path string, depth int) (fd int, trusted bool, err error) {
	if depth > maxLinkDepth {
		return -1, false, unix.ELOOP
	}
	if !filepath.IsAbs(path) {
		return -1, false, errors.New("not an absolute path")
	}
	path = filepath.Clean(path)
	base, inner := splitProcRoot(path)
	start := "/"
	if base != "" {
		start = base // the kernel resolves this link to the process's root
	}
	fd, err = unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false, err
	}
	trusted = rootOnly(fd)
	cur := "/" // inside base
	for _, name := range strings.Split(strings.TrimPrefix(inner, "/"), "/") {
		if name == "" {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(fd)
			return -1, false, err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			if !trusted || st.Uid != 0 {
				unix.Close(fd)
				return -1, false, errUnsafeLink
			}
			target, err := readlinkat(fd, name)
			unix.Close(fd)
			if err != nil {
				return -1, false, err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(cur, target)
			}
			target = filepath.Clean(target) // "/.." stays "/": no climbing out of base
			if fd, trusted, err = walkDir(base+target, depth+1); err != nil {
				return -1, false, err
			}
			cur = target
			continue
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, false, err
		}
		fd, cur = next, filepath.Join(cur, name)
		trusted = trusted && rootOnly(fd)
	}
	return fd, trusted, nil
}

// rootOnly reports whether only root can add, remove or rename entries in
// the directory fd.
func rootOnly(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Uid == 0 && st.Mode&0o022 == 0
}

func readlinkat(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	if n == len(buf) {
		return "", unix.ENAMETOOLONG
	}
	return string(buf[:n]), nil
}

// openIn opens name inside the directory dirfd without following a symlink.
// O_NONBLOCK keeps a planted FIFO from hanging the helper; it does nothing
// for regular files.
func openIn(dirfd int, dirPath, name string, flag int, perm uint32) (*os.File, error) {
	path := filepath.Join(dirPath, name)
	fd, err := unix.Openat(dirfd, name, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, perm)
	if errors.Is(err, unix.ELOOP) {
		return nil, errors.New(path + " is a symlink")
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// regularFile returns f's stat if f is a regular file.
func regularFile(f *os.File) (*unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New(f.Name() + " is not a regular file")
	}
	return &st, nil
}
