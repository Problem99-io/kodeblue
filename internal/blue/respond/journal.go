package respond

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The journal is what Undo acts on, so the helper must only ever read records
// it wrote itself. It lives in a directory that only root can change, under
// parents that only root can change: /var/lib/kodeblue is the kodeblue user's,
// and a directory there could be renamed away and replaced with one holding a
// forged journal. Every request takes an exclusive lock on the journal for
// its check, its action and its record, so concurrent requests (the socket
// accepts several) cannot both pass the rate limit or both act on one target.

// DefaultStateDir is the root helper's state: journal, quarantined files and
// SSH key backups. root:kodeblue 0750 (the kodeblue user reads the journal).
const DefaultStateDir = "/var/lib/kodeblue-respond"

// stateOwner is the uid trusted to own the state directory and its parents
// besides root. The helper runs as root, so in production this is 0 and the
// chain must be root-owned; under the test binary it is the test user's uid,
// which owns the temporary state dirs.
var stateOwner = uint32(os.Geteuid())

const (
	journalName = "actions.jsonl"
	lockName    = ".lock"
)

func trustedOwner(uid uint32) bool { return uid == 0 || uid == stateOwner }

// openStateDir opens the helper's state directory through the same
// symlink-safe walk the rest of the helper uses (following only root-owned
// links in root-only directories, e.g. /var -> /private/var), then checks the
// directory itself is owned by root and writable only by root. With create, a
// missing final component is made under a parent that passed the same walk, so
// the journal can never be opened through a directory a non-root user planted
// or could rename. The state dir must therefore sit under root-owned parents
// (for the default /var/lib/kodeblue-respond, /var and /var/lib).
func openStateDir(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("state dir %q must be an absolute, clean path", path)
	}
	fd, _, err := walkDir(path, 0)
	if errors.Is(err, unix.ENOENT) && create {
		parent, base := filepath.Dir(path), filepath.Base(path)
		pfd, _, perr := walkDir(parent, 0)
		if perr != nil {
			return -1, &os.PathError{Op: "open", Path: parent, Err: perr}
		}
		var pst unix.Stat_t
		if unix.Fstat(pfd, &pst) == nil && (!trustedOwner(pst.Uid) || pst.Mode&0o022 != 0) {
			unix.Close(pfd)
			return -1, fmt.Errorf("refusing to create state dir %s: %s is writable by someone other than root", path, parent)
		}
		merr := unix.Mkdirat(pfd, base, 0o750)
		unix.Close(pfd)
		if merr != nil && !errors.Is(merr, unix.EEXIST) {
			return -1, &os.PathError{Op: "mkdir", Path: path, Err: merr}
		}
		fd, _, err = walkDir(path, 0)
	}
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if !trustedOwner(st.Uid) || st.Mode&0o022 != 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("refusing state dir %s: it must be owned by root and not group- or world-writable", path)
	}
	return fd, nil
}

// journal is the root helper's open, locked action journal.
type journal struct {
	dir  string
	dfd  int
	lock *os.File
}

// openJournal checks and opens the state dir and takes the journal lock.
func openJournal(stateDir string) (*journal, error) {
	dfd, err := openStateDir(stateDir, true)
	if err != nil {
		return nil, err
	}
	lfd, err := unix.Openat(dfd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		unix.Close(dfd)
		return nil, &os.PathError{Op: "open", Path: filepath.Join(stateDir, lockName), Err: err}
	}
	if err := unix.Flock(lfd, unix.LOCK_EX); err != nil {
		unix.Close(lfd)
		unix.Close(dfd)
		return nil, err
	}
	return &journal{dir: stateDir, dfd: dfd, lock: os.NewFile(uintptr(lfd), filepath.Join(stateDir, lockName))}, nil
}

func (j *journal) Close() {
	j.lock.Close() // releases the flock
	unix.Close(j.dfd)
}

// open opens the journal file in the checked directory and makes sure it is
// root's: a record root did not write is never acted on.
func (j *journal) open(flag int) (*os.File, error) { return j.openFile(journalName, flag) }

// openFile opens name (the journal, or the containment rules) in the checked
// directory, refusing anything but a regular root-owned file.
func (j *journal) openFile(name string, flag int) (*os.File, error) {
	path := filepath.Join(j.dir, name)
	fd, err := unix.Openat(j.dfd, name, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o640)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || !trustedOwner(st.Uid) || st.Mode&0o022 != 0 {
		f.Close()
		return nil, fmt.Errorf("refusing %s: it must be a regular root-owned file with one link, writable only by root", path)
	}
	return f, nil
}

func (j *journal) records() ([]Record, error) {
	f, err := j.open(unix.O_RDONLY)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readRecords(f), nil
}

func (j *journal) find(id string) (*Record, error) {
	recs, err := j.records()
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r.ID == id {
			rr := r
			return &rr, nil
		}
	}
	return nil, nil
}

func (j *journal) append(rec Record) error {
	f, err := j.open(unix.O_WRONLY | unix.O_APPEND | unix.O_CREAT)
	if err != nil {
		return err
	}
	defer f.Close()
	// A new journal goes to the state dir's group (kodeblue), read-only.
	var dst unix.Stat_t
	if unix.Fstat(j.dfd, &dst) == nil {
		_ = f.Chown(-1, int(dst.Gid))
	}
	b, _ := json.Marshal(rec)
	_, err = f.Write(append(b, '\n'))
	return err
}

// Append writes a record to the action journal (root helper only).
func Append(stateDir string, rec Record) error {
	j, err := openJournal(stateDir)
	if err != nil {
		return err
	}
	defer j.Close()
	return j.append(rec)
}

// Load returns the latest state of each record by ID. It is for display and
// de-duplication on the unprivileged side; the root helper reads the journal
// through its checked directory instead.
func Load(stateDir string) []Record {
	f, err := os.Open(filepath.Join(stateDir, journalName))
	if err != nil {
		return nil
	}
	defer f.Close()
	return readRecords(f)
}

// Find returns the latest record with id (display only, like Load).
func Find(stateDir, id string) *Record {
	for _, r := range Load(stateDir) {
		if r.ID == id {
			rr := r
			return &rr
		}
	}
	return nil
}

func readRecords(r io.Reader) []Record {
	latest := map[string]Record{}
	var order []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if _, ok := latest[r.ID]; !ok {
			order = append(order, r.ID)
		}
		latest[r.ID] = r
	}
	out := make([]Record, 0, len(order))
	for _, id := range order {
		out = append(out, latest[id])
	}
	return out
}
