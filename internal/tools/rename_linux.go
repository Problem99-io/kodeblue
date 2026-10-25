package tools

import "golang.org/x/sys/unix"

// renameNoReplace renames from to to within dirFD, failing with EEXIST if to
// exists. Filesystems without RENAME_NOREPLACE fall back to link and unlink.
func renameNoReplace(dirFD int, from, to string) error {
	err := unix.Renameat2(dirFD, from, dirFD, to, unix.RENAME_NOREPLACE)
	if err == unix.EINVAL || err == unix.ENOSYS || err == unix.EOPNOTSUPP {
		return linkNoReplace(dirFD, from, to)
	}
	return err
}
