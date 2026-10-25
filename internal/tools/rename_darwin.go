package tools

import "golang.org/x/sys/unix"

// renameNoReplace renames from to to within dirFD, failing with EEXIST if to
// exists.
func renameNoReplace(dirFD int, from, to string) error {
	err := unix.RenameatxNp(dirFD, from, dirFD, to, unix.RENAME_EXCL)
	if err == unix.ENOTSUP {
		return linkNoReplace(dirFD, from, to)
	}
	return err
}
