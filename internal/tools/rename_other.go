//go:build unix && !linux && !darwin

package tools

// renameNoReplace renames from to to within dirFD, failing with EEXIST if to
// exists.
func renameNoReplace(dirFD int, from, to string) error {
	return linkNoReplace(dirFD, from, to)
}
