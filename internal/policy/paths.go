package policy

import "path/filepath"

// WorkspaceDirName is the directory under the project root that holds the
// agents' skills, definitions and spilled tool output.
const WorkspaceDirName = ".kodeblue"

// ProjectDir returns the workspace directory under a project root.
func ProjectDir(projectRoot string) string {
	return filepath.Join(projectRoot, WorkspaceDirName)
}
