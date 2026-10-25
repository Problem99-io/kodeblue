//go:build linux

package main

import "golang.org/x/sys/unix"

// hardenProcess marks this daemon non-dumpable (PR_SET_DUMPABLE = 0).
//
// The engine holds model keys in memory and an open fd to its SQLite
// database, and runs as the same uid as the processes it launches (MCP
// servers). By default a same-uid process can read another's
// /proc/<pid>/environ, /proc/<pid>/fd and /proc/<pid>/mem.
//
// Clearing the dumpable flag makes the kernel reparent this process's /proc
// entries to root and deny the ptrace-mode access check for same-uid readers,
// so environ/fd/mem become unreadable to its child processes, while
// the daemon keeps full access to its own /proc/self. The flag lives on the
// process mm (shared across threads), so a single call is process-wide.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// verifyNonDumpable reports whether this process is currently non-dumpable
// (PR_GET_DUMPABLE == 0). It backs the `-selfcheck-harden` build/CI gate: CI
// runs the compiled binary with that flag and fails if this returns false, so a
// change that removes or reorders the hardenProcess() call at startup cannot
// ship an engine whose /proc environ/fd/mem are readable by same-uid processes.
func verifyNonDumpable() (bool, error) {
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return false, err
	}
	return d == 0, nil
}
