//go:build !linux

package main

// hardenProcess is a no-op on non-Linux platforms (local dev builds).
// PR_SET_DUMPABLE is a Linux mechanism; see harden_linux.go.
func hardenProcess() error { return nil }

// verifyNonDumpable reports "ok" on non-Linux platforms: PR_SET_DUMPABLE is a
// Linux mechanism, so the -selfcheck-harden gate is a no-op here. See
// harden_linux.go.
func verifyNonDumpable() (bool, error) { return true, nil }
