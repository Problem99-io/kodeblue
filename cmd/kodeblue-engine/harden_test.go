//go:build linux

package main

import "testing"

// TestHardenProcessMakesNonDumpable is a security regression test. The engine
// holds model keys in memory and an open fd to its session database, and runs
// as the same uid as the processes it launches (MCP servers and their
// children). PR_SET_DUMPABLE=0 is what stops those processes reading its
// /proc/<pid>/environ, fd and mem. If a change removes or breaks
// hardenProcess(), this test fails; do not weaken it to make a build pass.
func TestHardenProcessMakesNonDumpable(t *testing.T) {
	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess() returned an error: %v", err)
	}
	ok, err := verifyNonDumpable()
	if err != nil {
		t.Fatalf("verifyNonDumpable() error: %v", err)
	}
	if !ok {
		t.Fatal("SECURITY REGRESSION: hardenProcess() did not clear the dumpable flag; " +
			"the engine's /proc/<pid>/environ, fd and mem would be readable by same-uid processes")
	}
}
