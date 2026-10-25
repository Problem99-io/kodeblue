//go:build linux

package main

import (
	"os"
	"strings"
	"unsafe"
)

// scrubArgvSecret zeroes, in place, the bytes of every argv element that
// contains the given secret so /proc/<pid>/cmdline no longer exposes it.
//
// The -api-key and -gateway-api-key flags are a fallback for standalone runs
// (kodeblue itself uses -secrets-fd). cmdline, unlike environ, stays
// world-readable even after hardenProcess() clears the dumpable flag, so any
// same-host process could otherwise harvest the key.
//
// This works because the Go runtime builds os.Args on Linux with
// gostringnocopy: each element aliases the original, writable argv memory the
// kernel serves /proc/<pid>/cmdline from (the same mechanism setproctitle
// implementations rely on). Callers MUST strings.Clone any flag value they
// need before invoking this — parsed flag values alias that same memory.
//
// Best-effort: there is a window between exec and this call where the key is
// visible; it only narrows exposure to process-listing races at spawn time.
func scrubArgvSecret(secret string) {
	if secret == "" {
		return
	}
	for _, arg := range os.Args {
		if len(arg) == 0 || !strings.Contains(arg, secret) {
			continue
		}
		b := unsafe.Slice(unsafe.StringData(arg), len(arg))
		for i := range b {
			b[i] = 0
		}
	}
}
