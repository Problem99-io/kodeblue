//go:build !linux

package main

// scrubArgvSecret is a no-op on non-Linux platforms (local dev builds): the
// /proc/<pid>/cmdline exposure it mitigates is a Linux procfs mechanism, and
// the daemon only runs untrusted code inside the Linux container. See
// scrub_argv_linux.go.
func scrubArgvSecret(secret string) {}
