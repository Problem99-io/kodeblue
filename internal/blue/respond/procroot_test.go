package respond

import (
	"fmt"
	"os"
	"testing"
)

func TestQuarantinePathThroughProcRoot(t *testing.T) {
	for _, c := range []struct {
		path string
		ok   bool
	}{
		{"/proc/42/root/tmp/x.js", true},
		{"/proc/42/root/var/www/shell.php", true},
		{"/proc/42/root/etc/passwd", false},
		{"/proc/42/root/usr/bin/node", false},
		{"/proc/42/root/tmp/../etc/passwd", false},
		{fmt.Sprintf("/proc/%d/root/tmp/x", os.Getpid()), false},
		{"/proc/42/cwd/tmp/x", false},
	} {
		err := checkQuarantinePath(c.path)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.path, err, c.ok)
		}
	}
}

func TestSplitProcRoot(t *testing.T) {
	for in, want := range map[string]string{
		"/proc/7/root/tmp/a": "/proc/7/root|/tmp/a",
		"/proc/7/root":       "/proc/7/root|/",
		"/proc/7/rootx/a":    "|/proc/7/rootx/a",
		"/tmp/a":             "|/tmp/a",
	} {
		b, i := splitProcRoot(in)
		if got := b + "|" + i; got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}
