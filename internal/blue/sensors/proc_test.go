package sensors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kodeblue running as a sidecar in the service's network namespace: its own
// sockets are not the server's listeners or outbound connections.
func TestSocketCollectorsSkipKodeblue(t *testing.T) {
	root := t.TempDir()
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	const hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	writeFile(t, filepath.Join(root, "proc/net/tcp"), hdr+
		"   0: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n"+ // node :3000
		"   1: 0200A8C0:9C40 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 1002 1\n"+ // node to 8.8.8.8:53
		"   2: 0100007F:B22B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1\n"+ // kodeblue's engine API
		"   3: 0200A8C0:9C41 73031268:01BB 01 00000000:00000000 00:00000000 00000000     0        0 1004 1\n") // kodeblue to its model API
	fakeService(t, root, 100, 0, "/usr/bin/node", "0::/", root, "1001", "1002")
	fakeService(t, root, 200, 0, self, "0::/", root, "1003", "1004")
	env := &Env{Root: root}

	keys := func(c Collector) string {
		items, _, err := c.Collect(context.Background(), env)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, it := range items {
			out = append(out, it.Key)
		}
		return strings.Join(out, " ")
	}
	if got := keys(listenerCollector{}); got != "tcp/3000/public//usr/bin/node" {
		t.Fatalf("listeners: %s", got)
	}
	if got := keys(outboundCollector{}); got != "/usr/bin/node->53" {
		t.Fatalf("outbound: %s", got)
	}
}

// A process running from a replaced binary carries the service it runs in,
// so the detector can tell kodeblue's own upgrade from anything else.
func TestProcessCollectorDeletedUnit(t *testing.T) {
	root := t.TempDir()
	proc := func(pid, exe, cgroup string) {
		d := filepath.Join(root, "proc", pid)
		writeFile(t, filepath.Join(d, "cmdline"), exe+"\x00upgrade\x00")
		writeFile(t, filepath.Join(d, "status"), "State:\tS (sleeping)\nPPid:\t1\nUid:\t0\t0\t0\t0\n")
		writeFile(t, filepath.Join(d, "cgroup"), cgroup)
		if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	proc("100", "/usr/local/bin/kodeblue (deleted)", "0::/system.slice/kodeblue-upgrade.service\n")
	proc("200", "/usr/sbin/sshd", "0::/system.slice/ssh.service\n")
	items, _, err := processCollector{}.Collect(context.Background(), &Env{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]string{}
	for _, it := range items {
		got[it.Attrs["pid"]] = it.Attrs
	}
	if a := got["100"]; a["deleted"] != "true" || a["unit"] != "kodeblue-upgrade.service" {
		t.Errorf("deleted process: %v", a)
	}
	if a := got["200"]; a["deleted"] != "" || a["unit"] != "" {
		t.Errorf("a live binary gets no unit (only deleted ones are looked up): %v", a)
	}
}
