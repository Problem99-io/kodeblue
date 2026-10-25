package sensors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeService writes /proc/<pid> under root: its executable, parent,
// cgroup, filesystem and the socket inodes it holds.
func fakeService(t *testing.T, root string, pid, ppid int, exe, cgroup, rootfs string, inodes ...string) {
	t.Helper()
	d := filepath.Join(root, "proc", fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(d, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(exe, filepath.Join(d, "exe"))
	_ = os.Symlink(rootfs, filepath.Join(d, "root"))
	_ = os.WriteFile(filepath.Join(d, "cmdline"), []byte(exe), 0o644)
	_ = os.WriteFile(filepath.Join(d, "cgroup"), []byte(cgroup+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "status"), []byte(fmt.Sprintf("State:\tS (sleeping)\nPPid:\t%d\nUid:\t0\t0\t0\t0\n", ppid)), 0o644)
	for i, ino := range inodes {
		_ = os.Symlink("socket:["+ino+"]", filepath.Join(d, "fd", fmt.Sprint(3+i)))
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverServices(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir() // a container's filesystem
	const hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	writeFile(t, filepath.Join(root, "proc/net/tcp"), hdr+
		"   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n"+ // nginx :80
		"   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1\n"+ // redis-like on loopback :6379
		"   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1\n"+ // init holds :22
		"   3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1\n"+ // nobody we can see: :8080
		"   4: 0B00007F:A077 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1\n") // Docker's embedded DNS

	fakeService(t, root, 1, 0, "/usr/lib/systemd/systemd", "0::/init.scope", root, "1002")
	fakeService(t, root, 100, 1, "/usr/sbin/nginx", "0::/system.slice/nginx.service", root, "1001")
	fakeService(t, root, 101, 100, "/usr/sbin/nginx", "0::/system.slice/nginx.service", root, "1001")
	fakeService(t, root, 200, 150, "/usr/local/bin/node", "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope", other)
	fakeService(t, root, 300, 250, "/usr/bin/bash", "0::/user.slice/user-1000.slice/session-3.scope", root) // a login shell: not a service
	fakeService(t, root, 400, 1, "/usr/local/bin/cache", "0::/user.slice/user-1000.slice/session-3.scope", root, "1004")
	fakeService(t, root, 500, 0, "/pause", "0::/", t.TempDir()) // a pod's sandbox
	fakeService(t, root, 600, 0, "/usr/bin/dash", "0::/", root) // a `docker exec` shell

	writeFile(t, filepath.Join(root, "run/systemd/system/.keep"), "")
	units := filepath.Join(root, "lib/systemd/system")
	writeFile(t, filepath.Join(units, "ssh.socket"), "[Socket]\nListenStream=22\n")
	writeFile(t, filepath.Join(units, "ssh.service"), "[Service]\nExecStart=/usr/sbin/sshd -D\n")
	writeFile(t, filepath.Join(units, "postgresql.service"), "[Service]\nType=notify\nExecStart=-/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql\n")
	writeFile(t, filepath.Join(units, "setup-once.service"), "[Service]\nType=oneshot\nExecStart=/usr/local/bin/setup\n")
	writeFile(t, filepath.Join(units, "nginx.service"), "[Service]\nExecStart=/usr/sbin/nginx\n")
	wants := filepath.Join(root, "etc/systemd/system/multi-user.target.wants")
	if err := os.MkdirAll(filepath.Join(root, "etc/systemd/system/sockets.target.wants"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{"multi-user.target.wants/nginx.service", "multi-user.target.wants/postgresql.service", "multi-user.target.wants/setup-once.service", "sockets.target.wants/ssh.socket"} {
		_ = os.MkdirAll(wants, 0o755)
		_ = os.Symlink(filepath.Join("/lib/systemd/system", filepath.Base(link)), filepath.Join(root, "etc/systemd/system", link))
	}

	got := map[string]Service{}
	for _, s := range DiscoverServices(&Env{Root: root}) {
		got[s.Name] = s
	}
	names := func() string {
		var l []string
		for n := range got {
			l = append(l, n)
		}
		return strings.Join(l, ", ")
	}

	nginx, ok := got["nginx"]
	if !ok || nginx.State != ServiceRunning || nginx.Unit != "nginx.service" || nginx.PID != 100 || !nginx.Public() || len(nginx.Exes) != 1 {
		t.Fatalf("nginx: %+v (found %s)", nginx, names())
	}
	c, ok := got["container 0123456789ab"]
	if !ok || c.Container != "0123456789ab" || c.Root != "/proc/200/root" || c.Exes[0] != "/usr/local/bin/node" {
		t.Fatalf("container: %+v (found %s)", c, names())
	}
	if _, ok := got["bash"]; ok {
		t.Fatal("a login shell is not a service")
	}
	cache, ok := got["cache"]
	if !ok || cache.Public() || len(cache.Listen) != 1 || cache.Listen[0].Port != 6379 {
		t.Fatalf("daemon of init listening on loopback: %+v", cache)
	}
	ssh, ok := got["ssh"]
	if !ok || ssh.State != ServiceSocket || len(ssh.Listen) != 1 || ssh.Listen[0].Port != 22 || ssh.Exes[0] != "/usr/sbin/sshd" {
		t.Fatalf("socket-activated ssh: %+v (found %s)", ssh, names())
	}
	pg, ok := got["postgresql"]
	if !ok || pg.State != ServiceEnabled || pg.Exes[0] != "/usr/lib/postgresql/16/bin/postgres" {
		t.Fatalf("enabled postgresql: %+v (found %s)", pg, names())
	}
	if _, ok := got["setup-once"]; ok {
		t.Fatal("a oneshot unit is a boot task, not a service")
	}
	unknown, ok := got["unknown tcp/8080"]
	if !ok || unknown.Note == "" || !unknown.Public() {
		t.Fatalf("listener nobody owns: %+v (found %s)", unknown, names())
	}
	for _, n := range []string{"systemd", "pause (other filesystem)", "dash"} {
		if _, ok := got[n]; ok {
			t.Fatalf("%s is not a service", n)
		}
	}
	if dns, ok := got["docker-dns"]; !ok || dns.Public() || dns.Note == "" {
		t.Fatalf("Docker's resolver: %+v (found %s)", dns, names())
	}
}

func TestSystemUnit(t *testing.T) {
	for cg, want := range map[string]string{
		"0::/system.slice/nginx.service":                                       "nginx.service",
		"12:pids:/system.slice/php8.2-fpm.service\n0::/system.slice/x.service": "php8.2-fpm.service",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/a.service": "",
		"0::/system.slice/docker-abc.scope":                                    "",
	} {
		if got := systemUnit(cg); got != want {
			t.Errorf("systemUnit(%q) = %q, want %q", cg, got, want)
		}
	}
}
