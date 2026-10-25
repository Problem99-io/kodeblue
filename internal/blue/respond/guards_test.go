package respond

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stop_unit must reject globs and non-stoppable unit types, and protect the
// built-in critical units whatever their type (ssh.socket, kodeblue*).
func TestStopUnitValidation(t *testing.T) {
	p := DefaultPolicy()
	j := "evidence: this unit was added by the attacker's persistence and re-launches the payload"
	bad := []string{"*", "ssh*", "evil.ser?vice", "evil[1].service", "-evil.service", "ssh.service",
		"sshd.socket", "ssh.socket", "kodeblue.service", "kodeblue-respond.socket", "systemd-journald.service",
		"basic.target", "home.mount", "evil@.service", `ev\x2dil.service`, "ev il.service"}
	for _, u := range bad {
		if err := Check(p, Request{Action: "stop_unit", Params: map[string]string{"unit": u}, Justification: j}); err == nil {
			t.Errorf("stop_unit %q must be refused", u)
		}
	}
	ok := []string{"evil.service", "evil", "miner.timer", "backdoor.socket", "x@1.service"}
	for _, u := range ok {
		if err := Check(p, Request{Action: "stop_unit", Params: map[string]string{"unit": u}, Justification: j}); err != nil {
			t.Errorf("stop_unit %q should pass: %v", u, err)
		}
	}
}

// disable_ssh_key must refuse a short/empty fingerprint prefix, and the admins
// kodeblue must never lock out (uid 0, sudo/wheel members, protected users).
func TestDisableKeyAndLockGuards(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	os.WriteFile(passwd, []byte(strings.Join([]string{
		"root:x:0:0::/root:/bin/bash",
		"alice:x:1000:1000::/home/alice:/bin/bash", // sudo member
		"bob:x:1001:1001::/home/bob:/bin/bash",     // ordinary user
		"super:x:0:0::/home/super:/bin/bash",       // second uid 0
		"kodeblue:x:999:999::/var/lib/kodeblue:/usr/sbin/nologin",
	}, "\n")+"\n"), 0o600)
	os.WriteFile(group, []byte("sudo:x:27:alice\nwheel:x:10:\n"), 0o600)
	defer func(a, b string) { passwdPath, groupPath = a, b }(passwdPath, groupPath)
	passwdPath, groupPath = passwd, group

	p := DefaultPolicy()
	p.ProtectedUsers = []string{"root", "deploy"}
	full := strings.Repeat("a", 64)
	j := "evidence: this key was planted by the attacker after the root login from 203.0.113.66"

	// Short/empty fingerprints are refused outright.
	for _, id := range []string{"", "abc", strings.Repeat("a", 10), strings.Repeat("A", 16)} {
		if err := Check(p, Request{Action: "disable_ssh_key", Params: map[string]string{"user": "bob", "key_id": id}, Justification: j}); err == nil {
			t.Errorf("disable_ssh_key key_id %q must be refused", id)
		}
	}
	// A full fingerprint on an ordinary user passes the check.
	if err := Check(p, Request{Action: "disable_ssh_key", Params: map[string]string{"user": "bob", "key_id": full}, Justification: j}); err != nil {
		t.Errorf("disable_ssh_key for bob should pass: %v", err)
	}
	// Admins are protected for both disable_ssh_key and lock_user.
	for _, u := range []string{"root", "super", "alice", "deploy", "kodeblue"} {
		if err := Check(p, Request{Action: "disable_ssh_key", Params: map[string]string{"user": u, "key_id": full}, Justification: j}); err == nil {
			t.Errorf("disable_ssh_key must refuse admin %q", u)
		}
		if err := Check(p, Request{Action: "lock_user", Params: map[string]string{"user": u}, Justification: j}); err == nil {
			t.Errorf("lock_user must refuse admin %q", u)
		}
	}
	// An ordinary user may be locked.
	if err := Check(p, Request{Action: "lock_user", Params: map[string]string{"user": "bob"}, Justification: j}); err != nil {
		t.Errorf("lock_user bob should pass: %v", err)
	}
}

// The MCP layer must never quarantine a protected/baseline admin's
// authorized_keys, even though the path contains "/." (the suspicious shortcut).
func TestKeyFileUserAndAdminReason(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\n"), 0o600)
	defer func(a string) { passwdPath = a }(passwdPath)
	passwdPath = passwd

	u, ok := KeyFileUser("/root/.ssh/authorized_keys")
	if !ok || u != "root" {
		t.Fatalf("root key file: %q %v", u, ok)
	}
	if AdminReason(DefaultPolicy(), "root") == "" {
		t.Fatal("root must be an admin")
	}
	if u, ok := KeyFileUser("/tmp/.x/payload"); ok && u != "" {
		t.Fatalf("not a key file: %q", u)
	}
	if u, _ := KeyFileUser("/home/bob/.ssh/authorized_keys"); u != "bob" {
		t.Fatalf("bob key file: %q", u)
	}
}

// The root helper itself refuses to quarantine an administrator's
// authorized_keys (the MCP layer's check is advisory: a compromised kodeblue
// user can call the helper directly), including through a host process's
// /proc/<pid>/root.
func TestQuarantineAdminKeyFile(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	os.WriteFile(passwd, []byte(strings.Join([]string{
		"root:x:0:0::/root:/bin/bash",
		"alice:x:1000:1000::/home/alice:/bin/bash", // sudo member
		"bob:x:1001:1001::/home/bob:/bin/bash",     // ordinary user
		"super:x:0:0::/home/super:/bin/bash",       // second uid 0
		"deploy:x:1002:1002::/home/deploy:/bin/bash",
		"ops:x:1003:10::/home/ops:/bin/bash", // primary group wheel
	}, "\n")+"\n"), 0o600)
	os.WriteFile(group, []byte("sudo:x:27:alice\nwheel:x:10:\n"), 0o600)
	defer func(a, b string) { passwdPath, groupPath = a, b }(passwdPath, groupPath)
	passwdPath, groupPath = passwd, group

	p := DefaultPolicy()
	p.ProtectedUsers = []string{"deploy"} // root is an admin by uid, whatever the policy lists
	p.StateDir = t.TempDir()
	j := "evidence: this file was written by the attacker's dropper after the web shell ran"
	refuse := map[string]string{
		"/root/.ssh/authorized_keys":                           "uid 0",
		"/root/.ssh/authorized_keys2":                          "uid 0",
		"/home/alice/.ssh/authorized_keys":                     "member of sudo",
		"/home/super/.ssh/authorized_keys":                     "uid 0",
		"/home/deploy/.ssh/authorized_keys":                    "protected_users",
		"/home/ops/.ssh/authorized_keys":                       "primary group is wheel",
		"/proc/1/root/root/.ssh/authorized_keys":               "uid 0",
		"/proc/999999999/root/home/alice/.ssh/authorized_keys": "member of sudo",
	}
	for path, want := range refuse {
		r := Request{ID: "act_k", Action: "quarantine_file", Params: map[string]string{"path": path}, Justification: j}
		if err := Check(p, r); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("quarantine %s: want refusal mentioning %q, got %v", path, want, err)
		}
		if rec := Execute(p, r); rec.Status != "refused" || !strings.Contains(rec.Result, "authorized_keys") {
			t.Errorf("helper must refuse %s: %s %q", path, rec.Status, rec.Result)
		}
	}
	for _, path := range []string{"/home/bob/.ssh/authorized_keys", "/tmp/.x/authorized_keys", "/home/alice/.ssh/known_hosts", "/home/gone/.ssh/authorized_keys"} {
		if err := Check(p, Request{Action: "quarantine_file", Params: map[string]string{"path": path}, Justification: j}); err != nil {
			t.Errorf("quarantine %s should pass the check: %v", path, err)
		}
	}
}

// block_ip refuses infrastructure whatever the address's class: the gateway,
// resolvers, SSH-session peers and the configured hub/model hosts.
func TestBlockInfraHosts(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("net/route", "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0100A8C0\t0003\n") // gw 192.168.0.1
	write("net/ipv6_route", "")
	hdr := "  sl  local_address rem_address   st\n"
	// Established SSH session from a PUBLIC address 203.0.113.70 (little-endian
	// 467100CB) to local :22 (0016).
	write("net/tcp", hdr+"   0: 0100007F:0016 467100CB:C000 01 0 0 0 0 0 0\n")
	write("net/tcp6", hdr)
	write("resolv.conf", "nameserver 9.9.9.9\n")
	defer func(a, b, c string) { procRoot, resolvConf, sshdConfig = a, b, c }(procRoot, resolvConf, sshdConfig)
	procRoot, resolvConf, sshdConfig = dir, filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "none")

	p := DefaultPolicy()
	p.InfraHosts = []string{"https://hub.example.com:8443", "https://api.example.com"}
	j := "evidence: this address is in the exploit chain seen in the request tap over the last hour"
	refuse := map[string]string{
		"192.168.0.1":   "gateway",     // private gateway
		"9.9.9.9":       "DNS",         // public resolver
		"203.0.113.70":  "SSH",         // public SSH-session source
		"203.0.113.200": "api.example", // public model endpoint (resolved)
		"203.0.113.100": "hub.example", // public hub (resolved)
	}
	defer func(f func(context.Context, string) ([]net.IP, error)) { lookupIP = f }(lookupIP)
	lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "api.example.com":
			return []net.IP{net.ParseIP("203.0.113.200")}, nil
		case "hub.example.com":
			return []net.IP{net.ParseIP("203.0.113.100")}, nil
		}
		return nil, nil
	}
	for ip, want := range refuse {
		err := Check(p, Request{Action: "block_ip", Params: map[string]string{"ip": ip}, Justification: j})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("block_ip %s: want refusal mentioning %q, got %v", ip, want, err)
		}
	}
	// An unrelated public attacker address is still blockable.
	if err := Check(p, Request{Action: "block_ip", Params: map[string]string{"ip": "203.0.113.66"}, Justification: j}); err != nil {
		t.Errorf("unrelated attacker address should be blockable: %v", err)
	}
}

// If a configured infra host cannot be resolved (a transient DNS failure, not
// a clean "no such host"), block_ip fails closed: the address cannot be ruled
// out against the hub/model endpoint, so blocking is refused. A definitive
// not-found answer rules it out and the block proceeds.
func TestBlockInfraFailsClosedOnDNSError(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	for _, f := range []string{"net/route", "net/ipv6_route", "net/tcp", "net/tcp6"} {
		os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte(""), 0o644)
	defer func(a, b, c string) { procRoot, resolvConf, sshdConfig = a, b, c }(procRoot, resolvConf, sshdConfig)
	procRoot, resolvConf, sshdConfig = dir, filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "none")

	p := DefaultPolicy()
	p.InfraHosts = []string{"https://hub.example.com"}
	j := "evidence: exploit chain from this address seen repeatedly in the request tap this hour"
	defer func(f func(context.Context, string) ([]net.IP, error)) { lookupIP = f }(lookupIP)

	// Transient failure → refuse (fail closed).
	lookupIP = func(context.Context, string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "hub.example.com", IsTemporary: true}
	}
	if err := Check(p, Request{Action: "block_ip", Params: map[string]string{"ip": "203.0.113.66"}, Justification: j}); err == nil || !strings.Contains(err.Error(), "could not be ruled out") {
		t.Fatalf("transient DNS failure must fail closed, got %v", err)
	}
	// Definitive not-found → the address is ruled out, block proceeds.
	lookupIP = func(context.Context, string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "hub.example.com", IsNotFound: true}
	}
	if err := Check(p, Request{Action: "block_ip", Params: map[string]string{"ip": "203.0.113.66"}, Justification: j}); err != nil {
		t.Fatalf("a definitively unresolvable host must not block unrelated addresses: %v", err)
	}
}
