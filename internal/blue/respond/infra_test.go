package respond

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A private address may be blocked when it is only a client of this server;
// what the server depends on stays reachable.
func TestBlockPrivateAddress(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Gateway 172.30.0.1 (little-endian hex).
	write("net/route", "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t01001EAC\t0003\neth0\t00001EAC\t00000000\t0001\n")
	write("net/ipv6_route", "")
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write("net/tcp", hdr+
		"   0: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n"+ // listen :3000
		"   1: 02001EAC:0BB8 03001EAC:D431 01 00000000:00000000 00:00000000 00000000     0        0 2\n"+ // client 172.30.0.3 -> :3000
		"   2: 02001EAC:A1B2 04001EAC:1538 01 00000000:00000000 00:00000000 00000000     0        0 3\n"+ // we dial 172.30.0.4:5432
		"   3: 02001EAC:0016 06001EAC:C000 01 00000000:00000000 00:00000000 00000000     0        0 4\n") // ssh from 172.30.0.6
	write("net/tcp6", hdr)
	write("resolv.conf", "nameserver 172.30.0.53\n")
	oldProc, oldResolv := procRoot, resolvConf
	procRoot, resolvConf = dir, filepath.Join(dir, "resolv.conf")
	t.Cleanup(func() { procRoot, resolvConf = oldProc, oldResolv })

	p := DefaultPolicy()
	j := "evidence: exploit requests then a successful admin login from this client"
	req := func(ip string) Request {
		return Request{Action: "block_ip", Params: map[string]string{"ip": ip}, Justification: j}
	}
	for _, ip := range []string{"172.30.0.3", "::ffff:172.30.0.3", "10.9.9.9"} {
		if err := Check(p, req(ip)); err != nil {
			t.Errorf("client %s should be blockable: %v", ip, err)
		}
	}
	for ip, want := range map[string]string{
		"172.30.0.1":  "gateway",
		"172.30.0.53": "DNS",
		"172.30.0.4":  "connects out",
		"172.30.0.6":  "SSH",
	} {
		err := Check(p, req(ip))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want refusal mentioning %q, got %v", ip, want, err)
		}
	}
	p.RefusePrivateIPs = true
	if err := Check(p, req("172.30.0.3")); err == nil {
		t.Error("refuse_private_ips must refuse every private address")
	}
}
