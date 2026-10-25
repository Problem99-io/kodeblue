package respond

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// procRoot is where the helper reads its network state (tests point it
// elsewhere).
var procRoot = "/proc"

// infraReason says why an address must never be blocked, public or private:
// this server's own addresses, its gateway and resolvers, the hub and model
// endpoints kodeblue talks to (hosts), and admins in a live SSH session.
func infraReason(ip net.IP, hosts []string) string {
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return "it is one of this server's own addresses"
			}
		}
	}
	for _, gw := range gateways() {
		if gw.Equal(ip) {
			return "it is the default gateway"
		}
	}
	for _, ns := range nameservers() {
		if ns.Equal(ip) {
			return "it is a DNS resolver in /etc/resolv.conf"
		}
	}
	if why := sshReason(ip); why != "" {
		return why
	}
	if why := infraHostReason(ip, hosts); why != "" {
		return why
	}
	// A private peer this server merely dials (database, a neighbour it
	// connects out to) is infrastructure too; a public one it dials may be
	// the attacker's command and control, so only private peers are spared.
	if ip.IsPrivate() {
		return peerReason(ip)
	}
	return ""
}

func gateways() []net.IP {
	var out []net.IP
	if f, err := os.Open(procRoot + "/net/route"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 3 || fl[1] != "00000000" || fl[2] == "00000000" {
				continue
			}
			if raw, err := hex.DecodeString(fl[2]); err == nil && len(raw) == 4 {
				out = append(out, net.IP{raw[3], raw[2], raw[1], raw[0]})
			}
		}
	}
	if b, err := os.ReadFile(procRoot + "/net/ipv6_route"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fl := strings.Fields(line)
			if len(fl) < 5 || fl[0] != strings.Repeat("0", 32) || fl[1] != "00" || fl[4] == strings.Repeat("0", 32) {
				continue
			}
			if raw, err := hex.DecodeString(fl[4]); err == nil && len(raw) == 16 {
				out = append(out, net.IP(raw))
			}
		}
	}
	return out
}

var resolvConf = "/etc/resolv.conf"

func nameservers() []net.IP {
	b, err := os.ReadFile(resolvConf)
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, line := range strings.Split(string(b), "\n") {
		fl := strings.Fields(line)
		if len(fl) >= 2 && fl[0] == "nameserver" {
			if ip := net.ParseIP(fl[1]); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

type sock struct {
	local, remote net.IP
	lport, rport  int
	state         string
}

// peerReason says why a private address is something this server depends
// on: a connection whose local port is not a listening port was opened by
// this server, so its remote end is something the server uses. Blocking a
// private address is how an attacker inside the network (another container,
// a compromised neighbour) is cut off; a public one this server dials may be
// the attacker's command and control, so this applies to private ones only.
func peerReason(ip net.IP) string {
	socks := tcpSocks()
	listening := map[int]bool{}
	for _, s := range socks {
		if s.state == "0A" {
			listening[s.lport] = true
		}
	}
	for _, s := range socks {
		if s.state == "0A" || !s.remote.Equal(ip) {
			continue
		}
		if !listening[s.lport] {
			return "this server connects out to it (port " + strconv.Itoa(s.rport) + ")"
		}
	}
	return ""
}

// sshReason: an address with an established connection to the SSH port is
// an admin (or an attacker, but locking out the admin is worse).
func sshReason(ip net.IP) string {
	ports := sshPorts()
	for _, s := range tcpSocks() {
		if s.state == "01" && s.remote.Equal(ip) && ports[s.lport] {
			return "it holds a live SSH session to this server"
		}
	}
	return ""
}

func tcpSocks() []sock {
	var socks []sock
	for _, f := range []string{"tcp", "tcp6"} {
		socks = append(socks, readSocks(procRoot+"/net/"+f)...)
	}
	return socks
}

func readSocks(path string) []sock {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []sock
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		return nil
	}
	for _, line := range lines[1:] {
		fl := strings.Fields(line)
		if len(fl) < 4 {
			continue
		}
		l, lp := hexAddr(fl[1])
		r, rp := hexAddr(fl[2])
		if l == nil || r == nil {
			continue
		}
		out = append(out, sock{local: l, remote: r, lport: lp, rport: rp, state: fl[3]})
	}
	return out
}

// hexAddr decodes a /proc/net/tcp address ("0100007F:0016").
func hexAddr(s string) (net.IP, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	return ip, int(port)
}
