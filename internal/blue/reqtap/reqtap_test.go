package reqtap

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ipv4TCP(src, dst string, sport, dport uint16, payload string) []byte {
	tcp := make([]byte, 20)
	tcp[0], tcp[1], tcp[2], tcp[3] = byte(sport>>8), byte(sport), byte(dport>>8), byte(dport)
	tcp[12] = 5 << 4
	b := make([]byte, 20)
	b[0] = 0x45
	total := 20 + len(tcp) + len(payload)
	b[2], b[3] = byte(total>>8), byte(total)
	b[9] = 6
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	return append(append(b, tcp...), payload...)
}

func ipv6TCP(src, dst string, sport, dport uint16, payload string) []byte {
	tcp := make([]byte, 20)
	tcp[0], tcp[1], tcp[2], tcp[3] = byte(sport>>8), byte(sport), byte(dport>>8), byte(dport)
	tcp[12] = 5 << 4
	b := make([]byte, 40)
	b[0] = 0x60
	plen := len(tcp) + len(payload)
	b[4], b[5] = byte(plen>>8), byte(plen)
	b[6] = 6
	copy(b[8:24], net.ParseIP(src).To16())
	copy(b[24:40], net.ParseIP(dst).To16())
	return append(append(b, tcp...), payload...)
}

func readLog(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, LogName))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestRecorderPairsRequestsAndResponses(t *testing.T) {
	dir := t.TempDir()
	r := NewRecorder(dir)
	r.SetPorts(map[uint16]bool{3000: true})
	// A request to a listening port, its response, and traffic that must be
	// ignored: another port, and the server's own outbound requests.
	r.Packet(ipv4TCP("172.30.0.3", "172.30.0.2", 40000, 3000, "GET /ftp/acquisitions.md?token=abc&q=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.5.0\r\n\r\n"))
	r.Packet(ipv4TCP("172.30.0.2", "172.30.0.3", 3000, 40000, "HTTP/1.1 200 OK\r\n\r\n"))
	r.Packet(ipv4TCP("172.30.0.3", "172.30.0.2", 40001, 8080, "GET /other HTTP/1.1\r\n\r\n"))
	r.Packet(ipv4TCP("172.30.0.2", "93.184.216.34", 50000, 80, "GET /outbound HTTP/1.1\r\n\r\n"))
	r.Packet(ipv6TCP("fd00::7", "fd00::2", 41000, 3000, "POST /file-upload HTTP/1.1\r\nUser-Agent: python-requests/2.31\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n"))
	r.Packet(ipv6TCP("fd00::2", "fd00::7", 3000, 41000, "HTTP/1.1 500 Internal Server Error\r\n\r\n"))
	r.Close()
	lines := readLog(t, dir)
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	if want := `"GET /ftp/acquisitions.md?token=REDACTED&q=1 HTTP/1.1" 200 - "-" "curl/8.5.0"`; !strings.HasPrefix(lines[0], "172.30.0.3 - - [") || !strings.Contains(lines[0], want) {
		t.Errorf("line 1: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "fd00::7 ") || !strings.Contains(lines[1], `"POST /file-upload HTTP/1.1" 500`) || !strings.Contains(lines[1], `xff="203.0.113.9"`) {
		t.Errorf("line 2: %s", lines[1])
	}
}

func TestRecorderLogsUnansweredAndEscapes(t *testing.T) {
	dir := t.TempDir()
	r := NewRecorder(dir)
	now := time.Now()
	r.now = func() time.Time { return now }
	r.SetPorts(map[uint16]bool{80: true})
	r.Packet(ipv4TCP("10.0.0.9", "10.0.0.1", 5555, 80, "GET /a\"b\n10.0.0.1 - - forged HTTP/1.1\r\nUser-Agent: x\"y\r\n\r\n"))
	r.Flush()
	if _, err := os.Stat(filepath.Join(dir, LogName)); err == nil {
		t.Fatal("a request still waiting for its response must not be logged yet")
	}
	now = now.Add(time.Minute)
	r.Flush()
	lines := readLog(t, dir)
	if len(lines) != 1 {
		t.Fatalf("a newline in the request must not forge a second line: %q", lines)
	}
	if !strings.Contains(lines[0], `"GET /a\x22b\x0a10.0.0.1 - - forged HTTP/1.1" - `) || !strings.Contains(lines[0], `"x\x22y"`) {
		t.Errorf("escaping: %s", lines[0])
	}
}
