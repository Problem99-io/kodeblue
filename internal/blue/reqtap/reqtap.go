// Package reqtap records the HTTP requests that reach this network
// namespace's listening TCP ports, read off the wire, into kodeblue's own
// access log. An application's log is not enough: apps register their
// request logger after some routes (static files, uploads, file browsers,
// admin tools), or keep no request log at all, and an attack confined to
// those routes leaves nothing to read. The tap sees every plaintext HTTP/1.x
// request whatever the application logs.
//
// It keeps the request line, client address, response status and user agent.
// Headers other than the user agent and X-Forwarded-For, bodies and the
// values of secret-looking query parameters are never written. TLS traffic is
// not readable: behind a TLS proxy the tap reads the proxy's plaintext
// requests to the backend.
package reqtap

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LogName is the file the tap writes in its directory.
const LogName = "access.log"

const (
	maxPerConn  = 32
	maxPending  = 20000
	unanswered  = 30 * time.Second // a request with no response by then is logged with status "-"
	rotateBytes = 20 << 20
)

var methods = [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "), []byte("PATCH "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("CONNECT "), []byte("TRACE "), []byte("PROPFIND ")}

type request struct {
	at            time.Time
	client        string
	line, ua, xff string
}

type connKey struct {
	client     string
	cport      uint16
	serverPort uint16
}

// Recorder turns packets into log lines. It is separate from the capture
// loop so it can be tested with hand-made packets.
type Recorder struct {
	Dir string

	mu      sync.Mutex
	ports   map[uint16]bool
	pending map[connKey][]request
	n       int
	f       *os.File
	size    int64
	now     func() time.Time
}

func NewRecorder(dir string) *Recorder {
	return &Recorder{Dir: dir, ports: map[uint16]bool{}, pending: map[connKey][]request{}, now: time.Now}
}

// SetPorts sets the listening ports whose traffic is recorded.
func (r *Recorder) SetPorts(ports map[uint16]bool) {
	r.mu.Lock()
	r.ports = ports
	r.mu.Unlock()
}

// Ports returns the ports being recorded.
func (r *Recorder) Ports() []uint16 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []uint16
	for p := range r.ports {
		out = append(out, p)
	}
	return out
}

// Packet handles one IPv4 or IPv6 packet (no link header).
func (r *Recorder) Packet(b []byte) {
	src, dst, sport, dport, payload, ok := parseTCP(b)
	if !ok || len(payload) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.ports[dport] && isRequest(payload):
		k := connKey{client: src.String(), cport: sport, serverPort: dport}
		if len(r.pending[k]) >= maxPerConn || r.n >= maxPending {
			return
		}
		line, ua, xff := parseRequest(payload)
		r.pending[k] = append(r.pending[k], request{at: r.now(), client: k.client, line: line, ua: ua, xff: xff})
		r.n++
	case r.ports[sport] && bytes.HasPrefix(payload, []byte("HTTP/1.")) && len(payload) >= 12:
		k := connKey{client: dst.String(), cport: dport, serverPort: sport}
		q := r.pending[k]
		if len(q) == 0 {
			return
		}
		r.write(q[0], string(payload[9:12]))
		if len(q) == 1 {
			delete(r.pending, k)
		} else {
			r.pending[k] = q[1:]
		}
		r.n--
	}
}

// Flush logs requests that got no response in time (the connection was cut,
// the response was not plaintext, or the server never answered).
func (r *Recorder) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cut := r.now().Add(-unanswered)
	for k, q := range r.pending {
		i := 0
		for i < len(q) && q[i].at.Before(cut) {
			r.write(q[i], "-")
			i++
		}
		r.n -= i
		if i == len(q) {
			delete(r.pending, k)
		} else {
			r.pending[k] = q[i:]
		}
	}
	if r.f != nil {
		_ = r.f.Sync()
	}
}

// Close writes what is pending and closes the log.
func (r *Recorder) Close() {
	r.mu.Lock()
	for k, q := range r.pending {
		for _, req := range q {
			r.write(req, "-")
		}
		delete(r.pending, k)
	}
	r.n = 0
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	r.mu.Unlock()
}

// write appends one line in the combined log format, so log monitors and
// people read it like any web server's access log. Called with r.mu held.
func (r *Recorder) write(req request, status string) {
	if r.f == nil || r.size >= rotateBytes {
		if err := r.open(); err != nil {
			return
		}
	}
	line := fmt.Sprintf("%s - - [%s] \"%s\" %s - \"-\" \"%s\"", req.client, req.at.UTC().Format("02/Jan/2006:15:04:05 -0700"), req.line, status, req.ua)
	if req.xff != "" {
		line += fmt.Sprintf(" xff=\"%s\"", req.xff)
	}
	n, _ := r.f.WriteString(line + "\n")
	r.size += int64(n)
}

func (r *Recorder) open() error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
		_ = os.Rename(filepath.Join(r.Dir, LogName), filepath.Join(r.Dir, LogName+".1"))
	}
	if err := os.MkdirAll(r.Dir, 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(r.Dir, LogName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	r.f, r.size = f, 0
	if st != nil {
		r.size = st.Size()
	}
	return nil
}

func isRequest(p []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

var secretParam = regexp.MustCompile(`(?i)([?&;](?:password|passwd|pwd|pass|token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|auth|authorization|session|sessionid|sid|jwt|signature|sig)=)[^&;# ]*`)

// parseRequest returns the request line (secret query values blanked), the
// user agent and X-Forwarded-For, each made safe for a one-line log.
func parseRequest(p []byte) (line, ua, xff string) {
	end := bytes.Index(p, []byte("\r\n"))
	head := p
	if end < 0 {
		end = len(p)
	} else {
		head = p[end:]
	}
	line = clean(secretParam.ReplaceAllString(string(p[:min(end, 4096)]), "${1}REDACTED"), 4096)
	ua = clean(header(head, "user-agent"), 512)
	xff = clean(header(head, "x-forwarded-for"), 256)
	return line, ua, xff
}

func header(head []byte, name string) string {
	lower := bytes.ToLower(head)
	i := bytes.Index(lower, []byte("\r\n"+name+":"))
	if i < 0 {
		return ""
	}
	v := head[i+len(name)+3:]
	if j := bytes.Index(v, []byte("\r\n")); j >= 0 {
		v = v[:j]
	}
	return strings.TrimSpace(string(v))
}

// clean escapes quotes, backslashes and control bytes: the text comes from
// the attacker, who must not be able to forge log lines.
func clean(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < n; i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			fmt.Fprintf(&b, "\\x%02x", c)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// parseTCP reads an IPv4 or IPv6 packet carrying TCP.
func parseTCP(b []byte) (src, dst net.IP, sport, dport uint16, payload []byte, ok bool) {
	if len(b) < 20 {
		return
	}
	var tcp []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(b[2])<<8 | int(b[3])
		if b[9] != 6 || ihl < 20 || len(b) < ihl+20 {
			return
		}
		if total >= ihl && total < len(b) {
			b = b[:total] // drop link padding
		}
		if off := int(b[6]&0x1f)<<8 | int(b[7]); off != 0 {
			return // a later fragment: no TCP header
		}
		src, dst = net.IP(b[12:16]), net.IP(b[16:20])
		tcp = b[ihl:]
	case 6:
		if len(b) < 60 || b[6] != 6 {
			return // extension headers before TCP are not followed
		}
		plen := int(b[4])<<8 | int(b[5])
		if 40+plen < len(b) {
			b = b[:40+plen]
		}
		src, dst = net.IP(b[8:24]), net.IP(b[24:40])
		tcp = b[40:]
	default:
		return
	}
	if len(tcp) < 20 {
		return
	}
	sport, dport = uint16(tcp[0])<<8|uint16(tcp[1]), uint16(tcp[2])<<8|uint16(tcp[3])
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || doff > len(tcp) {
		return
	}
	if v4 := src.To4(); v4 != nil {
		src = v4
	}
	if v4 := dst.To4(); v4 != nil {
		dst = v4
	}
	return src, dst, sport, dport, tcp[doff:], true
}
