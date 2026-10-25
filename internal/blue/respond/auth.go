package respond

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Caller is who sent a request to the root helper. The helper is reachable
// two ways, and both carry the caller's identity:
//
//   - the systemd socket (SocketGroup=kodeblue, Accept=yes): stdin is the
//     accepted connection, and SO_PEERCRED gives the connecting uid;
//   - the sudoers rule on hosts without systemd: sudo sets SUDO_UID to the
//     invoking user, whatever that user passes.
//
// The unprivileged kodeblue user is the only non-operator that may reach the
// helper (the socket's group and the sudoers rule are both its own). So a
// caller is an agent exactly when it is the kodeblue user; anyone else who
// can reach the helper already has root (via sudo, or the socket as root) and
// is an operator, who may approve and undo. agentUID is the kodeblue user's
// uid, -1 when there is no such user (then only uid 0 is an operator).
type Caller struct {
	UID      int
	Via      string // socket | sudo | direct
	agentUID int
}

// Operator reports whether the caller may approve and undo. Anyone who
// reaches the helper and is not the kodeblue user had to have root to do so —
// as root over the socket, or through sudo — and is therefore an operator.
func (c Caller) Operator() bool {
	if c.Agent() {
		return false
	}
	return c.UID == 0 || c.Via == "sudo"
}

// Agent reports whether the caller is the unprivileged kodeblue user.
func (c Caller) Agent() bool { return c.agentUID >= 0 && c.UID == c.agentUID }

func (c Caller) String() string { return fmt.Sprintf("uid %d via %s", c.UID, c.Via) }

// agentUIDLookup is the kodeblue user's uid, or -1 (tests override it).
var agentUIDLookup = func() int {
	home, uid, err := lookupUser("kodeblue")
	if err != nil || home == "" {
		return -1
	}
	return uid
}

// IdentifyCaller works out who is on the other end of stdin. SUDO_UID (set by
// sudo, not by the caller) names the invoking user on the sudoers path; under
// systemd, stdin is the accepted connection and the kernel names the peer.
func IdentifyCaller(stdin *os.File) (Caller, error) {
	agent := agentUIDLookup()
	if s, ok := os.LookupEnv("SUDO_UID"); ok {
		uid, err := strconv.Atoi(s)
		if err != nil || uid < 0 {
			return Caller{}, fmt.Errorf("bad SUDO_UID %q", s)
		}
		return Caller{UID: uid, Via: "sudo", agentUID: agent}, nil
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(stdin.Fd()), &st); err != nil {
		return Caller{}, err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFSOCK {
		uid, err := peerUID(int(stdin.Fd()))
		if err != nil {
			return Caller{}, fmt.Errorf("cannot identify the caller on the socket: %w", err)
		}
		return Caller{UID: uid, Via: "socket", agentUID: agent}, nil
	}
	return Caller{UID: os.Getuid(), Via: "direct", agentUID: agent}, nil
}

// What an agent-side request may claim to be: the responder ("agent"), a
// monitor reflex, or either approved on the hub.
var (
	agentByRe = regexp.MustCompile(`^(agent|monitor:[A-Za-z0-9_.:-]+)$`)
	hubByRe   = regexp.MustCompile(`^(agent|monitor:[A-Za-z0-9_.:-]+)\+hub:[^\n]{1,200}\+operator$`)
)

// Authorize decides whether caller may have req executed under policy mode.
// An operator (root) may do anything the policy allows. The kodeblue user may
// only run what the root-owned policy grants an agent: nothing in
// recommend/off mode, and in contain mode only an agent or monitor request —
// never one that claims its own operator approval. Hub approvals reach the
// helper through the kodeblue user, so hub.accept_approvals (root-owned) is
// the only thing vouching for them.
func Authorize(mode string, hubApprovals bool, c Caller, req Request) error {
	if mode == "off" {
		return errors.New("response disabled by policy")
	}
	if c.Operator() {
		return nil
	}
	if !c.Agent() {
		return fmt.Errorf("the request came from an untrusted caller (%s)", c)
	}
	by := req.RequestedBy
	switch {
	case agentByRe.MatchString(by):
		if mode != "contain" {
			return fmt.Errorf("policy mode is %s: operator approval required", mode)
		}
		return nil
	case hubByRe.MatchString(by):
		if !hubApprovals {
			return errors.New("this server does not accept approvals from the hub (hub.accept_approvals = false, or no hub)")
		}
		return nil
	case strings.Contains(by, "+operator") || strings.Contains(by, "+hub:"):
		return fmt.Errorf("an operator approval is only accepted from root (this request came from %s): run kodeblue respond approve with sudo", c)
	}
	return fmt.Errorf("unknown requester %q", by)
}

// VouchedByOperator reports whether a human operator stands behind req: the
// caller is an operator (approved on the server), or it is a hub approval the
// root-owned policy accepts. The root helper uses this to decide whether to
// trust request hints it cannot recompute itself, such as incident_linked
// (which the MCP layer derives from the incident store and which otherwise
// widens what kill_process will do).
func VouchedByOperator(hubApprovals bool, c Caller, req Request) bool {
	if c.Operator() {
		return true
	}
	return c.Agent() && hubApprovals && hubByRe.MatchString(req.RequestedBy)
}

// AuthorizeUndo: only an operator undoes containment.
func AuthorizeUndo(c Caller) error {
	if !c.Operator() {
		return fmt.Errorf("undo is for operators only (this request came from %s): run kodeblue respond undo with sudo", c)
	}
	return nil
}
