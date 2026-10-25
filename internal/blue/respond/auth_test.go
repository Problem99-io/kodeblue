package respond

import (
	"os"
	"strings"
	"testing"
)

// The kodeblue user (uid agentUID) is an agent; everyone else who reaches the
// helper is an operator. SUDO_UID set to a human admin is an operator even
// though it is not 0, because sudo put them there.
func TestCallerOperatorVsAgent(t *testing.T) {
	const kb = 999
	cases := []struct {
		c    Caller
		oper bool
		ag   bool
	}{
		{Caller{UID: 0, Via: "socket", agentUID: kb}, true, false},
		{Caller{UID: kb, Via: "socket", agentUID: kb}, false, true},
		{Caller{UID: 1000, Via: "sudo", agentUID: kb}, true, false}, // human admin via sudo
		{Caller{UID: kb, Via: "sudo", agentUID: kb}, false, true},   // daemon's sudoers rule
		{Caller{UID: 1000, Via: "socket", agentUID: kb}, false, false},
		{Caller{UID: 0, Via: "direct", agentUID: -1}, true, false},
	}
	for _, tc := range cases {
		if tc.c.Operator() != tc.oper || tc.c.Agent() != tc.ag {
			t.Errorf("%+v: operator=%v agent=%v, want %v/%v", tc.c, tc.c.Operator(), tc.c.Agent(), tc.oper, tc.ag)
		}
	}
}

// Approval spoofing: the kodeblue user cannot get an action executed in
// recommend mode by appending "+operator", nor claim a hub approval the
// policy does not accept. Only a real operator (root) may.
func TestAuthorizeRejectsSpoofedApproval(t *testing.T) {
	const kb = 999
	agent := Caller{UID: kb, Via: "socket", agentUID: kb}
	oper := Caller{UID: 0, Via: "socket", agentUID: kb}

	spoof := Request{Action: "block_ip", RequestedBy: "agent+operator"}
	if err := Authorize("recommend", true, agent, spoof); err == nil {
		t.Fatal("agent forged +operator in recommend mode must be refused")
	}
	// The same words from a real operator are fine (they are root).
	if err := Authorize("recommend", true, oper, spoof); err != nil {
		t.Fatalf("operator approval refused: %v", err)
	}
	// A hub approval is only honored when the root-owned policy accepts it.
	hub := Request{Action: "block_ip", RequestedBy: "agent+hub:alice+operator"}
	if err := Authorize("recommend", false, agent, hub); err == nil {
		t.Fatal("hub approval must be refused when accept_approvals is false")
	}
	if err := Authorize("recommend", true, agent, hub); err != nil {
		t.Fatalf("accepted hub approval refused: %v", err)
	}
	// In recommend mode a plain agent request is refused; in contain it runs.
	plain := Request{Action: "block_ip", RequestedBy: "agent"}
	if err := Authorize("recommend", true, agent, plain); err == nil {
		t.Fatal("plain agent request in recommend mode must be refused")
	}
	if err := Authorize("contain", true, agent, plain); err != nil {
		t.Fatalf("agent request in contain mode refused: %v", err)
	}
	// A caller that is neither operator nor the kodeblue user is refused.
	stranger := Caller{UID: 1000, Via: "socket", agentUID: kb}
	if err := Authorize("contain", true, stranger, plain); err == nil {
		t.Fatal("stranger on the socket must be refused")
	}
}

func TestAuthorizeUndoOperatorOnly(t *testing.T) {
	const kb = 999
	if err := AuthorizeUndo(Caller{UID: kb, Via: "socket", agentUID: kb}); err == nil {
		t.Fatal("the kodeblue user must not undo")
	}
	if err := AuthorizeUndo(Caller{UID: 0, Via: "socket", agentUID: kb}); err != nil {
		t.Fatalf("operator undo refused: %v", err)
	}
}

// incident_linked widens kill_process; the helper trusts it only when an
// operator vouches for the request.
func TestVouchedByOperator(t *testing.T) {
	const kb = 999
	agent := Caller{UID: kb, Via: "socket", agentUID: kb}
	oper := Caller{UID: 0, Via: "socket", agentUID: kb}
	if VouchedByOperator(true, agent, Request{RequestedBy: "agent"}) {
		t.Fatal("a plain agent request is not vouched for")
	}
	if !VouchedByOperator(true, agent, Request{RequestedBy: "agent+hub:alice+operator"}) {
		t.Fatal("an accepted hub approval is vouched for")
	}
	if VouchedByOperator(false, agent, Request{RequestedBy: "agent+hub:alice+operator"}) {
		t.Fatal("a hub approval the policy rejects is not vouched for")
	}
	if !VouchedByOperator(false, oper, Request{RequestedBy: "agent"}) {
		t.Fatal("an operator always vouches")
	}
}

// IdentifyCaller reads SUDO_UID on the sudoers path.
func TestIdentifyCallerSudo(t *testing.T) {
	defer func(f func() int) { agentUIDLookup = f }(agentUIDLookup)
	agentUIDLookup = func() int { return 999 }
	t.Setenv("SUDO_UID", "1000")
	c, err := IdentifyCaller(os.Stdin)
	if err != nil || c.UID != 1000 || c.Via != "sudo" || !c.Operator() {
		t.Fatalf("sudo caller: %+v %v", c, err)
	}
	t.Setenv("SUDO_UID", "999")
	c, _ = IdentifyCaller(os.Stdin)
	if !c.Agent() || c.Operator() {
		t.Fatalf("kodeblue via sudoers must be an agent: %+v", c)
	}
	if strings.TrimSpace(c.String()) == "" {
		t.Fatal("String()")
	}
}
