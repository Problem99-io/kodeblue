package hub

import (
	"encoding/json"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

func TestAskBobAuthorizationCapabilityAndConversationScope(t *testing.T) {
	_, st, ts := newHub(t)
	if err := st.AddUser("alice", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	_, token, err := st.CreateServer("test-server", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, _, err := st.Enroll(token, "test-host", "")
	if err != nil {
		t.Fatal(err)
	}
	status := hubproto.Status{AcceptsMessages: true, AcceptsBob: true, ModelsEnabled: true}
	records := []hubproto.Record{{Kind: "incident", ID: "7", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":7,"kind":"incident","severity":"critical","status":"needs_human","report":"A requested action has not been approved."}`)}, {Kind: "incident", ID: "8", UpdatedAt: time.Now(), Data: json.RawMessage(`{"id":8,"kind":"incident","status":"resolved"}`)}}
	if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: status, Records: records}); err != nil {
		t.Fatal(err)
	}
	url := ts.URL + "/api/servers/" + srv.ID
	request := map[string]any{"incident_id": 7, "body": "Explain this report"}
	if code, _ := do(t, ts.Client(), "POST", url+"/bob", "", "", request); code != 401 {
		t.Fatalf("anonymous Bob request=%d", code)
	}
	client := ts.Client()
	client.Jar, _ = cookiejar.New(nil)
	code, body := do(t, client, "POST", ts.URL+"/api/login", "", "", map[string]string{"name": "alice", "password": "correct horse battery"})
	if code != 200 {
		t.Fatal(string(body))
	}
	var login struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, client, "POST", url+"/bob", "", "", request); code != 403 {
		t.Fatalf("CSRF bypass=%d", code)
	}
	code, body = do(t, client, "POST", url+"/bob", "", login.CSRF, request)
	if code != 200 {
		t.Fatalf("Bob request=%d %s", code, body)
	}
	var bob Message
	if err := json.Unmarshal(body, &bob); err != nil {
		t.Fatal(err)
	}
	if bob.Command != hubproto.CommandBob || bob.IncidentID != 7 || bob.ConversationID == "" {
		t.Fatalf("Bob metadata lost: %+v", bob)
	}
	for _, test := range []struct {
		path    string
		request map[string]any
		want    int
	}{
		{"/messages", map[string]any{"command": "bob", "body": "not an operator action", "incident_id": 7}, 400},
		{"/messages", map[string]any{"body": "change mode", "conversation_id": bob.ConversationID}, 409},
		{"/bob", map[string]any{"body": "different report", "incident_id": 8, "conversation_id": bob.ConversationID}, 409},
		{"/bob", map[string]any{"body": "unknown conversation", "incident_id": 7, "conversation_id": "c_unknown"}, 409},
		{"/bob", map[string]any{"body": "missing report", "incident_id": 999}, 404},
		{"/bob", map[string]any{"body": "run learning", "command": "learn", "incident_id": 7}, 400},
	} {
		if code, body := do(t, client, "POST", url+test.path, "", login.CSRF, test.request); code != test.want {
			t.Fatalf("%s=%d want=%d %s", test.path, code, test.want, body)
		}
	}
	code, body = do(t, client, "POST", url+"/messages", "", login.CSRF, map[string]any{"body": "ordinary operator conversation"})
	if code != 200 {
		t.Fatal(string(body))
	}
	var operator Message
	if err := json.Unmarshal(body, &operator); err != nil {
		t.Fatal(err)
	}
	if list := st.Messages(srv.ID, 200); len(list) != 1 || list[0].ID != operator.ID {
		t.Fatal("Bob crowded ordinary server conversation history")
	}
	if list := st.AllMessages(300); len(list) != 1 || list[0].ID != operator.ID {
		t.Fatal("Bob crowded ordinary fleet conversation history")
	}
	if code, _ := do(t, client, "POST", url+"/bob", "", login.CSRF, map[string]any{"body": "reuse operator", "incident_id": 7, "conversation_id": operator.ConversationID}); code != 409 {
		t.Fatalf("operator session reused=%d", code)
	}
	code, body = do(t, client, "GET", url+"/messages?bob_incident_id=7", "", "", nil)
	if code != 200 {
		t.Fatal(string(body))
	}
	var history []Message
	if err := json.Unmarshal(body, &history); err != nil || len(history) != 1 || history[0].ID != bob.ID {
		t.Fatalf("history mixed modes: %s %v", body, err)
	}
	if code, body := do(t, client, "GET", url+"/messages?bob_incident_id=8", "", "", nil); code != 200 || string(body) != "[]\n" {
		t.Fatalf("history crossed report scope: %d %s", code, body)
	}
	status.AcceptsBob = false
	if err := st.ApplySync(srv.ID, &hubproto.SyncRequest{Status: status}); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, client, "POST", url+"/bob", "", login.CSRF, request); code != 409 {
		t.Fatalf("unsupported agent accepted Bob=%d", code)
	}
	if len(st.BobMessages(srv.ID, 7)) != 1 {
		t.Fatal("refused requests were queued")
	}
}
