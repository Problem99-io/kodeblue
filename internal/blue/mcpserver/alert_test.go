package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func alertServer(t *testing.T, limit int) (*Server, *store.Store) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.StateDir = t.TempDir()
	cfg.Server.Name = "test-server"
	cfg.Hub.URL = "https://hub.example.test"
	cfg.Notify.AgentMessagesPerHour = limit
	st, err := store.Open(filepath.Join(cfg.Server.StateDir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(cfg, st), st
}

func TestSendAlertMCPQueuesForConfiguredDestinations(t *testing.T) {
	s, st := alertServer(t, 20)
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_alert","arguments":{"severity":"high","title":"Suspicious login","message":"An unfamiliar source authenticated as deploy.","incident_id":7}}}` + "\n"
	var output bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var catalog struct {
		Result struct {
			Tools []struct{ Name string }
		}
	}
	if err := decoder.Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range catalog.Result.Tools {
		if tool.Name == "notify_slack" {
			t.Fatal("catalog still exposes a provider-specific notification tool")
		}
		found = found || tool.Name == "send_alert"
	}
	if !found {
		t.Fatal("send_alert is not available to agents")
	}
	var reply struct {
		Error  json.RawMessage
		Result struct {
			IsError bool
			Content []struct{ Text string }
		}
	}
	if err := decoder.Decode(&reply); err != nil || len(reply.Error) != 0 || reply.Result.IsError || len(reply.Result.Content) != 1 {
		t.Fatalf("tool invocation failed: %+v, decode error %v", reply, err)
	}
	queued := st.UnsyncedNotifications(10)
	if len(queued) != 1 || queued[0].Kind != "agent" || queued[0].Severity != "high" || queued[0].IncidentID != 7 || queued[0].Title != "Suspicious login" {
		t.Fatalf("alert not queued with its context: %+v", queued)
	}
}

type alertDestination struct{ messages []notify.Message }

func (d *alertDestination) Send(_ context.Context, m notify.Message) error {
	d.messages = append(d.messages, m)
	return nil
}
func (d *alertDestination) Async(m notify.Message, _ func(error)) { d.messages = append(d.messages, m) }

func TestSendAlertUsesGenericSenders(t *testing.T) {
	s, _ := alertServer(t, 20)
	a, b := &alertDestination{}, &alertDestination{}
	s.slack = notify.New(false, nil, "", "", false, a, b)
	if _, err := s.sendAlert(context.Background(), json.RawMessage(`{"severity":"high","title":"Alert","message":"A security event needs attention."}`)); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []*alertDestination{a, b} {
		if len(destination.messages) != 1 || destination.messages[0].Server != "test-server" || destination.messages[0].Body != "A security event needs attention." {
			t.Fatalf("generic destination did not receive the alert: %+v", destination.messages)
		}
	}
}

func TestSendAlertRateLimitSurvivesRename(t *testing.T) {
	for _, action := range []string{"slack.agent", "alert.agent"} {
		t.Run(action, func(t *testing.T) {
			s, st := alertServer(t, 2)
			st.Journal("agent", action, "incident=7 high: Earlier alert")
			args := json.RawMessage(`{"severity":"high","title":"Alert","message":"A security event needs attention."}`)
			if _, err := s.sendAlert(context.Background(), args); err != nil {
				t.Fatal(err)
			}
			if _, err := s.sendAlert(context.Background(), args); err == nil || !strings.Contains(err.Error(), "Alert rate limit") {
				t.Fatalf("hourly cap did not count historical and new alerts: %v", err)
			}
			if queued := st.UnsyncedNotifications(10); len(queued) != 1 {
				t.Fatalf("rate-limited call queued another alert: %+v", queued)
			}
		})
	}
}

type failedAlertDestination struct{}

func (failedAlertDestination) Send(context.Context, notify.Message) error {
	return errors.New("Telegram down")
}
func (failedAlertDestination) Async(notify.Message, func(error)) {}
func TestPartialDeliveryIsJournaledAndRateLimited(t *testing.T) {
	s, st := alertServer(t, 2)
	good := &alertDestination{}
	s.slack = notify.New(false, nil, "", "", false, good, failedAlertDestination{})
	args := json.RawMessage(`{"severity":"high","title":"Alert","message":"A real security update needs attention.","incident_id":7}`)
	for i := 0; i < 2; i++ {
		if _, err := s.sendAlert(context.Background(), args); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.sendAlert(context.Background(), args); err == nil || len(good.messages) != 2 {
		t.Fatalf("partial retries bypassed cap: %v posts=%d", err, len(good.messages))
	}
	n := 0
	for _, entry := range st.JournalSince(time.Now().Add(-time.Hour), 20) {
		if entry.Action == "alert.agent" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("accepted alerts not journaled: %d", n)
	}
}
