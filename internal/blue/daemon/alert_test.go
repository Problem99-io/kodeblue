package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/notify"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestAgentPostedRecognizesRenamedAlerts(t *testing.T) {
	for _, action := range []string{"slack.agent", "alert.agent"} {
		t.Run(action, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "kb.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			d := &Daemon{st: st, slack: &notify.Outbox{Q: st}}
			st.Journal("agent", action, "incident=7 high: Alert sent")
			if !d.agentPosted(7, time.Now().Add(-time.Hour)) || d.agentPosted(70, time.Now().Add(-time.Hour)) {
				t.Fatal("incident duplicate suppression lost the alert or matched a different incident")
			}
		})
	}
}
