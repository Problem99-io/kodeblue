package daemon

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/monitor"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

func TestSeedRequestMonitors(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.StateDir = dir
	st, err := store.Open(filepath.Join(dir, "kb.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := New(cfg, st, slog.Default())

	// No tap: nothing seeded.
	d.setTapStatus(TapStatus{Status: "unavailable"})
	d.seedRequestMonitors()
	if n := len(st.Monitors(false)); n != 0 {
		t.Fatalf("no tap should seed nothing, got %d", n)
	}

	d.setTapStatus(TapStatus{Status: "ok", Log: filepath.Join(dir, "requests", "access.log")})
	d.seedRequestMonitors()
	d.seedRequestMonitors() // idempotent
	rows := st.Monitors(false)
	byID := map[string]monitor.Spec{}
	for _, r := range rows {
		var s monitor.Spec
		if err := json.Unmarshal(r.Spec, &s); err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("%s invalid: %v", s.ID, err)
		}
		byID[s.ID] = s
	}
	if len(byID) != 4 {
		t.Fatalf("want 4 seeded monitors (idempotent), got %d", len(rows))
	}
	// A successful login from a new client must trip; nothing is pre-trusted.
	login := byID["kb-requests-new-login"]
	if login.KnownValues == nil || len(*login.KnownValues) != 0 || !login.NewValues {
		t.Fatalf("new-login must pre-trust nothing: %+v", login.KnownValues)
	}
	lre := regexp.MustCompile(login.Pattern)
	if !lre.MatchString(`x - - [x] "POST /rest/user/login HTTP/1.1" 200 - "-" "c"`) ||
		!lre.MatchString(`x - - [x] "POST /api/Users HTTP/1.1" 201 - "-" "c"`) ||
		lre.MatchString(`x - - [x] "GET /api/Products HTTP/1.1" 200 - "-" "c"`) {
		t.Fatalf("new-login pattern wrong: %s", login.Pattern)
	}
	// The earlier attack: a burst of 401/500 and an admin/enum client.
	errs := byID["kb-requests-error-bursts"]
	re := regexp.MustCompile(errs.Pattern)
	hit := `::ffff:172.30.0.3 - - [x] "GET /api/Users HTTP/1.1" 401 - "-" "curl/8.5.0"`
	miss := `::ffff:172.30.0.3 - - [x] "GET /api/Products HTTP/1.1" 200 - "-" "curl/8.5.0"`
	if !re.MatchString(hit) || re.MatchString(miss) {
		t.Fatalf("error-burst pattern wrong: hit=%v miss=%v", re.MatchString(hit), re.MatchString(miss))
	}
}
