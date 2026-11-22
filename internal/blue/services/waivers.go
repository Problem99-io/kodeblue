package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/store"
)

// WaiversKey holds the coverage waivers: checks a human or an agent said
// cannot be covered on this server, with the reason. A waived check is not
// missing, so it opens no coverage case, but the inventory and the hub
// still show it, with the reason, as not watched.
const WaiversKey = "coverage_waivers"

// Waiver is one waived check of one service.
type Waiver struct {
	Reason    string    `json:"reason"`
	By        string    `json:"by"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Waivers maps service name to check to its waiver.
type Waivers map[string]map[string]Waiver

// DefaultWaiverDays is how long a waiver lasts unless told otherwise: the
// server changes, and a limitation that was real may not be any more.
const DefaultWaiverDays = 180

// MaxWaiverDays caps a waiver's life.
const MaxWaiverDays = 365

// LoadWaivers reads the waivers that have not expired.
func LoadWaivers(st *store.Store) Waivers {
	all := Waivers{}
	_ = json.Unmarshal([]byte(st.Get(WaiversKey)), &all)
	now := time.Now()
	out := Waivers{}
	for svc, checks := range all {
		for c, w := range checks {
			if !w.ExpiresAt.IsZero() && now.After(w.ExpiresAt) {
				continue
			}
			if out[svc] == nil {
				out[svc] = map[string]Waiver{}
			}
			out[svc][c] = w
		}
	}
	return out
}

func saveWaivers(st *store.Store, w Waivers) error {
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return st.Set(WaiversKey, string(b))
}

// Waive records that checks of service cannot be covered here, for days
// (DefaultWaiverDays when 0). Only the known checks can be waived: they are
// the ones kodeblue itself would otherwise keep asking for.
func Waive(st *store.Store, service string, checks []string, reason, by string, days int) error {
	service, reason = strings.TrimSpace(service), strings.TrimSpace(reason)
	switch {
	case service == "":
		return errors.New("service is required")
	case len(checks) == 0:
		return errors.New("name the checks to waive")
	case len(reason) < 20:
		return errors.New("reason must say why the check cannot be covered here")
	}
	if extra := unknownChecks(checks); len(extra) > 0 {
		return fmt.Errorf("only %s can be waived, not %s", strings.Join(known, ", "), strings.Join(extra, ", "))
	}
	if days <= 0 {
		days = DefaultWaiverDays
	}
	days = min(days, MaxWaiverDays)
	w := LoadWaivers(st)
	if w[service] == nil {
		w[service] = map[string]Waiver{}
	}
	now := time.Now().UTC()
	for _, c := range checks {
		w[service][c] = Waiver{Reason: reason, By: by, At: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}
	}
	if err := saveWaivers(st, w); err != nil {
		return err
	}
	st.Journal(by, "coverage.waive", fmt.Sprintf("%s: %s until %s (%s)", service, strings.Join(checks, ","), now.Add(time.Duration(days)*24*time.Hour).Format("2006-01-02"), reason))
	return nil
}

// Unwaive drops the waivers of checks of service (all of them when checks
// is empty), so kodeblue asks for those checks again.
func Unwaive(st *store.Store, service string, checks []string, by string) (int, error) {
	w := LoadWaivers(st)
	n := 0
	for c := range w[service] {
		if len(checks) == 0 || slices.Contains(checks, c) {
			delete(w[service], c)
			n++
		}
	}
	if len(w[service]) == 0 {
		delete(w, service)
	}
	if n == 0 {
		return 0, nil
	}
	if err := saveWaivers(st, w); err != nil {
		return 0, err
	}
	st.Journal(by, "coverage.unwaive", fmt.Sprintf("%s: %s", service, strings.Join(checks, ",")))
	return n, nil
}

// List returns the waivers sorted by service and check, for display.
func (w Waivers) List() []string {
	var out []string
	for svc, checks := range w {
		for c, wv := range checks {
			out = append(out, fmt.Sprintf("%s\t%s\t%s\t%s\t%s", svc, c, wv.By, wv.ExpiresAt.Format("2006-01-02"), wv.Reason))
		}
	}
	sort.Strings(out)
	return out
}
