package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/containment"
)

const rulesUsage = "usage: kodeblue rules [list] | show <id> | approve <id> [--yes] | reject <id> <why> | pause <id> <why> | delete <id> [note]"

// rulesCmd lists and rules on containment rules. Approving and deleting go
// to the root helper, which takes them only from root (run with sudo).
func rulesCmd(cfg config.Config, pos []string, yes bool) {
	if len(pos) == 0 {
		pos = []string{"list"}
	}
	st := mustStore(cfg)
	defer st.Close()
	if pos[0] == "list" {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tACTION\tWHEN\tFIRED\tEXPIRES\tTITLE")
		for _, v := range containment.List(cfg, st) {
			status := v.Status
			if v.Pending {
				status += " (change waiting)"
			}
			expires := "-"
			if !v.ExpiresAt.IsZero() {
				expires = v.ExpiresAt.Local().Format("2006-01-02")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", v.ID, status, v.Action, v.When.Rule, v.Fired, expires, trunc(v.Title, 60))
		}
		w.Flush()
		return
	}
	if len(pos) < 2 {
		fatal(errors.New(rulesUsage))
	}
	id := pos[1]
	note := strings.TrimSpace(strings.Join(pos[2:], " "))
	v := containment.Get(cfg, st, id)
	if v == nil {
		fatal(fmt.Errorf("no containment rule %s", id))
	}
	ctx := context.Background()
	switch pos[0] {
	case "show":
		printRule(os.Stdout, *v)
	case "approve":
		printRule(os.Stdout, *v)
		if !yes && !confirm("Approve this rule? kodeblue will take this action on its own every time it matches. [y/N] ") {
			fatal(errors.New("not approved"))
		}
		r, err := containment.Approve(ctx, cfg, st, id, v.Hash, "")
		if err != nil {
			fatal(err)
		}
		st.Journal(r.ApprovedBy, "rule.approved", id+" until "+r.ExpiresAt.UTC().Format("2006-01-02"))
		fmt.Printf("%s approved by %s; active until %s\n", id, r.ApprovedBy, r.ExpiresAt.Local().Format("2006-01-02 15:04"))
	case "reject":
		if note == "" {
			fatal(errors.New("usage: kodeblue rules reject <id> <why>"))
		}
		if err := containment.Reject(st, id, "operator", note); err != nil {
			fatal(err)
		}
		st.Journal("operator", "rule.rejected", id+": "+note)
		fmt.Println(id, "rejected")
	case "pause":
		if note == "" {
			fatal(errors.New("usage: kodeblue rules pause <id> <why>"))
		}
		if _, err := containment.Pause(ctx, cfg, st, id, "", note); err != nil {
			fatal(err)
		}
		fmt.Println(id, "paused; approve it again to resume")
	case "delete":
		if _, err := containment.Delete(ctx, cfg, st, id, "", note); err != nil {
			fatal(err)
		}
		st.Journal("operator", "rule.deleted", id)
		fmt.Println(id, "deleted")
	default:
		fatal(errors.New(rulesUsage))
	}
}

func printRule(w io.Writer, v containment.View) {
	fmt.Fprintf(w, "%s  %s\n  status:   %s", v.ID, v.Title, v.Status)
	if v.Pending {
		fmt.Fprint(w, " (a changed version waits for approval; approving replaces the active one)")
	}
	fmt.Fprintf(w, "\n  when:     a finding of rule %s", v.When.Rule)
	if v.When.Field != "" {
		fmt.Fprintf(w, ", target from evidence field %q", v.When.Field)
	}
	if v.When.Extract != "" {
		fmt.Fprintf(w, ", extracted with /%s/", v.When.Extract)
	}
	fmt.Fprintf(w, "\n  action:   %s", v.Action)
	for k, s := range v.Scope {
		fmt.Fprintf(w, ", %s %s", k, s)
	}
	fmt.Fprintf(w, "\n  limits:   %d per hour, active %d days after approval\n", v.MaxPerHour, v.Days)
	fmt.Fprintf(w, "  proposed: by %s %s\n", v.ProposedBy, v.ProposedAt.Local().Format("2006-01-02 15:04"))
	if v.ApprovedBy != "" {
		fmt.Fprintf(w, "  approved: by %s %s, expires %s\n", v.ApprovedBy, v.ApprovedAt.Local().Format("2006-01-02 15:04"), v.ExpiresAt.Local().Format("2006-01-02 15:04"))
	}
	if v.Fired > 0 {
		fmt.Fprintf(w, "  fired:    %d times, last %s\n", v.Fired, v.LastFired.Local().Format(time.DateTime))
	}
	fmt.Fprintf(w, "  why:      %s\n  hash:     %s\n\n", strings.ReplaceAll(v.Why, "\n", "\n            "), v.Hash)
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}
