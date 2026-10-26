package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/store"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

// openMaintenance opens a maintenance window of d and journals why.
func openMaintenance(cfg config.Config, st *store.Store, d time.Duration, reason string) (string, error) {
	until := time.Now().Add(d).UTC().Format(time.RFC3339)
	if err := os.WriteFile(cfg.MaintenanceFile(), []byte(until), 0o640); err != nil {
		return "", err
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		reason = "planned work"
	}
	st.Journal("operator", "maintenance.on", "until "+until+": "+reason)
	return until, nil
}

// upgradeCmd installs a release: `sudo kodeblue upgrade v0.1.7`, or the
// root helper's unit for an upgrade a hub operator started. The release
// comes from [upgrade] release_url and must match its SHA256SUMS.
func upgradeCmd(cfg config.Config, version, by string) {
	if os.Geteuid() != 0 {
		fatal(errors.New("kodeblue upgrade must run as root (sudo)"))
	}
	if err := checkRootOwned(cfg.Path()); err != nil {
		fatal(err)
	}
	if by == "" {
		by = "root"
	}
	uid := -1
	if u, err := user.Lookup("kodeblue"); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	install := upgrade.RunInstaller(os.Stdout)
	err := upgrade.Apply(ctx, upgrade.Options{
		ReleaseURL: cfg.Upgrade.ReleaseURL, Version: version, Running: hubproto.Version,
		StateDir: cfg.Server.StateDir, StatusUID: uid, By: by, Log: os.Stdout,
		Install: func(ctx context.Context, dir string) error {
			// Only now, with a genuine newer release in hand: kodeblue
			// watches its own binaries, and the swap is planned work. The
			// installer opens its own window too, right before the swap.
			if st, err := store.Open(cfg.DBPath()); err == nil {
				_, _ = openMaintenance(cfg, st, 15*time.Minute, fmt.Sprintf("kodeblue upgrade %s -> %s (asked by %s)", hubproto.Version, version, by))
				st.Close()
				if uid >= 0 {
					_ = os.Chown(cfg.MaintenanceFile(), uid, uid)
				}
			}
			return install(ctx, dir)
		},
	})
	if err != nil {
		fatal(err)
	}
}

var byRe = regexp.MustCompile(`^[A-Za-z0-9:@._+-]{1,80}$`)

// startUpgrade is the root helper's upgrade op: it starts `kodeblue upgrade`
// in its own systemd unit, which outlives the kodeblue service it restarts,
// and returns. The kodeblue user may ask only on a server enrolled with a hub
// whose root-owned config accepts upgrades from it; root may always.
func startUpgrade(cfg config.Config, caller respond.Caller, env helperEnvelope) (respond.Record, error) {
	switch {
	case caller.Agent():
		if !cfg.Hub.Enabled() || !cfg.Hub.AcceptUpgrades {
			return respond.Record{}, errors.New("upgrades from the hub are off on this server (hub.accept_upgrades)")
		}
	case !caller.Operator():
		return respond.Record{}, fmt.Errorf("%s may not upgrade kodeblue", caller)
	}
	if err := upgrade.Check(env.Version, hubproto.Version); err != nil {
		return respond.Record{}, err
	}
	by := env.By
	if !byRe.MatchString(by) {
		by = "uid-" + strconv.Itoa(caller.UID)
	}
	run, err := exec.LookPath("systemd-run")
	if _, serr := os.Stat("/run/systemd/system"); err != nil || serr != nil {
		return respond.Record{}, fmt.Errorf("no systemd on this server: run sudo kodeblue upgrade %s", env.Version)
	}
	self, err := os.Executable()
	if err != nil {
		return respond.Record{}, err
	}
	out, err := exec.Command(run, "--unit", upgrade.Unit, "--collect", "--quiet",
		"--description", "kodeblue upgrade to "+env.Version, "--",
		self, "upgrade", env.Version, "--by", by, "--config", cfg.Path()).CombinedOutput()
	if err != nil {
		return respond.Record{}, fmt.Errorf("could not start the upgrade (is one running? systemctl status %s): %s", upgrade.Unit, strings.TrimSpace(string(out)))
	}
	return respond.Record{ID: "upgrade-" + env.Version, Action: "upgrade", Status: "started",
		Result: fmt.Sprintf("upgrading %s -> %s in unit %s (journalctl -u %s)", hubproto.Version, env.Version, upgrade.Unit, upgrade.Unit)}, nil
}
