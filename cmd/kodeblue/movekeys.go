package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
	"github.com/Problem99-io/kodeblue/internal/blue/respond"
	"github.com/Problem99-io/kodeblue/internal/blue/upgrade"
)

// moveKeysCmd hands this server's own model endpoint and key to the hub,
// which takes them over as a connection for this server and picks the same
// models on it, then removes every copy here: the key file is emptied and an
// inline api_key and the endpoint are dropped from the config. A key the
// server holds without calling an endpoint with it (a key file next to an
// inline key, or left by an older enrollment) goes to the hub too, which
// keeps it aside for an operator. Settings an older hub saved here with
// connection keys need nothing: the hub now sends this server its
// connections without keys, and the daemon replaces them on its first sync
// (keys of connections servers call themselves stay, as chosen on the hub).
//
// It moves keys only to a hub at least as new as this server: a hub that is
// behind may not take them the way this version expects, so the keys stay
// until the hub is upgraded, and then the daemon has the root helper run
// this again (helper op move_keys). The installer runs it as root on every
// install and upgrade of a server on a hub; it changes nothing when there is
// nothing to move or the hub cannot take the key.
func moveKeysCmd(cfg config.Config) {
	if os.Geteuid() != 0 {
		fatal(errors.New("move-keys must run as root (it edits /etc/kodeblue): use sudo"))
	}
	if !cfg.Hub.Enabled() {
		fmt.Println("not on a hub: the model key stays on this server")
		return
	}
	if !cfg.Hub.AcceptSettings {
		fmt.Println("[hub] accept_settings is off, so the hub cannot give this server its models: the model key stays on this server")
		return
	}
	u, err := hubproto.CheckURL(cfg.Hub.URL)
	if err != nil {
		fatal(err)
	}
	hubKey, err := cfg.Hub.APIKey()
	if err != nil {
		fatal(err)
	}
	client, err := hubproto.HTTPClient(cfg.Hub.Pin, cfg.Hub.CAFile, 30*time.Second)
	if err != nil {
		fatal(err)
	}
	move := func(req hubproto.MoveKeysRequest) (hubproto.MoveKeysResponse, bool) {
		var resp hubproto.MoveKeysResponse
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		err := hublink.Call(ctx, client, u.String(), hubKey, http.MethodPost, hubproto.PathMoveKeys, req, &resp)
		switch code, msg := hublink.Status(err); {
		case code == http.StatusNotFound:
			fmt.Println("the hub does not take model keys yet (update the hub): model keys stay on this server")
			os.Exit(0)
		case code == http.StatusUnprocessableEntity || code == http.StatusTooManyRequests:
			fmt.Println("the hub kept the model key here:", msg)
			return resp, false
		case err != nil:
			fatal(fmt.Errorf("the hub could not be reached, model keys stay on this server for now: %w", err))
		}
		return resp, resp.Connection != "" || resp.Kept
	}

	// Ask first, moving nothing: the hub learns that this server calls its
	// models through the hub, and says which version it runs.
	hello, _ := move(hubproto.MoveKeysRequest{})
	if hubBehind(hello.HubVersion) {
		hv := hello.HubVersion
		if hv == "" {
			hv = "an older version"
		}
		fmt.Printf("the hub runs %s, older than this server (%s): model keys stay on this server until the hub is upgraded, then kodeblue moves them by itself\n", hv, hubproto.Version)
		return
	}

	inline, file, env := ownKeys(cfg)
	if env != "" {
		fmt.Printf("the model key comes from $%s, which kodeblue cannot remove: it stays (unset it, then run sudo kodeblue move-keys)\n", cfg.Inference.APIKeyEnv)
	}
	key := inline
	if key == "" {
		key = file
	}
	if key == "" || env != "" {
		fmt.Println("no model key to move")
		return
	}
	resp, ok := move(hubproto.MoveKeysRequest{BaseURL: cfg.Inference.BaseURL, Key: key, Models: ownModels(cfg.WithHubSettings())})
	if !ok {
		return
	}
	var gone []string
	if inline != "" {
		gone = append(gone, "api_key removed from "+cfg.Path())
	}
	// The key file next to an inline key: the same key goes with it; another
	// one goes to the hub on its own, which has it or keeps it aside.
	if file != "" && (file == key || func() bool {
		_, ok := move(hubproto.MoveKeysRequest{Key: file, SeenWith: cfg.Inference.BaseURL})
		return ok
	}()) {
		if err := writeKey(cfg.Inference.APIKeyFile, ""); err != nil {
			fatal(fmt.Errorf("the hub took the key, but emptying %s failed: %w", cfg.Inference.APIKeyFile, err))
		}
		gone = append(gone, cfg.Inference.APIKeyFile+" emptied")
	} else if file != "" {
		fmt.Printf("%s holds another key, which the hub did not take: it stays\n", cfg.Inference.APIKeyFile)
	}
	if err := dropOwnEndpoint(cfg.Path(), resp.Connection); err != nil {
		fatal(fmt.Errorf("the hub took the key, but editing %s failed: %w", cfg.Path(), err))
	}
	if strings.TrimSpace(cfg.Inference.BaseURL) != "" {
		gone = append(gone, "the endpoint dropped from "+cfg.Path())
	}
	how := "now holds it as connection " + resp.Connection
	switch {
	case resp.Created:
		how = "took it over as a new connection, " + resp.Connection
	case resp.Kept:
		how = "keeps it aside until an operator makes it a connection or deletes it (Settings, Model connections)"
	}
	fmt.Printf("model key moved: the hub %s", how)
	if len(resp.Roles) > 0 {
		fmt.Printf(" (models for %s)", strings.Join(resp.Roles, ", "))
	}
	fmt.Printf("; on this server: %s\n", strings.Join(gone, ", "))
	restartService()
}

// moveKeysUnit is the systemd unit a move asked for by the daemon runs in:
// it outlives the kodeblue service it restarts, and one runs at a time.
const moveKeysUnit = "kodeblue-move-keys"

// startMoveKeys is the root helper's move_keys op: the daemon asks once the
// hub is at least as new as this server, for a key the installer left here
// because the hub was behind. It runs move-keys in its own unit and returns.
// The kodeblue user may ask only on a server that takes its settings from a
// hub; the move goes to the hub of the root-owned config, nowhere else.
func startMoveKeys(cfg config.Config, caller respond.Caller) (respond.Record, error) {
	switch {
	case caller.Agent():
		if !cfg.Hub.Enabled() || !cfg.Hub.AcceptSettings {
			return respond.Record{}, errors.New("this server does not take its settings from a hub (hub.accept_settings): its model key stays")
		}
	case !caller.Operator():
		return respond.Record{}, fmt.Errorf("%s may not move the model keys", caller)
	}
	run, err := exec.LookPath("systemd-run")
	if _, serr := os.Stat("/run/systemd/system"); err != nil || serr != nil {
		return respond.Record{}, errors.New("no systemd on this server: run sudo kodeblue move-keys")
	}
	self, err := os.Executable()
	if err != nil {
		return respond.Record{}, err
	}
	out, err := exec.Command(run, "--unit", moveKeysUnit, "--collect", "--quiet",
		"--description", "kodeblue: move model keys to the hub", "--",
		self, "move-keys", "--config", cfg.Path()).CombinedOutput()
	if err != nil {
		return respond.Record{}, fmt.Errorf("could not start the move (is one running? systemctl status %s): %s", moveKeysUnit, strings.TrimSpace(string(out)))
	}
	return respond.Record{ID: "move-keys", Action: "move_keys", Status: "started",
		Result: fmt.Sprintf("moving the model keys to the hub in unit %s (journalctl -u %s)", moveKeysUnit, moveKeysUnit)}, nil
}

// hubBehind reports whether a hub running version v is older than this
// server (an empty v: a hub from before it said, so older).
func hubBehind(v string) bool {
	return v == "" || upgrade.Behind(v, hubproto.Version)
}

// ownKeys are the keys of the server's own [inference] endpoint: inline in
// the config, in the key file, and in the environment (which kodeblue cannot
// remove). A key file counts even without an endpoint: an older enrollment
// may have left one.
func ownKeys(cfg config.Config) (inline, file, env string) {
	in := cfg.Inference
	inline = strings.TrimSpace(in.APIKey)
	if in.APIKeyFile != "" {
		if b, err := os.ReadFile(in.APIKeyFile); err == nil {
			file = strings.TrimSpace(string(b))
		}
	}
	if in.APIKeyEnv != "" && inline == "" && file == "" && strings.TrimSpace(in.BaseURL) != "" {
		env = strings.TrimSpace(os.Getenv(in.APIKeyEnv))
	}
	return inline, file, env
}

// ownModels are the models of the roles that use the server's own endpoint:
// the default (agent_model) and each role whose model differs from it. The
// others follow the default on the hub too, so a default changed there
// later reaches them. Critical always goes when escalation_model is set,
// since the server would pick it over the hub's default.
func ownModels(cfg config.Config) map[string]hubproto.ModelRef {
	if strings.TrimSpace(cfg.Inference.BaseURL) == "" {
		return nil
	}
	norm := func(r hubproto.ModelRef) hubproto.ModelRef {
		if r.Provider == "" {
			r.Provider = cfg.Inference.Provider
		}
		return r
	}
	def := norm(cfg.ModelRef(hubproto.RoleDefault))
	out := map[string]hubproto.ModelRef{}
	for _, role := range hubproto.ModelRoles {
		r := norm(cfg.ModelRef(role))
		if r.Connection != "" || strings.TrimSpace(r.Model) == "" {
			continue
		}
		if role == hubproto.RoleDefault || r != def || (role == hubproto.RoleCritical && cfg.Inference.EscalationModel != "") {
			out[role] = r
		}
	}
	return out
}

// dropOwnEndpoint removes the [inference] api_key line and comments out
// base_url, noting where the endpoint went. /etc/kodeblue is root's, so the
// file is replaced the way replaceSection does.
func dropOwnEndpoint(path, conn string) error {
	where := "connection " + conn
	if conn == "" {
		where = "the hub"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = t
		}
		if section == "[inference]" {
			k, _, ok := strings.Cut(t, "=")
			switch k = strings.TrimSpace(k); {
			case ok && k == "api_key":
				continue
			case ok && k == "base_url":
				out = append(out, fmt.Sprintf("# Moved to %s (kodeblue move-keys, %s): this server calls its models through the hub.", where, time.Now().UTC().Format("2006-01-02")))
				line = "# " + line
			}
		}
		out = append(out, line)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")), st.Mode().Perm()); err != nil {
		return err
	}
	if g, err := user.LookupGroup("kodeblue"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		_ = os.Chown(tmp, 0, gid)
	}
	return os.Rename(tmp, path)
}
