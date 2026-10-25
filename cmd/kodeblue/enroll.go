package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Problem99-io/kodeblue/internal/blue/config"
	"github.com/Problem99-io/kodeblue/internal/blue/hublink"
	"github.com/Problem99-io/kodeblue/internal/blue/hubproto"
)

// enrollCmd registers this server with a kodeblue hub. It trades a one-time
// enrollment token (from the hub's "Add server" dialog) for this server's own
// API key, stores the key root:kodeblue 0640, and points [hub] at the hub.
// The token is read from $KODEBLUE_ENROLL_TOKEN so it stays out of argv.
func enrollCmd(cfg config.Config, hubURL, pin, caFile, name string) {
	if os.Geteuid() != 0 {
		fatal(errors.New("enroll must run as root (it writes /etc/kodeblue)"))
	}
	token := strings.TrimSpace(os.Getenv("KODEBLUE_ENROLL_TOKEN"))
	if token == "" {
		fatal(errors.New("set KODEBLUE_ENROLL_TOKEN to the enrollment token from the hub"))
	}
	u, err := hubproto.CheckURL(hubURL)
	if err != nil {
		fatal(err)
	}
	client, err := hubproto.HTTPClient(pin, caFile, 30*time.Second)
	if err != nil {
		fatal(err)
	}
	host, _ := os.Hostname()
	if name == "" {
		name = cfg.Server.Name
	}
	var resp hubproto.EnrollResponse
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := hublink.Call(ctx, client, u.String(), "", http.MethodPost, hubproto.PathEnroll,
		hubproto.EnrollRequest{Token: token, Name: name, Hostname: host, Version: hubproto.Version}, &resp); err != nil {
		fatal(fmt.Errorf("enrollment failed: %w", err))
	}
	if resp.APIKey == "" {
		fatal(errors.New("hub returned no API key"))
	}
	if err := writeSecret(cfg.Hub.KeyFile, resp.APIKey, true); err != nil {
		fatal(err)
	}
	if resp.InferenceKey != "" && cfg.Inference.APIKeyFile != "" {
		_ = writeSecret(cfg.Inference.APIKeyFile, resp.InferenceKey, false)
	}
	if d := resp.Inference; d != nil && cfg.Inference.BaseURL == "" {
		if err := writeInference(cfg, d.BaseURL, d.Provider, d.Model); err != nil {
			fmt.Fprintln(os.Stderr, "kodeblue: fleet model endpoint not applied:", err)
		} else {
			fmt.Printf("model endpoint from the hub: %s (%s)\n", d.BaseURL, d.Model)
		}
	}
	section := fmt.Sprintf("[hub]\n# Written by `kodeblue enroll`. kodeblue dials out to the hub; nothing listens here.\nurl = %s\nkey_file = %s\n", strconv.Quote(u.String()), strconv.Quote(cfg.Hub.KeyFile))
	if pin != "" {
		section += fmt.Sprintf("pin = %s\n", strconv.Quote(pin))
	}
	if caFile != "" {
		section += fmt.Sprintf("ca_file = %s\n", strconv.Quote(caFile))
	}
	section += "accept_messages = true      # operators can message this server's agents from the hub\nshare_transcripts = true    # agents' reasoning and tool calls are visible on the hub\n"
	if err := replaceSection(cfg.Path(), "hub", section); err != nil {
		fatal(err)
	}
	fmt.Printf("enrolled with %s as %q (server id %s)\n", u.Host, resp.Name, resp.ServerID)
	fmt.Println("notifications now go to the hub, which posts them to Slack (configure the channel on the hub)")
}

// writeSecret writes a one-line secret root:kodeblue 0640. Unless overwrite
// is set, an existing non-empty file is kept (the server's own key wins over
// a fleet default).
func writeSecret(path, value string, overwrite bool) error {
	if !overwrite {
		if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) != "" {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.TrimSpace(value)+"\n"), 0o640); err != nil {
		return err
	}
	if g, err := user.LookupGroup("kodeblue"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		_ = os.Chown(tmp, 0, gid)
	}
	return os.Rename(tmp, path)
}

// replaceSection swaps one top-level [name] table in a TOML file for body,
// keeping everything else (comments included) as it was.
func replaceSection(path, name, body string) error {
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out []string
	skipping := false
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			skipping = t == "["+name+"]"
		}
		if !skipping {
			out = append(out, line)
		}
	}
	text := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n\n" + body
	st, err := os.Stat(path)
	mode := os.FileMode(0o640)
	if err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), mode); err != nil {
		return err
	}
	if g, err := user.LookupGroup("kodeblue"); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		_ = os.Chown(tmp, 0, gid)
	}
	return os.Rename(tmp, path)
}
