package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Cloudflare struct {
	APIToken     string   `toml:"api_token"`
	APITokenFile string   `toml:"api_token_file"`
	ZoneIDs      []string `toml:"zone_ids"`
}

func (c Cloudflare) Token() (string, error) {
	if token := strings.TrimSpace(c.APIToken); token != "" {
		return token, nil
	}
	if c.APITokenFile == "" {
		return "", nil
	}
	// This directory is denied by every host inspection tool, including
	// symlink resolution. Do not allow a custom secret path the model can read.
	path := filepath.Clean(c.APITokenFile)
	if !strings.HasPrefix(path, "/etc/kodeblue/") {
		return "", errors.New("Cloudflare token files must be under /etc/kodeblue/")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.HasPrefix(resolved, "/etc/kodeblue/") {
		return "", errors.New("Cloudflare token files must resolve under /etc/kodeblue/")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("could not read Cloudflare token file")
	}
	return strings.TrimSpace(string(data)), nil
}
