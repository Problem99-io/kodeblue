package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type Cloudflare struct {
	APIToken     string   `toml:"api_token"`
	APITokenFile string   `toml:"api_token_file"`
	ZoneIDs      []string `toml:"zone_ids"`
}

func (c Cloudflare) Token(configPath ...string) (string, error) {
	if token := strings.TrimSpace(c.APIToken); token != "" {
		if len(configPath) != 1 {
			return "", errors.New("inline Cloudflare tokens require a protected configuration file")
		}
		f, err := openCloudflareSecret(configPath[0], true)
		if err != nil {
			return "", err
		}
		f.Close()
		return token, nil
	}
	if c.APITokenFile == "" {
		return "", nil
	}
	f, err := openCloudflareSecret(c.APITokenFile, false)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("could not read Cloudflare token file")
	}
	return strings.TrimSpace(string(data)), nil
}

func openCloudflareSecret(path string, config bool) (*os.File, error) {
	path = filepath.Clean(path)
	if !strings.HasPrefix(path, "/etc/kodeblue/") {
		return nil, errors.New("Cloudflare credentials must be under /etc/kodeblue/")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.HasPrefix(resolved, "/etc/kodeblue/") {
		return nil, errors.New("Cloudflare credentials must resolve under /etc/kodeblue/")
	}
	if !config && (forbiddenCloudflareFile(path) || forbiddenCloudflareFile(resolved)) {
		return nil, errors.New("Cloudflare requires its own token file, not another kodeblue credential")
	}
	// Read the resolved path and refuse replacement with a symlink between
	// resolution and open. Validate owner and permissions on the opened inode.
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("could not open protected Cloudflare credential file")
	}
	f := os.NewFile(uintptr(fd), resolved)
	info, err := f.Stat()
	if err != nil || !protectedCloudflareInfo(info) {
		f.Close()
		return nil, errors.New("Cloudflare credentials require a root-owned regular file with permissions 0600 or 0640")
	}
	return f, nil
}
func forbiddenCloudflareFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == "hub.key" || name == "inference.key" || name == "kodeblue.toml" || name == "telegram.token" || name == "telegram.chat" || strings.HasSuffix(name, ".webhook")
}
func protectedCloudflareInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
