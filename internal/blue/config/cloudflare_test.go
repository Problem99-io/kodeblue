package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestCloudflareTokenCannotUseInspectablePath(t *testing.T) {
	for _, path := range []string{"/tmp/public-token", "/etc/kodeblue/../../tmp/token"} {
		if _, err := (Cloudflare{APITokenFile: path}).Token(); err == nil {
			t.Fatalf("accepted inspectable token path %s", path)
		}
	}
	if _, err := (Cloudflare{APIToken: "synthetic-token"}).Token("/tmp/config.toml"); err == nil {
		t.Fatal("accepted inspectable inline token")
	}
}

type cfInfo struct {
	mode os.FileMode
	uid  uint32
}

func (i cfInfo) Name() string       { return "token" }
func (i cfInfo) Size() int64        { return 30 }
func (i cfInfo) Mode() os.FileMode  { return i.mode }
func (i cfInfo) ModTime() time.Time { return time.Time{} }
func (i cfInfo) IsDir() bool        { return false }
func (i cfInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }
func TestCloudflareFileProtection(t *testing.T) {
	for _, name := range []string{"hub.key", "inference.key", "kodeblue.toml", "slack.webhook", "telegram.token"} {
		if !forbiddenCloudflareFile("/etc/kodeblue/" + name) {
			t.Errorf("allowed shared credential %s", name)
		}
	}
	for _, tc := range []struct {
		mode os.FileMode
		uid  uint32
		ok   bool
	}{{0640, 0, true}, {0600, 0, true}, {0644, 0, false}, {0660, 0, false}, {0600, 1000, false}, {os.ModeNamedPipe | 0600, 0, false}} {
		if protectedCloudflareInfo(cfInfo{tc.mode, tc.uid}, 0) != tc.ok {
			t.Errorf("mode=%v uid=%d", tc.mode, tc.uid)
		}
	}
}

func TestAgentCommandsRefuseInspectableInlineCloudflareToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kodeblue.toml")
	if err := os.WriteFile(path, []byte(`[cloudflare]
api_token = "synthetic-cloudflare-secret-token"
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("optional integration disabled administrative commands: %v", err)
	}
	if cfg.ValidateAgentCredentials() == nil {
		t.Fatal("agent commands accepted an inspectable token")
	}
}

func TestCloudflareRealProtectedFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for actual credential ownership checks")
	}
	group, err := user.LookupGroup("kodeblue")
	if err != nil {
		t.Skip("requires kodeblue group")
	}
	gid, _ := strconv.Atoi(group.Gid)
	if err := os.MkdirAll("/etc/kodeblue", 0750); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/etc/kodeblue", "cloudflare-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	tokenPath := filepath.Join(dir, "cloudflare.token")
	token := "synthetic-cloudflare-test-token"
	if err := os.WriteFile(tokenPath, []byte(token), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(tokenPath, 0, gid); err != nil {
		t.Fatal(err)
	}
	if got, err := (Cloudflare{APITokenFile: tokenPath}).Token(); err != nil || got != token {
		t.Fatalf("valid token file: %q %v", got, err)
	}
	cfgPath := filepath.Join(dir, "kodeblue.toml")
	_ = os.WriteFile(cfgPath, []byte("[cloudflare]\napi_token = "+strconv.Quote(token)), 0640)
	_ = os.Chown(cfgPath, 0, gid)
	cfg, err := Load(cfgPath)
	if err != nil || cfg.ValidateAgentCredentials() != nil {
		t.Fatalf("valid inline config: %v", err)
	}
	_ = os.Chmod(tokenPath, 0644)
	if _, err := (Cloudflare{APITokenFile: tokenPath}).Token(); err == nil {
		t.Fatal("world-readable token accepted")
	}
	_ = os.Chmod(tokenPath, 0640)
	_ = os.Chown(tokenPath, 0, gid+1)
	if _, err := (Cloudflare{APITokenFile: tokenPath}).Token(); err == nil {
		t.Fatal("wrong group accepted")
	}
}
