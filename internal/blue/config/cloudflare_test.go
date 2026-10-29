package config

import (
	"os"
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
		if protectedCloudflareInfo(cfInfo{tc.mode, tc.uid}) != tc.ok {
			t.Errorf("mode=%v uid=%d", tc.mode, tc.uid)
		}
	}
}
