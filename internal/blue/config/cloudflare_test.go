package config

import (
	"strings"
	"testing"
)

func TestCloudflareTokenCannotUseInspectablePath(t *testing.T) {
	for _, path := range []string{"/tmp/public-token", "/etc/kodeblue/../../tmp/token"} {
		if _, err := (Cloudflare{APITokenFile: path}).Token(); err == nil {
			t.Fatalf("accepted inspectable token path %s", path)
		}
	}
	token, err := (Cloudflare{APIToken: "  synthetic-token  "}).Token()
	if err != nil || strings.TrimSpace(token) != "synthetic-token" {
		t.Fatal("inline root config token unavailable")
	}
}
