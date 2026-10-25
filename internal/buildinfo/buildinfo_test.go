package buildinfo

import (
	"encoding/hex"
	"runtime"
	"testing"
)

func TestCurrentReportsExecutableAndPlatformIdentity(t *testing.T) {
	info := Current()
	if info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH {
		t.Fatalf("platform = %s/%s, want %s/%s", info.GOOS, info.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if len(info.BinarySHA256) != 64 {
		t.Fatalf("binary SHA-256 length = %d, want 64 (%q)", len(info.BinarySHA256), info.BinarySHA256)
	}
	if _, err := hex.DecodeString(info.BinarySHA256); err != nil {
		t.Fatalf("binary SHA-256 is not hexadecimal: %q: %v", info.BinarySHA256, err)
	}
}
