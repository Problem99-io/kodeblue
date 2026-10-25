// Package buildinfo exposes facts compiled into the engine binary. Release
// builds set them with -ldflags; local builds report "dev"/"unknown".
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"sync"
)

var (
	Version    = "dev"
	Commit     = "unknown"
	SourceHash = "unknown"
	BuildTime  = "unknown"
)

type Info struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	SourceHash   string `json:"source_hash"`
	BuildTime    string `json:"build_time"`
	BinarySHA256 string `json:"binary_sha256"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
}

var binaryHash = sync.OnceValue(func() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
})

func Current() Info {
	return Info{Version: Version, Commit: Commit, SourceHash: SourceHash, BuildTime: BuildTime, BinarySHA256: binaryHash(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}
