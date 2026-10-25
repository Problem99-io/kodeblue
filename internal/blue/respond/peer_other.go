//go:build !linux

package respond

import "errors"

// peerUID is only implemented on Linux, the one platform the helper runs on.
func peerUID(int) (int, error) {
	return -1, errors.New("peer credentials are not supported on this platform")
}
