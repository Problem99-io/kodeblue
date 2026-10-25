//go:build !linux

package reqtap

import (
	"context"
	"errors"
)

// Run is Linux-only.
func Run(ctx context.Context, rec *Recorder, onPorts func([]uint16)) error {
	return errors.New("the request tap needs Linux")
}
