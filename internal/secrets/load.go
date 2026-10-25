package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Payload is the wire format the supervisor writes to the secrets pipe: a
// single JSON object keyed by the slot names above. Unknown keys are ignored.
type Payload map[string]string

// LoadFromReader parses a secrets payload and installs every non-empty value.
// The serialized bytes are zeroed before returning so the JSON copy does not
// linger in the heap alongside the parsed strings.
func LoadFromReader(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read secrets payload: %w", err)
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	// An empty payload is not an error: it means the supervisor had no secrets
	// to hand over (no gateway key configured yet, say).
	if len(trimSpace(raw)) == 0 {
		return nil
	}

	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("parse secrets payload: %w", err)
	}
	for name, value := range payload {
		Set(name, value)
	}
	return nil
}

// LoadFromFD reads a secrets payload from an inherited file descriptor and
// closes it. This is the production path: passing the descriptor number as an
// argument (rather than the secret itself) means no key material ever appears
// in /proc/<pid>/cmdline, not even for the instant before the argv scrub.
func LoadFromFD(fd int) error {
	if fd <= 2 {
		return fmt.Errorf("refusing to read secrets from fd %d: must be above stdio", fd)
	}
	// The supervisor writes the payload and closes its end, so ReadAll sees a
	// clean EOF; this process owns the descriptor from here on.
	f := os.NewFile(uintptr(fd), "secrets")
	if f == nil {
		return fmt.Errorf("secrets fd %d is not valid", fd)
	}
	defer f.Close()
	return LoadFromReader(f)
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
