package logging

import (
	"log/slog"
	"os"
)

// Logger wraps slog.Logger for structured logging.
type Logger struct {
	*slog.Logger
}

// NewLogger creates a structured logger at the given level.
// If pretty is true, uses a text handler; otherwise uses JSON.
func NewLogger(level slog.Level, pretty bool) *Logger {
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if pretty {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	return &Logger{Logger: slog.New(handler)}
}

// SetDefault sets this logger as the default slog logger.
func SetDefault(l *Logger) {
	slog.SetDefault(l.Logger)
}
