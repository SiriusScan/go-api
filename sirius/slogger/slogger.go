// Package slogger provides a shared LOG_LEVEL-aware slog initialization helper.
//
// Call Init() at the start of any service's main() to configure the global
// slog logger based on the LOG_LEVEL environment variable. This also bridges
// legacy log.Print* calls through slog (Go 1.22+ behaviour via slog.SetDefault).
//
// Valid LOG_LEVEL values: "debug", "info", "warn", "error".
// Default: "info".
package slogger

import (
	"log/slog"
	"os"
	"strings"
)

// level holds the dynamic log level so it can be queried at runtime.
var level *slog.LevelVar

// Init reads the LOG_LEVEL environment variable, configures a global slog
// TextHandler on stdout, and sets it as the default logger. Legacy log.Print*
// calls are automatically routed through this handler (Go 1.22+).
func Init() {
	level = &slog.LevelVar{}
	level.Set(parseLevel(os.Getenv("LOG_LEVEL")))

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// Level returns the current slog.Level. Useful for conditional logic such as
// skipping expensive debug formatting when not in debug mode.
func Level() slog.Level {
	if level == nil {
		return slog.LevelInfo
	}
	return level.Level()
}

// IsDebug returns true when the current log level is debug or lower.
func IsDebug() bool {
	return Level() <= slog.LevelDebug
}

// parseLevel converts a string log level to slog.Level.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
