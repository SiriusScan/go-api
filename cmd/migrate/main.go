// Command migrate applies forward-only core schema migrations
// (schema_migrations_core ledger).
//
// Usage:
//
//	DB_HOST=sirius-postgres DB_USER=postgres DB_PASSWORD=... DB_NAME=sirius \
//	  go run ./cmd/migrate
//
// Or run the compiled binary shipped in production images.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SiriusScan/go-api/sirius/migrate"
)

func main() {
	timeout := flag.Duration("timeout", 10*time.Minute, "maximum time to apply core migrations")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if *timeout <= 0 {
		slog.Error("Migration timeout must be positive", "timeout", *timeout)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	slog.Info("Starting core schema migrations")
	if err := migrate.UpFromDefaultContext(ctx); err != nil {
		slog.Error("Migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("All core migrations applied successfully")
}
