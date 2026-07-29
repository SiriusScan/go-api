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
	"log/slog"
	"os"

	"github.com/SiriusScan/go-api/sirius/migrate"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	slog.Info("Starting core schema migrations")
	if err := migrate.UpFromDefault(); err != nil {
		slog.Error("Migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("All core migrations applied successfully")
}
