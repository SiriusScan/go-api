package postgres

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm/logger"
)

func TestConnectionConfigPreservesLiteralCredentials(t *testing.T) {
	t.Setenv("DB_HOST", "db.example.test")
	t.Setenv("POSTGRES_HOST", "unused.example.test")
	t.Setenv("DB_PORT", "5440")
	t.Setenv("DB_NAME", "fixture database")
	t.Setenv("DB_USER", "fixture role /%'\\")
	t.Setenv("DB_SSLMODE", "require")
	t.Setenv("PGCONNECT_TIMEOUT", "2")
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGTARGETSESSIONATTRS", "")
	t.Setenv("PGSSLROOTCERT", "")
	t.Setenv("PGSSLCERT", "")
	t.Setenv("PGSSLKEY", "")

	tests := []struct {
		name     string
		primary  string
		fallback string
		want     string
	}{
		{name: "plain", primary: "fixture", want: "fixture"},
		{name: "spaces", primary: "with spaces", want: "with spaces"},
		{name: "apostrophe", primary: "'apostrophe", want: "'apostrophe"},
		{name: "slash", primary: "slash/end", want: "slash/end"},
		{name: "percent", primary: "percent%end", want: "percent%end"},
		{name: "backslash", primary: "back\\slash\\", want: "back\\slash\\"},
		{name: "whitespace boundaries", primary: " \t boundaries \r\n ", want: " \t boundaries \r\n "},
		{name: "combined punctuation", primary: "\\' /% TimeZone=UTC \\", want: "\\' /% TimeZone=UTC \\"},
		{name: "override", primary: "explicit override", fallback: "other value", want: "explicit override"},
		{name: "whitespace override", primary: " \t", fallback: "other value", want: " \t"},
		{name: "legacy fallback", fallback: "legacy /%'\\", want: "legacy /%'\\"},
		{name: "default", want: "postgres"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DB_PASSWORD", test.primary)
			t.Setenv("POSTGRES_PASSWORD", test.fallback)

			config, err := connectionSettingsFromEnv().pgxConfig()
			if err != nil {
				t.Fatal("could not build the synthetic pgx configuration")
			}
			if config.Password != test.want || config.User != "fixture role /%'\\" {
				t.Fatal("pgx received different credential bytes")
			}
			if config.ConnString() != "postgresql://?host=db.example.test&port=5440&sslmode=require" {
				t.Fatal("pgx connection string contains more than the transport settings")
			}
			if config.Host != "db.example.test" || config.Port != 5440 ||
				config.Database != "fixture database" || config.TLSConfig == nil ||
				config.ConnectTimeout != 2*time.Second {
				t.Fatal("pgx received different connection settings")
			}
		})
	}
}

func TestConnectionConfigPreservesSocketAndFallbackHosts(t *testing.T) {
	t.Setenv("DB_HOST", "")
	t.Setenv("POSTGRES_HOST", "/tmp/pg sockets,backup.example.test")
	t.Setenv("DB_PORT", "")
	t.Setenv("POSTGRES_PORT", "5438,5439")
	t.Setenv("DB_SSLMODE", "")
	t.Setenv("POSTGRES_SSLMODE", "disable")
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGCONNECT_TIMEOUT", "")
	t.Setenv("PGTARGETSESSIONATTRS", "")

	config, err := connectionSettingsFromEnv().pgxConfig()
	if err != nil {
		t.Fatal("could not build the synthetic pgx configuration")
	}
	if config.Host != "/tmp/pg sockets" || config.Port != 5438 || config.TLSConfig != nil {
		t.Fatal("pgx received different primary host settings")
	}
	if len(config.Fallbacks) != 1 || config.Fallbacks[0].Host != "backup.example.test" ||
		config.Fallbacks[0].Port != 5439 || config.Fallbacks[0].TLSConfig != nil {
		t.Fatal("pgx received different fallback host settings")
	}
}

func TestConnectionConfigSanitizesStartupErrors(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGCONNECT_TIMEOUT", "1")
	t.Setenv("PGTARGETSESSIONATTRS", "")

	const fixture = "synthetic /% ' \\"
	var output bytes.Buffer
	dbLogger := logger.New(log.New(&output, "", 0), logger.Config{LogLevel: logger.Warn})
	settings := connectionSettings{
		host:     t.TempDir(), // A Unix socket lookup requires no network or database.
		port:     "invalid-port",
		database: "fixture",
		user:     "fixture",
		password: fixture,
		sslMode:  "disable",
	}
	if _, err := openConnection(settings, dbLogger); err == nil || !strings.Contains(err.Error(), "DB_PORT") ||
		strings.Contains(err.Error(), fixture) || strings.Contains(err.Error(), "invalid-port") {
		t.Fatal("invalid configuration did not return a sanitized configuration diagnostic")
	}

	settings.port = "5432"
	if _, err := openConnection(settings, dbLogger); err == nil || !strings.Contains(err.Error(), "failed to connect") ||
		strings.Contains(err.Error(), fixture) || strings.Contains(err.Error(), settings.host) {
		t.Fatal("failed connection did not return a sanitized connection diagnostic")
	}
	if output.Len() != 0 {
		t.Fatal("GORM logged a startup failure directly")
	}

	err := connectionFailure(&pgconn.PgError{Code: "28P01", Message: fixture})
	if !strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), fixture) {
		t.Fatal("authentication error did not return a sanitized authentication diagnostic")
	}
}
