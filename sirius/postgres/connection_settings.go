package postgres

import (
	"errors"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5"
)

type connectionSettings struct {
	host     string
	port     string
	database string
	user     string
	password string
	sslMode  string
}

func connectionSettingsFromEnv() connectionSettings {
	settings := connectionSettings{
		host:     databaseEnv("DB_HOST", "POSTGRES_HOST", ""),
		port:     "5432",
		database: "sirius",
		user:     "postgres",
		password: "postgres",
		sslMode:  "disable",
	}
	if settings.host == "" {
		settings.host = "localhost"
		if _, err := os.Stat("/.dockerenv"); err == nil {
			settings.host = "sirius-postgres"
		}
		return settings
	}

	settings.port = databaseEnv("DB_PORT", "POSTGRES_PORT", settings.port)
	settings.database = databaseEnv("DB_NAME", "POSTGRES_DB", settings.database)
	settings.user = databaseEnv("DB_USER", "POSTGRES_USER", settings.user)
	settings.password = databaseEnv("DB_PASSWORD", "POSTGRES_PASSWORD", settings.password)
	settings.sslMode = databaseEnv("DB_SSLMODE", "POSTGRES_SSLMODE", settings.sslMode)
	return settings
}

func databaseEnv(primary, secondary, fallback string) string {
	if value := os.Getenv(primary); value != "" {
		return value
	}
	if value := os.Getenv(secondary); value != "" {
		return value
	}
	return fallback
}

func (settings connectionSettings) pgxConfig() (*pgx.ConnConfig, error) {
	// Let pgx resolve transport settings, including socket paths and host lists.
	// Keep credentials out of both pgx and GORM connection strings.
	target := url.Values{
		"host":    {settings.host},
		"port":    {settings.port},
		"sslmode": {settings.sslMode},
	}
	config, err := pgx.ParseConfig("postgresql://?" + target.Encode())
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection settings. Check DB_HOST, DB_PORT, DB_SSLMODE, their POSTGRES_ aliases, and PG* driver settings")
	}

	config.Database = settings.database
	config.User = settings.user
	config.Password = settings.password
	return config, nil
}
