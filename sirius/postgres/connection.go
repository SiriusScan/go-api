// File: connection.go
package postgres

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database connection variables
var (
	db              *gorm.DB
	isInitialized   bool
	connectionError error
)

// init initializes the database connection
func init() {
	// Set up a connection to the database
	slog.Info("Initializing PostgreSQL database connection...")

	// Connect with retries
	connectWithRetries()
}

// connectWithRetries attempts to connect to the database with exponential backoff
func connectWithRetries() {
	// Initial connection attempt
	connect()

	// If connection failed, log the error but allow the application to continue
	if connectionError != nil {
		slog.Warn("Initial database connection failed", "error", connectionError)
		slog.Info("Application will continue without database functionality")
		slog.Info("Database operations will be retried automatically")
	}
}

// connect attempts to establish a connection to the database
func connect() {
	// Configure custom logger to avoid excessive logging
	newLogger := logger.New(
		log.New(log.Writer(), "[DB] ", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	settings := connectionSettingsFromEnv()
	slog.Info("Connecting to PostgreSQL database", "host", settings.host, "port", settings.port,
		"dbname", settings.database, "sslmode", settings.sslMode)
	conn, err := openConnection(settings, newLogger)
	db = conn
	if err != nil {
		connectionError = err
		isInitialized = false
		return
	}

	// Connection succeeded, initialize schema
	slog.Info("PostgreSQL database connection established")
	isInitialized = true
	connectionError = nil

	// Initialize database schema
	initializeSchema()
}

func openConnection(settings connectionSettings, dbLogger logger.Interface) (*gorm.DB, error) {
	config, err := settings.pgxConfig()
	if err != nil {
		return nil, err
	}

	sqlDB := stdlib.OpenDB(*config)
	// GORM logs failed startup pings verbatim. Use the normal logger once the pool is ready.
	conn, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		Logger: dbLogger.LogMode(logger.Silent),
	})
	if err != nil {
		_ = sqlDB.Close()
		return nil, connectionFailure(err)
	}
	conn.Logger = dbLogger
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(time.Minute)
	slog.Info("Database connection pool configured")
	return conn, nil
}

// connectionFailure translates driver errors into diagnostics safe for startup logs.
func connectionFailure(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "28000", "28P01":
			return errors.New("PostgreSQL rejected authentication. Check the configured role, password and server authentication rules")
		case "3D000":
			return errors.New("PostgreSQL database does not exist. Check DB_NAME or POSTGRES_DB")
		}
	}

	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return errors.New("could not resolve the PostgreSQL host. Check DB_HOST or POSTGRES_HOST and DNS")
	case errors.Is(err, syscall.ECONNREFUSED):
		return errors.New("PostgreSQL refused the connection. Check the server is listening on the configured host and port")
	case pgconn.Timeout(err):
		return errors.New("PostgreSQL connection timed out. Check network access and server availability")
	default:
		return errors.New("failed to connect to PostgreSQL. Check server availability, host, port and TLS settings")
	}
}

// initializeSchema optionally applies GORM AutoMigrate on connect.
// Production schema changes must go through sirius/migrate (schema_migrations_core).
// Set SIRIUS_SCHEMA_AUTO_MIGRATE=true for local/dev convenience only.
// Set SIRIUS_SCHEMA_FORCE_RESET=true to drop all tables before AutoMigrate (tests only).
func initializeSchema() {
	if strings.TrimSpace(os.Getenv("SIRIUS_SCHEMA_MODE")) == "verify" {
		slog.Info("Skipping schema AutoMigrate in verify mode")
		return
	}
	autoMigrate := os.Getenv("SIRIUS_SCHEMA_AUTO_MIGRATE") == "true"
	forceReset := os.Getenv("SIRIUS_SCHEMA_FORCE_RESET") == "true"

	if !autoMigrate {
		slog.Info("Skipping schema AutoMigrate on connect; use go-api migrate command for schema changes")
		return
	}

	slog.Info("Initializing database schema via AutoMigrate (SIRIUS_SCHEMA_AUTO_MIGRATE=true)")

	if forceReset {
		slog.Warn("SIRIUS_SCHEMA_FORCE_RESET=true: dropping all tables before AutoMigrate")
		dropTablesInOrder()
	}

	if err := migrateSchema(db); err != nil {
		slog.Error("Database schema AutoMigrate failed", "error", err)
		return
	}
	slog.Info("Database schema AutoMigrate completed")
}

// dropTablesInOrder drops all tables in the correct order to avoid foreign key constraint errors
func dropTablesInOrder() {
	slog.Debug("Dropping existing tables...")

	// First drop junction tables to avoid foreign key constraints
	junctionTables := []string{
		"host_vulnerabilities",
		"host_ports",
		"services",
		"notes",
		"cpes",
		"users",
	}

	for _, table := range junctionTables {
		db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", table))
	}

	// Then drop main tables
	mainTables := []string{
		"ports",
		"vulnerabilities",
		"hosts",
		"agents",
	}

	for _, table := range mainTables {
		db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", table))
	}

	// Special handling for 'references' which is a reserved keyword in PostgreSQL
	db.Exec(`DROP TABLE IF EXISTS "references" CASCADE`)

	// Finally drop auxiliary tables
	auxTables := []string{
		"base_metric_v2",
		"configurations",
		"cpe_matches",
		"cve_data",
		"cve_data_meta",
		"cve_items",
		"impacts",
		"nodes",
		"problem_type_data",
		"problem_types",
		"descriptions",
	}

	for _, table := range auxTables {
		db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", table))
	}

	slog.Debug("All tables dropped successfully")
}

// migrateSchema creates all tables in the correct order (additive only).
func migrateSchema(conn *gorm.DB) error {
	if conn == nil {
		return fmt.Errorf("database connection is nil")
	}
	slog.Debug("Migrating schema...")

	if err := conn.AutoMigrate(&models.Agent{}); err != nil {
		return fmt.Errorf("base tables: %w", err)
	}

	if err := conn.AutoMigrate(
		&models.Host{},
		&models.Port{},
		&models.Vulnerability{},
	); err != nil {
		return fmt.Errorf("entity tables: %w", err)
	}

	if err := conn.AutoMigrate(
		&models.Service{},
		&models.User{},
		&models.Note{},
		&models.CPE{},
		&models.HostVulnerability{},
		&models.HostPort{},
		&models.Event{},
		&models.ScanHistoryEntry{},
	); err != nil {
		return fmt.Errorf("relationship tables: %w", err)
	}

	if err := conn.AutoMigrate(
		&models.CVEData{},
		&models.CVEItem{},
		&models.CVEDataMeta{},
		&models.ProblemType{},
		&models.ProblemTypeData{},
		&models.Reference{},
		&models.Configurations{},
		&models.Node{},
		&models.CpeMatch{},
		&models.Impact{},
		&models.BaseMetricV2{},
	); err != nil {
		return fmt.Errorf("CVE tables: %w", err)
	}

	// Enhanced junction tables (source attribution) are owned by the
	// schema_migrations_core migrator (steps 002/003). Do not DROP/recreate here.
	return nil
}

// AutoMigrateSchema runs GORM AutoMigrate for core models without dropping tables.
// Used by the ledger migrator baseline step and by SIRIUS_SCHEMA_AUTO_MIGRATE.
func AutoMigrateSchema() error {
	return AutoMigrateSchemaDB(db)
}

// AutoMigrateSchemaDB runs GORM AutoMigrate against the provided connection.
func AutoMigrateSchemaDB(conn *gorm.DB) error {
	return migrateSchema(conn)
}

// GetDB returns the database connection, initializing it if necessary
func GetDB() *gorm.DB {
	// If connection is already established, return it
	if isInitialized && db != nil {
		return db
	}

	// If we haven't tried to connect yet or connection failed
	if connectionError != nil {
		// Attempt to reconnect
		slog.Debug("Attempting to reconnect to PostgreSQL database...")
		connect()

		// If reconnection succeeded, return the connection
		if isInitialized && db != nil {
			return db
		}

		// If reconnection failed, log the error
		slog.Warn("Database reconnection failed", "error", connectionError)
		return nil
	}

	// Should never reach here, but just in case
	return nil
}

// IsConnected returns whether the database is connected
func IsConnected() bool {
	return isInitialized && db != nil
}

// GetConnectionError returns the last connection error
func GetConnectionError() error {
	return connectionError
}
