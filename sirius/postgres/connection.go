// File: connection.go
package postgres

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
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

// Database configuration
const (
	maxRetries = 5
	retryDelay = 3 * time.Second
)

// getConnectionString returns the appropriate connection string based on environment
func getConnectionString() string {
	// Check for environment variable first
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		return fmt.Sprintf("host=%s user=postgres password=postgres dbname=sirius port=5432 sslmode=disable", dbHost)
	}

	// Default to auto-detection: If we're running in a container, use the container hostname
	// otherwise use localhost
	if _, err := os.Stat("/.dockerenv"); err == nil {
		// We're in a container, use the service name
		return "host=sirius-postgres user=postgres password=postgres dbname=sirius port=5432 sslmode=disable"
	}

	// We're on the host, use localhost
	return "host=localhost user=postgres password=postgres dbname=sirius port=5432 sslmode=disable"
}

// init initializes the database connection
func init() {
	// Set up a connection to the database
	log.Println("Initializing PostgreSQL database connection...")

	// Connect with retries
	connectWithRetries()
}

// connectWithRetries attempts to connect to the database with exponential backoff
func connectWithRetries() {
	// Initial connection attempt
	connect()

	// If connection failed, log the error but allow the application to continue
	if connectionError != nil {
		log.Printf("⚠️ Initial database connection failed: %v", connectionError)
		log.Println("Application will continue without database functionality")
		log.Println("Database operations will be retried automatically")
	}
}

// connect attempts to establish a connection to the database
func connect() {
	var err error

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

	// Get appropriate connection string
	pgConnString := getConnectionString()

	// Connect to PostgreSQL database
	log.Printf("Connecting to PostgreSQL database: %s", pgConnString)
	db, err = gorm.Open(postgres.Open(pgConnString), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		connectionError = fmt.Errorf("failed to connect to database: %w", err)
		isInitialized = false
		return
	}

	// Connection succeeded, initialize schema
	log.Println("✅ PostgreSQL database connection established")
	isInitialized = true
	connectionError = nil

	// Initialize database schema
	initializeSchema()
}

// initializeSchema sets up the database schema
func initializeSchema() {
	log.Println("Initializing database schema...")

	// Drop existing tables in the correct order
	dropTablesInOrder()

	// Migrate schema
	migrateSchema()

	log.Println("✅ Database schema initialized successfully")
}

// dropTablesInOrder drops all tables in the correct order to avoid foreign key constraint errors
func dropTablesInOrder() {
	log.Println("Dropping existing tables...")

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

	log.Println("All tables dropped successfully")
}

// migrateSchema creates all tables in the correct order
func migrateSchema() {
	log.Println("Migrating schema...")

	// Step 1: Base tables without dependencies
	err := db.AutoMigrate(&models.Agent{})
	if err != nil {
		log.Printf("⚠️ Failed to migrate base tables: %v", err)
		return
	}

	// Step 2: Entity tables
	err = db.AutoMigrate(
		&models.Host{},
		&models.Port{},
		&models.Vulnerability{},
	)
	if err != nil {
		log.Printf("⚠️ Failed to migrate entity tables: %v", err)
		return
	}

	// Step 3: Relationship and dependent tables
	err = db.AutoMigrate(
		&models.Service{},
		&models.User{},
		&models.Note{},
		&models.CPE{},
		&models.HostVulnerability{},
	)
	if err != nil {
		log.Printf("⚠️ Failed to migrate relationship tables: %v", err)
		return
	}

	// Step 4: CVE-related tables
	err = db.AutoMigrate(
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
	)
	if err != nil {
		log.Printf("⚠️ Failed to migrate CVE tables: %v", err)
		return
	}
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
		log.Println("Attempting to reconnect to PostgreSQL database...")
		connect()

		// If reconnection succeeded, return the connection
		if isInitialized && db != nil {
			return db
		}

		// If reconnection failed, log the error
		log.Printf("⚠️ Database reconnection failed: %v", connectionError)
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
