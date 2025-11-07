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
// const (
// 	maxRetries = 5
// 	retryDelay = 3 * time.Second
// )

// getConnectionString returns the appropriate connection string based on environment
func getConnectionString() string {
	// Check for environment variables (try both DB_ and POSTGRES_ prefixes)
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = os.Getenv("POSTGRES_HOST")
	}

	if dbHost != "" {
		dbUser := os.Getenv("DB_USER")
		if dbUser == "" {
			dbUser = os.Getenv("POSTGRES_USER")
			if dbUser == "" {
				dbUser = "postgres"
			}
		}

		dbPassword := os.Getenv("DB_PASSWORD")
		if dbPassword == "" {
			dbPassword = os.Getenv("POSTGRES_PASSWORD")
			if dbPassword == "" {
				dbPassword = "postgres"
			}
		}

		dbName := os.Getenv("DB_NAME")
		if dbName == "" {
			dbName = os.Getenv("POSTGRES_DB")
			if dbName == "" {
				dbName = "sirius"
			}
		}

		dbPort := os.Getenv("DB_PORT")
		if dbPort == "" {
			dbPort = os.Getenv("POSTGRES_PORT")
			if dbPort == "" {
				dbPort = "5432"
			}
		}

		dbSSLMode := os.Getenv("DB_SSLMODE")
		if dbSSLMode == "" {
			dbSSLMode = os.Getenv("POSTGRES_SSLMODE")
			if dbSSLMode == "" {
				dbSSLMode = "disable"
			}
		}

		connectionString := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
			dbHost, dbUser, dbPassword, dbName, dbPort, dbSSLMode)

		log.Printf("Using environment variables for database connection: host=%s dbname=%s user=%s port=%s",
			dbHost, dbName, dbUser, dbPort)

		return connectionString
	}

	// Default to auto-detection: If we're running in a container, use the container hostname
	// otherwise use localhost
	if _, err := os.Stat("/.dockerenv"); err == nil {
		// We're in a container, use the service name
		log.Println("Detected container environment, using sirius-postgres hostname")
		return "host=sirius-postgres user=postgres password=postgres dbname=sirius port=5432 sslmode=disable"
	}

	// We're on the host, use localhost
	log.Println("Detected host environment, using localhost")
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

	if err == nil {
		// Configure connection pool to prevent leaks
		sqlDB, err := db.DB()
		if err == nil {
			// Set connection pool settings
			sqlDB.SetMaxOpenConns(25)                 // Maximum number of open connections
			sqlDB.SetMaxIdleConns(10)                 // Maximum number of idle connections
			sqlDB.SetConnMaxLifetime(5 * time.Minute) // Maximum connection lifetime
			sqlDB.SetConnMaxIdleTime(1 * time.Minute) // Maximum idle time before closing
			log.Println("✅ Database connection pool configured")
		}
	}

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
		&models.HostPort{},
		&models.Event{},
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

	// Step 5: Post-migration - Replace simple junction tables with enhanced ones
	enhanceJunctionTables()
}

// enhanceJunctionTables replaces the simple many-to-many junction tables with enhanced ones
func enhanceJunctionTables() {
	log.Println("Enhancing junction tables with source attribution...")

	// Drop the simple junction tables created by GORM
	err := db.Exec("DROP TABLE IF EXISTS host_vulnerabilities CASCADE").Error
	if err != nil {
		log.Printf("⚠️ Failed to drop simple host_vulnerabilities table: %v", err)
	}

	err = db.Exec("DROP TABLE IF EXISTS host_ports CASCADE").Error
	if err != nil {
		log.Printf("⚠️ Failed to drop simple host_ports table: %v", err)
	}

	// Create enhanced junction tables
	err = db.Exec(`
		CREATE TABLE host_vulnerabilities (
			host_id BIGINT NOT NULL,
			vulnerability_id BIGINT NOT NULL,
			source VARCHAR(255) NOT NULL DEFAULT 'unknown',
			source_version VARCHAR(255) DEFAULT '',
			first_seen TIMESTAMP DEFAULT NOW(),
			last_seen TIMESTAMP DEFAULT NOW(),
			status VARCHAR(255) DEFAULT 'active',
			confidence DECIMAL(3,2) DEFAULT 1.0,
			port INTEGER,
			service_info TEXT,
			notes TEXT,
			PRIMARY KEY (host_id, vulnerability_id, source),
			FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
			FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
		)
	`).Error
	if err != nil {
		log.Printf("⚠️ Failed to create enhanced host_vulnerabilities table: %v", err)
		return
	}

	err = db.Exec(`
		CREATE TABLE host_ports (
			host_id BIGINT NOT NULL,
			port_id BIGINT NOT NULL,
			source VARCHAR(255) NOT NULL DEFAULT 'unknown',
			source_version VARCHAR(255) DEFAULT '',
			first_seen TIMESTAMP DEFAULT NOW(),
			last_seen TIMESTAMP DEFAULT NOW(),
			status VARCHAR(255) DEFAULT 'active',
			notes TEXT,
			PRIMARY KEY (host_id, port_id, source),
			FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
			FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
		)
	`).Error
	if err != nil {
		log.Printf("⚠️ Failed to create enhanced host_ports table: %v", err)
		return
	}

	// Add indexes for performance
	indexes := []string{
		"CREATE INDEX idx_host_vulnerabilities_source ON host_vulnerabilities(source)",
		"CREATE INDEX idx_host_vulnerabilities_status ON host_vulnerabilities(status)",
		"CREATE INDEX idx_host_vulnerabilities_last_seen ON host_vulnerabilities(last_seen)",
		"CREATE INDEX idx_host_vulns_host_source ON host_vulnerabilities(host_id, source)",
		"CREATE INDEX idx_host_ports_source ON host_ports(source)",
		"CREATE INDEX idx_host_ports_status ON host_ports(status)",
		"CREATE INDEX idx_host_ports_host_source ON host_ports(host_id, source)",
	}

	for _, indexSQL := range indexes {
		err = db.Exec(indexSQL).Error
		if err != nil {
			log.Printf("⚠️ Warning: Failed to create index: %v", err)
		}
	}

	log.Println("✅ Junction tables enhanced with source attribution")
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
