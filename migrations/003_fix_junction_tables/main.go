package main

import (
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres"
)

func main() {
	log.Println("Starting migration to fix junction table primary keys...")

	// Initialize database connection
	db := postgres.GetDB()

	// Drop and recreate junction tables with correct structure
	log.Println("Dropping existing junction tables...")

	err := db.Exec("DROP TABLE IF EXISTS host_vulnerabilities CASCADE").Error
	if err != nil {
		log.Fatalf("Failed to drop host_vulnerabilities table: %v", err)
	}

	err = db.Exec("DROP TABLE IF EXISTS host_ports CASCADE").Error
	if err != nil {
		log.Fatalf("Failed to drop host_ports table: %v", err)
	}

	log.Println("Recreating junction tables with correct structure...")

	// Recreate host_vulnerabilities table
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
		log.Fatalf("Failed to create host_vulnerabilities table: %v", err)
	}

	// Recreate host_ports table
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
		log.Fatalf("Failed to create host_ports table: %v", err)
	}

	// Add indexes for performance
	log.Println("Adding indexes for improved query performance...")

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
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	log.Println("Migration completed successfully!")
	log.Println("Junction tables recreated with correct primary key structure:")
	log.Println("  - host_vulnerabilities: PRIMARY KEY (host_id, vulnerability_id, source)")
	log.Println("  - host_ports: PRIMARY KEY (host_id, port_id, source)")
	log.Println("  - Performance indexes created")
}
