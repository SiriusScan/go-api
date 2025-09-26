package main

import (
	"log"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func main() {
	db := postgres.GetDB()

	log.Println("Starting migration to add source attribution to junction tables...")

	// 1. Create backups of existing junction table data
	log.Println("Creating backups of existing junction table data...")

	type HostVulnBackup struct {
		ID              uint      `gorm:"primaryKey"`
		HostID          uint      `json:"host_id"`
		VulnerabilityID uint      `json:"vulnerability_id"`
		CreatedAt       time.Time `json:"created_at"`
		UpdatedAt       time.Time `json:"updated_at"`
	}

	type HostPortBackup struct {
		ID        uint      `gorm:"primaryKey"`
		HostID    uint      `json:"host_id"`
		PortID    uint      `json:"port_id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	var vulnBackups []HostVulnBackup
	err := db.Table("host_vulnerabilities").Find(&vulnBackups).Error
	if err != nil {
		log.Fatalf("Failed to backup host_vulnerabilities: %v", err)
	}

	var portBackups []HostPortBackup
	err = db.Table("host_ports").Find(&portBackups).Error
	if err != nil {
		log.Fatalf("Failed to backup host_ports: %v", err)
	}

	log.Printf("Backed up %d vulnerability relationships and %d port relationships",
		len(vulnBackups), len(portBackups))

	// 2. Add new columns to host_vulnerabilities table
	log.Println("Adding source attribution columns to host_vulnerabilities...")

	// Add source columns
	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS source VARCHAR(255) DEFAULT 'unknown'").Error
	if err != nil {
		log.Fatalf("Failed to add source column: %v", err)
	}

	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS source_version VARCHAR(255) DEFAULT ''").Error
	if err != nil {
		log.Fatalf("Failed to add source_version column: %v", err)
	}

	// Add temporal tracking columns
	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW()").Error
	if err != nil {
		log.Fatalf("Failed to add first_seen column: %v", err)
	}

	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()").Error
	if err != nil {
		log.Fatalf("Failed to add last_seen column: %v", err)
	}

	// Add status and confidence columns
	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS status VARCHAR(255) DEFAULT 'active'").Error
	if err != nil {
		log.Fatalf("Failed to add status column: %v", err)
	}

	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS confidence DECIMAL(3,2) DEFAULT 1.0").Error
	if err != nil {
		log.Fatalf("Failed to add confidence column: %v", err)
	}

	// Add optional columns
	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS port INTEGER").Error
	if err != nil {
		log.Fatalf("Failed to add port column: %v", err)
	}

	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS service_info TEXT").Error
	if err != nil {
		log.Fatalf("Failed to add service_info column: %v", err)
	}

	err = db.Exec("ALTER TABLE host_vulnerabilities ADD COLUMN IF NOT EXISTS notes TEXT").Error
	if err != nil {
		log.Fatalf("Failed to add notes column: %v", err)
	}

	// 3. Add new columns to host_ports table
	log.Println("Adding source attribution columns to host_ports...")

	err = db.Exec("ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS source VARCHAR(255) DEFAULT 'unknown'").Error
	if err != nil {
		log.Fatalf("Failed to add source column to host_ports: %v", err)
	}

	err = db.Exec("ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS source_version VARCHAR(255) DEFAULT ''").Error
	if err != nil {
		log.Fatalf("Failed to add source_version column to host_ports: %v", err)
	}

	err = db.Exec("ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW()").Error
	if err != nil {
		log.Fatalf("Failed to add first_seen column to host_ports: %v", err)
	}

	err = db.Exec("ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()").Error
	if err != nil {
		log.Fatalf("Failed to add last_seen column to host_ports: %v", err)
	}

	err = db.Exec("ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS status VARCHAR(255) DEFAULT 'active'").Error
	if err != nil {
		log.Fatalf("Failed to add status column to host_ports: %v", err)
	}

	err = db.Exec("ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS notes TEXT").Error
	if err != nil {
		log.Fatalf("Failed to add notes column to host_ports: %v", err)
	}

	// 4. Update existing records with default values and proper timestamps
	log.Println("Updating existing records with default source attribution...")

	// Update vulnerability records
	err = db.Exec(`
		UPDATE host_vulnerabilities 
		SET 
			source = 'unknown',
			source_version = 'legacy',
			first_seen = NOW(),
			last_seen = NOW(),
			status = 'active',
			confidence = 1.0
		WHERE source IS NULL OR source = ''
	`).Error
	if err != nil {
		log.Fatalf("Failed to update vulnerability records: %v", err)
	}

	// Update port records
	err = db.Exec(`
		UPDATE host_ports 
		SET 
			source = 'unknown',
			source_version = 'legacy',
			first_seen = NOW(),
			last_seen = NOW(),
			status = 'active'
		WHERE source IS NULL OR source = ''
	`).Error
	if err != nil {
		log.Fatalf("Failed to update port records: %v", err)
	}

	// 5. Create scan_history_entries table for tracking scan timeline
	log.Println("Creating scan_history_entries table...")

	err = db.AutoMigrate(&models.ScanHistoryEntry{})
	if err != nil {
		log.Fatalf("Failed to create scan_history_entries table: %v", err)
	}

	// 6. Add indexes for performance
	log.Println("Adding indexes for improved query performance...")

	// Indexes for host_vulnerabilities
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_source ON host_vulnerabilities(source)").Error
	if err != nil {
		log.Printf("Warning: Failed to create index on source: %v", err)
	}

	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_status ON host_vulnerabilities(status)").Error
	if err != nil {
		log.Printf("Warning: Failed to create index on status: %v", err)
	}

	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_last_seen ON host_vulnerabilities(last_seen)").Error
	if err != nil {
		log.Printf("Warning: Failed to create index on last_seen: %v", err)
	}

	// Indexes for host_ports
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_ports_source ON host_ports(source)").Error
	if err != nil {
		log.Printf("Warning: Failed to create index on host_ports source: %v", err)
	}

	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_ports_status ON host_ports(status)").Error
	if err != nil {
		log.Printf("Warning: Failed to create index on host_ports status: %v", err)
	}

	// Compound indexes for common queries
	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_vulns_host_source ON host_vulnerabilities(host_id, source)").Error
	if err != nil {
		log.Printf("Warning: Failed to create compound index on host_vulnerabilities: %v", err)
	}

	err = db.Exec("CREATE INDEX IF NOT EXISTS idx_host_ports_host_source ON host_ports(host_id, source)").Error
	if err != nil {
		log.Printf("Warning: Failed to create compound index on host_ports: %v", err)
	}

	// 7. Verify the migration
	log.Println("Verifying migration results...")

	var vulnCount, portCount int64
	db.Table("host_vulnerabilities").Count(&vulnCount)
	db.Table("host_ports").Count(&portCount)

	log.Printf("Migration completed successfully!")
	log.Printf("Results:")
	log.Printf("  - host_vulnerabilities: %d records migrated", vulnCount)
	log.Printf("  - host_ports: %d records migrated", portCount)
	log.Printf("  - All existing data preserved with 'unknown' source attribution")
	log.Printf("  - Performance indexes created")
	log.Printf("  - scan_history_entries table created")

	log.Println("Migration 002_add_source_attribution completed!")
}
 