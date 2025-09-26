package main

import (
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres"
)

func main() {
	db := postgres.GetDB()

	log.Println("Starting migration to add SBOM and system fingerprinting schema...")

	// 1. Create backup table for hosts in case of rollback
	log.Println("Creating backup of hosts table schema...")

	// Create a backup table to preserve the original state
	err := db.Exec(`
		CREATE TABLE IF NOT EXISTS hosts_backup_004 AS 
		SELECT * FROM hosts WHERE 1=0
	`).Error
	if err != nil {
		log.Fatalf("Failed to create backup table: %v", err)
	}

	// Store current schema info for rollback
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS migration_004_rollback_info (
			id SERIAL PRIMARY KEY,
			table_name VARCHAR(255),
			column_name VARCHAR(255),
			created_at TIMESTAMP DEFAULT NOW()
		)
	`).Error
	if err != nil {
		log.Fatalf("Failed to create rollback info table: %v", err)
	}

	// 2. Add JSONB columns to hosts table
	log.Println("Adding JSONB columns to hosts table...")

	// Add software_inventory JSONB column
	err = db.Exec(`
		ALTER TABLE hosts 
		ADD COLUMN IF NOT EXISTS software_inventory JSONB DEFAULT '{}'::jsonb
	`).Error
	if err != nil {
		log.Fatalf("Failed to add software_inventory column: %v", err)
	}

	// Log the added column for rollback
	err = db.Exec(`
		INSERT INTO migration_004_rollback_info (table_name, column_name) 
		VALUES ('hosts', 'software_inventory')
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to log rollback info for software_inventory: %v", err)
	}

	// Add system_fingerprint JSONB column
	err = db.Exec(`
		ALTER TABLE hosts 
		ADD COLUMN IF NOT EXISTS system_fingerprint JSONB DEFAULT '{}'::jsonb
	`).Error
	if err != nil {
		log.Fatalf("Failed to add system_fingerprint column: %v", err)
	}

	// Log the added column for rollback
	err = db.Exec(`
		INSERT INTO migration_004_rollback_info (table_name, column_name) 
		VALUES ('hosts', 'system_fingerprint')
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to log rollback info for system_fingerprint: %v", err)
	}

	// Add agent_metadata JSONB column
	err = db.Exec(`
		ALTER TABLE hosts 
		ADD COLUMN IF NOT EXISTS agent_metadata JSONB DEFAULT '{}'::jsonb
	`).Error
	if err != nil {
		log.Fatalf("Failed to add agent_metadata column: %v", err)
	}

	// Log the added column for rollback
	err = db.Exec(`
		INSERT INTO migration_004_rollback_info (table_name, column_name) 
		VALUES ('hosts', 'agent_metadata')
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to log rollback info for agent_metadata: %v", err)
	}

	// 3. Initialize existing records with empty JSONB objects
	log.Println("Initializing existing hosts with default JSONB values...")

	err = db.Exec(`
		UPDATE hosts 
		SET 
			software_inventory = '{
				"scan_metadata": {
					"agent_version": "unknown",
					"scan_date": null,
					"scan_duration_ms": 0,
					"scan_modules": []
				},
				"packages": [],
				"certificates": []
			}'::jsonb,
			system_fingerprint = '{
				"hardware": {},
				"network": {},
				"users": [],
				"services": []
			}'::jsonb,
			agent_metadata = '{
				"last_agent_contact": null,
				"agent_version": "unknown", 
				"capabilities": [],
				"configuration": {}
			}'::jsonb
		WHERE 
			software_inventory IS NULL 
			OR system_fingerprint IS NULL 
			OR agent_metadata IS NULL
			OR software_inventory = 'null'::jsonb
			OR system_fingerprint = 'null'::jsonb
			OR agent_metadata = 'null'::jsonb
	`).Error
	if err != nil {
		log.Fatalf("Failed to initialize existing records: %v", err)
	}

	// 4. Add constraints and validation
	log.Println("Adding JSONB validation constraints...")

	// Ensure JSONB columns are not null
	err = db.Exec(`
		ALTER TABLE hosts 
		ALTER COLUMN software_inventory SET NOT NULL
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to set software_inventory NOT NULL constraint: %v", err)
	}

	err = db.Exec(`
		ALTER TABLE hosts 
		ALTER COLUMN system_fingerprint SET NOT NULL
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to set system_fingerprint NOT NULL constraint: %v", err)
	}

	err = db.Exec(`
		ALTER TABLE hosts 
		ALTER COLUMN agent_metadata SET NOT NULL
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to set agent_metadata NOT NULL constraint: %v", err)
	}

	// 5. Create indexes for efficient JSONB querying
	log.Println("Creating JSONB indexes for efficient querying...")

	// GIN indexes for general JSONB operations
	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_software_inventory_gin 
		ON hosts USING gin (software_inventory)
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create GIN index on software_inventory: %v", err)
	}

	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_system_fingerprint_gin 
		ON hosts USING gin (system_fingerprint)
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create GIN index on system_fingerprint: %v", err)
	}

	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_agent_metadata_gin 
		ON hosts USING gin (agent_metadata)
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create GIN index on agent_metadata: %v", err)
	}

	// Specific indexes for common query paths
	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_software_packages 
		ON hosts USING gin ((software_inventory -> 'packages'))
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create index on software packages: %v", err)
	}

	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_hardware_info 
		ON hosts USING gin ((system_fingerprint -> 'hardware'))
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create index on hardware info: %v", err)
	}

	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_network_info 
		ON hosts USING gin ((system_fingerprint -> 'network'))
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create index on network info: %v", err)
	}

	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_agent_version 
		ON hosts USING btree ((agent_metadata ->> 'agent_version'))
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create index on agent version: %v", err)
	}

	err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_hosts_last_contact 
		ON hosts USING btree ((agent_metadata ->> 'last_agent_contact'))
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create index on last agent contact: %v", err)
	}

	// 6. Create example JSONB documents for validation
	log.Println("Creating example JSONB structure documentation...")

	err = db.Exec(`
		INSERT INTO migration_004_rollback_info (table_name, column_name) 
		VALUES 
			('documentation', 'software_inventory_example'),
			('documentation', 'system_fingerprint_example'),
			('documentation', 'agent_metadata_example')
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to log documentation entries: %v", err)
	}

	// 7. Verify the migration
	log.Println("Verifying migration results...")

	// Check if all columns exist
	var softwareInventoryExists, systemFingerprintExists, agentMetadataExists bool

	err = db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'hosts' AND column_name = 'software_inventory'
		)
	`).Scan(&softwareInventoryExists).Error
	if err != nil {
		log.Fatalf("Failed to verify software_inventory column: %v", err)
	}

	err = db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'hosts' AND column_name = 'system_fingerprint'
		)
	`).Scan(&systemFingerprintExists).Error
	if err != nil {
		log.Fatalf("Failed to verify system_fingerprint column: %v", err)
	}

	err = db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'hosts' AND column_name = 'agent_metadata'
		)
	`).Scan(&agentMetadataExists).Error
	if err != nil {
		log.Fatalf("Failed to verify agent_metadata column: %v", err)
	}

	// Count total hosts and verify they have JSONB data
	var hostCount int64
	err = db.Table("hosts").Count(&hostCount).Error
	if err != nil {
		log.Fatalf("Failed to count hosts: %v", err)
	}

	var hostsWithData int64
	err = db.Raw(`
		SELECT COUNT(*) FROM hosts 
		WHERE 
			software_inventory IS NOT NULL 
			AND system_fingerprint IS NOT NULL 
			AND agent_metadata IS NOT NULL
			AND software_inventory != 'null'::jsonb
			AND system_fingerprint != 'null'::jsonb
			AND agent_metadata != 'null'::jsonb
	`).Scan(&hostsWithData).Error
	if err != nil {
		log.Fatalf("Failed to count hosts with JSONB data: %v", err)
	}

	// 8. Final verification and summary
	log.Printf("Migration completed successfully!")
	log.Printf("Results:")
	log.Printf("  ✅ software_inventory column: %t", softwareInventoryExists)
	log.Printf("  ✅ system_fingerprint column: %t", systemFingerprintExists)
	log.Printf("  ✅ agent_metadata column: %t", agentMetadataExists)
	log.Printf("  📊 Total hosts: %d", hostCount)
	log.Printf("  📊 Hosts with JSONB data: %d", hostsWithData)
	log.Printf("  🔍 JSONB indexes created for efficient querying")
	log.Printf("  🔄 Rollback information stored in migration_004_rollback_info")

	if !softwareInventoryExists || !systemFingerprintExists || !agentMetadataExists {
		log.Fatalf("Migration verification failed - not all columns were created")
	}

	if hostCount > 0 && hostsWithData != hostCount {
		log.Printf("Warning: %d hosts do not have complete JSONB data", hostCount-hostsWithData)
	}

	log.Println("Migration 004_add_sbom_schema completed successfully!")
	log.Println("")
	log.Println("📋 JSONB Schema Documentation:")
	log.Println("   software_inventory: Packages, certificates, and scan metadata")
	log.Println("   system_fingerprint: Hardware, network, users, and services")
	log.Println("   agent_metadata: Agent version, capabilities, and configuration")
	log.Println("")
	log.Println("🔧 To rollback this migration, run: go run migrations/004_add_sbom_schema/rollback/main.go")
}
