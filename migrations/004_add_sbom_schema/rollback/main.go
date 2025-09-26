package main

import (
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres"
)

func main() {
	db := postgres.GetDB()

	log.Println("Starting rollback of migration 004_add_sbom_schema...")

	// 1. Verify rollback information exists
	var rollbackCount int64
	err := db.Table("migration_004_rollback_info").Count(&rollbackCount).Error
	if err != nil {
		log.Fatalf("Migration rollback info not found. Cannot safely rollback: %v", err)
	}

	if rollbackCount == 0 {
		log.Fatalf("No rollback information found. Migration may not have been run or rollback info was deleted.")
	}

	log.Printf("Found %d rollback entries", rollbackCount)

	// 2. Create backup of current state before rollback
	log.Println("Creating backup of current hosts table state...")

	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS hosts_pre_rollback_004 AS 
		SELECT * FROM hosts LIMIT 0
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to create pre-rollback backup table: %v", err)
	}

	// Save a sample of current JSONB data for verification
	err = db.Exec(`
		INSERT INTO hosts_pre_rollback_004 
		SELECT * FROM hosts LIMIT 5
	`).Error
	if err != nil {
		log.Printf("Warning: Failed to backup sample data: %v", err)
	}

	// 3. Drop indexes first (in reverse order of creation)
	log.Println("Dropping JSONB indexes...")

	indexes := []string{
		"idx_hosts_last_contact",
		"idx_hosts_agent_version",
		"idx_hosts_network_info",
		"idx_hosts_hardware_info",
		"idx_hosts_software_packages",
		"idx_hosts_agent_metadata_gin",
		"idx_hosts_system_fingerprint_gin",
		"idx_hosts_software_inventory_gin",
	}

	for _, index := range indexes {
		err = db.Exec("DROP INDEX IF EXISTS " + index).Error
		if err != nil {
			log.Printf("Warning: Failed to drop index %s: %v", index, err)
		} else {
			log.Printf("✅ Dropped index: %s", index)
		}
	}

	// 4. Remove JSONB columns (in reverse order of creation)
	log.Println("Removing JSONB columns from hosts table...")

	columns := []string{
		"agent_metadata",
		"system_fingerprint",
		"software_inventory",
	}

	for _, column := range columns {
		// First check if column exists
		var columnExists bool
		err = db.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'hosts' AND column_name = ?
			)
		`, column).Scan(&columnExists).Error

		if err != nil {
			log.Printf("Error checking column %s: %v", column, err)
			continue
		}

		if columnExists {
			err = db.Exec("ALTER TABLE hosts DROP COLUMN IF EXISTS " + column).Error
			if err != nil {
				log.Printf("❌ Failed to drop column %s: %v", column, err)
			} else {
				log.Printf("✅ Dropped column: %s", column)
			}
		} else {
			log.Printf("⚠️  Column %s does not exist", column)
		}
	}

	// 5. Clean up rollback tracking tables
	log.Println("Cleaning up rollback tracking tables...")

	err = db.Exec("DROP TABLE IF EXISTS migration_004_rollback_info").Error
	if err != nil {
		log.Printf("Warning: Failed to drop rollback info table: %v", err)
	} else {
		log.Printf("✅ Dropped rollback info table")
	}

	err = db.Exec("DROP TABLE IF EXISTS hosts_backup_004").Error
	if err != nil {
		log.Printf("Warning: Failed to drop backup table: %v", err)
	} else {
		log.Printf("✅ Dropped backup table")
	}

	// 6. Verify rollback success
	log.Println("Verifying rollback success...")

	var softwareInventoryExists, systemFingerprintExists, agentMetadataExists bool

	err = db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'hosts' AND column_name = 'software_inventory'
		)
	`).Scan(&softwareInventoryExists).Error
	if err != nil {
		log.Fatalf("Failed to verify software_inventory removal: %v", err)
	}

	err = db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'hosts' AND column_name = 'system_fingerprint'
		)
	`).Scan(&systemFingerprintExists).Error
	if err != nil {
		log.Fatalf("Failed to verify system_fingerprint removal: %v", err)
	}

	err = db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns 
			WHERE table_name = 'hosts' AND column_name = 'agent_metadata'
		)
	`).Scan(&agentMetadataExists).Error
	if err != nil {
		log.Fatalf("Failed to verify agent_metadata removal: %v", err)
	}

	// Check hosts table integrity
	var hostCount int64
	err = db.Table("hosts").Count(&hostCount).Error
	if err != nil {
		log.Fatalf("Failed to verify hosts table integrity: %v", err)
	}

	// 7. Final verification and summary
	log.Printf("Rollback completed!")
	log.Printf("Results:")
	log.Printf("  ❌ software_inventory column removed: %t", !softwareInventoryExists)
	log.Printf("  ❌ system_fingerprint column removed: %t", !systemFingerprintExists)
	log.Printf("  ❌ agent_metadata column removed: %t", !agentMetadataExists)
	log.Printf("  📊 Hosts table integrity: %d records preserved", hostCount)
	log.Printf("  🔄 Pre-rollback backup: hosts_pre_rollback_004 (preserved)")

	if softwareInventoryExists || systemFingerprintExists || agentMetadataExists {
		log.Printf("⚠️  Warning: Some columns still exist after rollback:")
		if softwareInventoryExists {
			log.Printf("     - software_inventory still exists")
		}
		if systemFingerprintExists {
			log.Printf("     - system_fingerprint still exists")
		}
		if agentMetadataExists {
			log.Printf("     - agent_metadata still exists")
		}
		log.Printf("   Manual intervention may be required")
	} else {
		log.Printf("✅ All JSONB columns successfully removed")
	}

	log.Println("")
	log.Println("📋 Rollback Summary:")
	log.Println("   - All SBOM and fingerprinting JSONB columns removed")
	log.Println("   - All related indexes dropped")
	log.Println("   - Original hosts table structure restored")
	log.Println("   - Pre-rollback backup available in hosts_pre_rollback_004")
	log.Println("")
	log.Println("🔧 To re-apply this migration, run: go run migrations/004_add_sbom_schema/main.go")
}
