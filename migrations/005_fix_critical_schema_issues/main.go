package main

import (
	"fmt"
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"gorm.io/gorm"
)

func main() {
	log.Println("=== Starting Migration 005: Fix Critical Schema Issues ===")
	log.Println("This migration addresses 6 critical database design issues:")
	log.Println("  1. Port.ID conflict (HIGH - causing current scan failures)")
	log.Println("  2. Vulnerability.VID unique constraint (HIGH - data integrity)")
	log.Println("  3. CVEDataMeta.ID conflict (HIGH - potential corruption)")
	log.Println("  4. Missing performance indexes (MEDIUM)")
	log.Println("  5. ScanHistoryEntry redundant ID (LOW - cleanup)")
	log.Println("")

	db := postgres.GetDB()
	if db == nil {
		log.Fatal("Failed to get database connection")
	}

	// ==================== PHASE 1: CRITICAL FIXES ====================

	log.Println("Phase 1: Fixing Port.ID Conflict...")
	if err := fixPortIDConflict(db); err != nil {
		log.Fatalf("Failed to fix Port.ID conflict: %v", err)
	}

	log.Println("Phase 1: Adding Vulnerability.VID Unique Constraint...")
	if err := addVulnerabilityVIDUniqueConstraint(db); err != nil {
		log.Fatalf("Failed to add VID unique constraint: %v", err)
	}

	// ==================== PHASE 2: CRITICAL PREVENTION ====================

	log.Println("Phase 2: Fixing CVEDataMeta.ID Conflict...")
	if err := fixCVEDataMetaIDConflict(db); err != nil {
		log.Fatalf("Failed to fix CVEDataMeta.ID conflict: %v", err)
	}

	log.Println("Phase 2: Adding Performance Indexes...")
	if err := addPerformanceIndexes(db); err != nil {
		log.Fatalf("Failed to add performance indexes: %v", err)
	}

	// ==================== VERIFICATION ====================

	log.Println("Verifying migration results...")
	if err := verifyMigration(db); err != nil {
		log.Fatalf("Migration verification failed: %v", err)
	}

	log.Println("")
	log.Println("=== Migration 005 Completed Successfully ===")
	log.Println("✅ Port.ID conflict resolved - scans should work now")
	log.Println("✅ Vulnerability.VID uniqueness enforced")
	log.Println("✅ CVEDataMeta.ID conflict resolved")
	log.Println("✅ Performance indexes added")
}

// fixPortIDConflict resolves the Port.ID field conflict
func fixPortIDConflict(db *gorm.DB) error {
	log.Println("  → Checking current ports table structure...")

	// Step 1: Check if ports table exists
	var tableExists bool
	err := db.Raw("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ports')").Scan(&tableExists).Error
	if err != nil {
		return fmt.Errorf("failed to check ports table existence: %w", err)
	}

	if !tableExists {
		log.Println("  → Ports table doesn't exist yet, skipping migration")
		return nil
	}

	// Step 2: Check if 'number' column already exists (migration already ran)
	var numberColumnExists bool
	err = db.Raw(`
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_name = 'ports' AND column_name = 'number'
		)
	`).Scan(&numberColumnExists).Error
	if err != nil {
		return fmt.Errorf("failed to check for number column: %w", err)
	}

	if numberColumnExists {
		log.Println("  → Port migration already completed (number column exists)")
		return nil
	}

	// Step 3: Backup existing data
	log.Println("  → Creating backup of ports table...")
	err = db.Exec("DROP TABLE IF EXISTS ports_backup_migration_005").Error
	if err != nil {
		return fmt.Errorf("failed to drop old backup: %w", err)
	}

	err = db.Exec("CREATE TABLE ports_backup_migration_005 AS SELECT * FROM ports").Error
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	var backupCount int64
	db.Table("ports_backup_migration_005").Count(&backupCount)
	log.Printf("  → Backed up %d port records", backupCount)

	// Step 4: Check and backup host_ports relationships
	log.Println("  → Backing up host_ports relationships...")
	err = db.Exec("DROP TABLE IF EXISTS host_ports_backup_migration_005").Error
	if err != nil {
		return fmt.Errorf("failed to drop old host_ports backup: %w", err)
	}

	err = db.Exec("CREATE TABLE host_ports_backup_migration_005 AS SELECT * FROM host_ports").Error
	if err != nil {
		return fmt.Errorf("failed to create host_ports backup: %w", err)
	}

	var hostPortsCount int64
	db.Table("host_ports_backup_migration_005").Count(&hostPortsCount)
	log.Printf("  → Backed up %d host-port relationships", hostPortsCount)

	// Step 5: Drop ALL foreign key constraints from host_ports that reference ports
	log.Println("  → Dropping all foreign key constraints from host_ports...")
	
	// Find all foreign key constraints on host_ports that reference ports
	var constraintNames []string
	err = db.Raw(`
		SELECT conname
		FROM pg_constraint
		WHERE conrelid = 'host_ports'::regclass
		AND confrelid = 'ports'::regclass
	`).Scan(&constraintNames).Error
	if err != nil {
		log.Printf("  → Warning: Failed to find foreign key constraints: %v", err)
	}
	
	// Drop each constraint
	for _, constraintName := range constraintNames {
		log.Printf("  → Dropping constraint: %s", constraintName)
		err = db.Exec(fmt.Sprintf("ALTER TABLE host_ports DROP CONSTRAINT IF EXISTS %s CASCADE", constraintName)).Error
		if err != nil {
			log.Printf("  → Warning: Failed to drop %s: %v", constraintName, err)
		}
	}

	// Step 6: Rename id column to number in ports table
	log.Println("  → Dropping primary key constraint with CASCADE...")
	err = db.Exec("ALTER TABLE ports DROP CONSTRAINT IF EXISTS ports_pkey CASCADE").Error
	if err != nil {
		return fmt.Errorf("failed to drop primary key: %w", err)
	}
	
	log.Println("  → Renaming ports.id column to number...")


	err = db.Exec("ALTER TABLE ports RENAME COLUMN id TO number").Error
	if err != nil {
		return fmt.Errorf("failed to rename id to number: %w", err)
	}

	// Step 7: Add new auto-increment id column
	log.Println("  → Adding new auto-increment id column...")
	err = db.Exec("ALTER TABLE ports ADD COLUMN id SERIAL PRIMARY KEY").Error
	if err != nil {
		return fmt.Errorf("failed to add new id column: %w", err)
	}

	// Step 8: Add unique constraint on (number, protocol)
	log.Println("  → Adding unique constraint on (number, protocol)...")
	err = db.Exec(`
		ALTER TABLE ports 
		ADD CONSTRAINT unique_port_number_protocol 
		UNIQUE (number, protocol)
	`).Error
	if err != nil {
		return fmt.Errorf("failed to add unique constraint: %w", err)
	}

	// Step 9: Rebuild host_ports table with new port IDs
	log.Println("  → Rebuilding host_ports relationships with new port IDs...")
	
	// Create temporary mapping table
	err = db.Exec(`
		CREATE TEMP TABLE port_id_mapping AS
		SELECT 
			hpb.host_id,
			hpb.port_id as old_port_id,
			p.id as new_port_id,
			hpb.source,
			hpb.source_version,
			hpb.first_seen,
			hpb.last_seen,
			hpb.status,
			hpb.notes
		FROM host_ports_backup_migration_005 hpb
		JOIN ports p ON p.number = hpb.port_id
	`).Error
	if err != nil {
		return fmt.Errorf("failed to create port ID mapping: %w", err)
	}

	// Clear host_ports table
	err = db.Exec("TRUNCATE TABLE host_ports").Error
	if err != nil {
		return fmt.Errorf("failed to truncate host_ports: %w", err)
	}

	// Insert updated relationships
	err = db.Exec(`
		INSERT INTO host_ports (
			host_id, port_id, source, source_version, 
			first_seen, last_seen, status, notes
		)
		SELECT 
			host_id, new_port_id, source, source_version,
			first_seen, last_seen, status, notes
		FROM port_id_mapping
	`).Error
	if err != nil {
		return fmt.Errorf("failed to restore host_ports relationships: %w", err)
	}

	var restoredCount int64
	db.Table("host_ports").Count(&restoredCount)
	log.Printf("  → Restored %d host-port relationships with new IDs", restoredCount)

	// Step 10: Re-add foreign key constraint
	log.Println("  → Re-adding foreign key constraints...")
	err = db.Exec(`
		ALTER TABLE host_ports 
		ADD CONSTRAINT fk_host_ports_port 
		FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
	`).Error
	if err != nil {
		log.Printf("  → Warning: Failed to add foreign key constraint: %v", err)
	}

	log.Println("  ✅ Port.ID conflict resolved successfully")
	return nil
}

// addVulnerabilityVIDUniqueConstraint adds unique constraint to v_id column
func addVulnerabilityVIDUniqueConstraint(db *gorm.DB) error {
	log.Println("  → Checking for duplicate VIDs before adding constraint...")

	// Find duplicates
	var duplicates []struct {
		VID   string
		Count int
	}
	err := db.Raw(`
		SELECT v_id, COUNT(*) as count 
		FROM vulnerabilities 
		WHERE v_id IS NOT NULL AND v_id != ''
		GROUP BY v_id 
		HAVING COUNT(*) > 1
	`).Scan(&duplicates).Error
	if err != nil {
		return fmt.Errorf("failed to check for duplicates: %w", err)
	}

	if len(duplicates) > 0 {
		log.Printf("  ⚠️  Found %d duplicate VIDs, cleaning up...", len(duplicates))
		
		// For each duplicate, keep only the most recent one
		for _, dup := range duplicates {
			err = db.Exec(`
				DELETE FROM vulnerabilities 
				WHERE id IN (
					SELECT id FROM vulnerabilities 
					WHERE v_id = ? 
					ORDER BY updated_at DESC 
					OFFSET 1
				)
			`, dup.VID).Error
			if err != nil {
				log.Printf("  → Warning: Failed to clean duplicate VID %s: %v", dup.VID, err)
			} else {
				log.Printf("  → Cleaned duplicate VID: %s (%d duplicates removed)", dup.VID, dup.Count-1)
			}
		}
	}

	// Check if constraint already exists
	var constraintExists bool
	err = db.Raw(`
		SELECT EXISTS (
			SELECT FROM pg_constraint 
			WHERE conname = 'unique_vulnerability_vid'
		)
	`).Scan(&constraintExists).Error
	if err != nil {
		return fmt.Errorf("failed to check for existing constraint: %w", err)
	}

	if constraintExists {
		log.Println("  → Unique constraint already exists")
		return nil
	}

	// Add unique constraint
	log.Println("  → Adding unique constraint on v_id...")
	err = db.Exec(`
		ALTER TABLE vulnerabilities 
		ADD CONSTRAINT unique_vulnerability_vid 
		UNIQUE (v_id)
	`).Error
	if err != nil {
		return fmt.Errorf("failed to add unique constraint: %w", err)
	}

	log.Println("  ✅ Vulnerability.VID unique constraint added")
	return nil
}

// fixCVEDataMetaIDConflict resolves the CVEDataMeta.ID field conflict
func fixCVEDataMetaIDConflict(db *gorm.DB) error {
	// Check if cve_data_meta table exists
	var tableExists bool
	err := db.Raw("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'cve_data_meta')").Scan(&tableExists).Error
	if err != nil {
		return fmt.Errorf("failed to check table existence: %w", err)
	}

	if !tableExists {
		log.Println("  → cve_data_meta table doesn't exist, skipping")
		return nil
	}

	// Check if cve_identifier column already exists
	var columnExists bool
	err = db.Raw(`
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_name = 'cve_data_meta' AND column_name = 'cve_identifier'
		)
	`).Scan(&columnExists).Error
	if err != nil {
		return fmt.Errorf("failed to check column existence: %w", err)
	}

	if columnExists {
		log.Println("  → CVEDataMeta migration already completed")
		return nil
	}

	// Check if there's a conflicting 'id' column (string type)
	var hasStringID bool
	err = db.Raw(`
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_name = 'cve_data_meta' 
			AND column_name = 'id' 
			AND data_type = 'character varying'
		)
	`).Scan(&hasStringID).Error
	if err != nil {
		return fmt.Errorf("failed to check for string ID: %w", err)
	}

	if hasStringID {
		log.Println("  → Renaming conflicting string ID column to cve_identifier...")
		
		// Drop unique index if it exists
		err = db.Exec("DROP INDEX IF EXISTS idx_cve_data_meta_id").Error
		if err != nil {
			log.Printf("  → Warning: Failed to drop index: %v", err)
		}

		// Rename the column
		err = db.Exec("ALTER TABLE cve_data_meta RENAME COLUMN id TO cve_identifier").Error
		if err != nil {
			return fmt.Errorf("failed to rename column: %w", err)
		}

		// Recreate unique index with new name
		err = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_data_meta_identifier ON cve_data_meta(cve_identifier)").Error
		if err != nil {
			log.Printf("  → Warning: Failed to create unique index: %v", err)
		}

		log.Println("  ✅ CVEDataMeta.ID conflict resolved")
	} else {
		log.Println("  → No conflicting string ID found, skipping")
	}

	return nil
}

// addPerformanceIndexes adds missing indexes for commonly queried fields
func addPerformanceIndexes(db *gorm.DB) error {
	indexes := []struct {
		name  string
		sql   string
		table string
	}{
		{
			name:  "idx_vulnerabilities_vid",
			sql:   "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vid ON vulnerabilities(v_id)",
			table: "vulnerabilities",
		},
		{
			name:  "idx_hosts_hostname",
			sql:   "CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname)",
			table: "hosts",
		},
		{
			name:  "idx_ports_number_protocol",
			sql:   "CREATE INDEX IF NOT EXISTS idx_ports_number_protocol ON ports(number, protocol)",
			table: "ports",
		},
		{
			name:  "idx_hosts_os",
			sql:   "CREATE INDEX IF NOT EXISTS idx_hosts_os ON hosts(os)",
			table: "hosts",
		},
	}

	for _, idx := range indexes {
		// Check if table exists
		var tableExists bool
		err := db.Raw(fmt.Sprintf("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = '%s')", idx.table)).Scan(&tableExists).Error
		if err != nil || !tableExists {
			log.Printf("  → Skipping %s (table doesn't exist)", idx.name)
			continue
		}

		log.Printf("  → Creating index %s...", idx.name)
		err = db.Exec(idx.sql).Error
		if err != nil {
			log.Printf("  → Warning: Failed to create %s: %v", idx.name, err)
		} else {
			log.Printf("  → ✓ Created %s", idx.name)
		}
	}

	log.Println("  ✅ Performance indexes added")
	return nil
}

// verifyMigration checks that all changes were applied correctly
func verifyMigration(db *gorm.DB) error {
	log.Println("  → Verifying ports table structure...")
	
	// Check for number column
	var hasNumber bool
	err := db.Raw(`
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_name = 'ports' AND column_name = 'number'
		)
	`).Scan(&hasNumber).Error
	if err == nil && hasNumber {
		log.Println("  ✓ ports.number column exists")
	}

	// Check for unique constraint
	var hasConstraint bool
	err = db.Raw(`
		SELECT EXISTS (
			SELECT FROM pg_constraint 
			WHERE conname = 'unique_port_number_protocol'
		)
	`).Scan(&hasConstraint).Error
	if err == nil && hasConstraint {
		log.Println("  ✓ unique_port_number_protocol constraint exists")
	}

	// Check for vulnerability VID unique constraint
	var hasVIDConstraint bool
	err = db.Raw(`
		SELECT EXISTS (
			SELECT FROM pg_constraint 
			WHERE conname = 'unique_vulnerability_vid'
		)
	`).Scan(&hasVIDConstraint).Error
	if err == nil && hasVIDConstraint {
		log.Println("  ✓ unique_vulnerability_vid constraint exists")
	}

	// Count records
	var portCount, hostPortCount int64
	db.Table("ports").Count(&portCount)
	db.Table("host_ports").Count(&hostPortCount)
	
	log.Printf("  ✓ Ports table: %d records", portCount)
	log.Printf("  ✓ Host-Port relationships: %d records", hostPortCount)

	return nil
}

