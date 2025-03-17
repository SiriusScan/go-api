package main

import (
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func main() {
	db := postgres.GetDB()

	log.Println("Starting migration to fix many-to-many relationships...")

	// 1. Create a backup of existing relationships
	log.Println("Creating backups of existing relationships...")

	type PortBackup struct {
		PortID   int
		Protocol string
		State    string
		HostID   uint
	}

	var portBackups []PortBackup
	err := db.Table("ports").Select("id as port_id, protocol, state, host_id").Find(&portBackups).Error
	if err != nil {
		log.Fatalf("Failed to backup port relationships: %v", err)
	}

	type VulnBackup struct {
		VulnID uint
		HostID uint
	}

	var vulnBackups []VulnBackup
	err = db.Table("vulnerabilities").
		Select("id as vuln_id, host_id").
		Where("host_id IS NOT NULL AND host_id > 0").
		Find(&vulnBackups).Error
	if err != nil {
		log.Fatalf("Failed to backup vulnerability relationships: %v", err)
	}

	// 2. Run migrations to update the schema
	log.Println("Updating database schema...")

	// Auto-migrate will create the new junction table
	err = db.AutoMigrate(&models.Host{}, &models.Port{}, &models.Vulnerability{}, &models.HostPort{})
	if err != nil {
		log.Fatalf("Failed to migrate schema: %v", err)
	}

	// 3. Restore relationships using the new junction table for ports
	log.Println("Restoring port relationships...")
	for _, backup := range portBackups {
		// Create the junction table entry
		err = db.Exec("INSERT INTO host_ports (host_id, port_id, created_at, updated_at) VALUES (?, ?, NOW(), NOW())",
			backup.HostID, backup.PortID).Error
		if err != nil {
			log.Printf("Warning: Failed to restore port relationship (Host: %d, Port: %d): %v",
				backup.HostID, backup.PortID, err)
		}
	}

	// 4. Ensure all vulnerability relationships are properly set
	log.Println("Ensuring vulnerability relationships...")
	for _, backup := range vulnBackups {
		// Check if this relationship already exists in the junction table
		var count int64
		db.Table("host_vulnerabilities").
			Where("host_id = ? AND vulnerability_id = ?", backup.HostID, backup.VulnID).
			Count(&count)

		// If it doesn't exist, create it
		if count == 0 {
			err = db.Exec("INSERT INTO host_vulnerabilities (host_id, vulnerability_id, created_at, updated_at) VALUES (?, ?, NOW(), NOW())",
				backup.HostID, backup.VulnID).Error
			if err != nil {
				log.Printf("Warning: Failed to restore vulnerability relationship (Host: %d, Vulnerability: %d): %v",
					backup.HostID, backup.VulnID, err)
			}
		}
	}

	// 5. Remove HostID column from vulnerabilities table
	log.Println("Removing HostID column from vulnerabilities table...")
	err = db.Exec("ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS host_id").Error
	if err != nil {
		log.Printf("Warning: Failed to drop host_id column from vulnerabilities: %v", err)
	}

	// 6. Remove HostID column from ports table
	log.Println("Removing HostID column from ports table...")
	err = db.Exec("ALTER TABLE ports DROP COLUMN IF EXISTS host_id").Error
	if err != nil {
		log.Printf("Warning: Failed to drop host_id column from ports: %v", err)
	}

	log.Println("Migration completed successfully!")
}
