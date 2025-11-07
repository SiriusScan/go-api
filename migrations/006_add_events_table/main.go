package main

import (
	"fmt"
	"log"
	"os"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"gorm.io/gorm"
)

func main() {
	log.Println("🔄 Starting migration 006: Add Events Table")

	// Get database connection
	db := postgres.GetDB()
	if db == nil {
		log.Fatal("❌ Failed to connect to database")
	}

	// Run migration
	if err := migrateUp(db); err != nil {
		log.Fatalf("❌ Migration failed: %v", err)
	}

	log.Println("✅ Migration 006 completed successfully")
}

func migrateUp(db *gorm.DB) error {
	log.Println("📊 Creating events table...")

	// Create events table
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS events (
		id BIGSERIAL PRIMARY KEY,
		event_id VARCHAR(255) UNIQUE NOT NULL,
		timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		service VARCHAR(100) NOT NULL,
		subcomponent VARCHAR(100),
		event_type VARCHAR(50) NOT NULL,
		severity VARCHAR(20) NOT NULL,
		title VARCHAR(255) NOT NULL,
		description TEXT,
		metadata JSONB,
		entity_type VARCHAR(50),
		entity_id VARCHAR(255),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	`

	if err := db.Exec(createTableSQL).Error; err != nil {
		return fmt.Errorf("failed to create events table: %w", err)
	}

	log.Println("✅ Events table created")

	// Create indexes
	log.Println("📊 Creating indexes...")

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);",
		"CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);",
		"CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);",
		"CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);",
		"CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_type, entity_id);",
	}

	for _, indexSQL := range indexes {
		if err := db.Exec(indexSQL).Error; err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	log.Println("✅ All indexes created")

	return nil
}

func migrateDown(db *gorm.DB) error {
	log.Println("🔄 Rolling back events table...")

	// Drop indexes first
	dropIndexSQL := []string{
		"DROP INDEX IF EXISTS idx_events_entity;",
		"DROP INDEX IF EXISTS idx_events_severity;",
		"DROP INDEX IF EXISTS idx_events_type;",
		"DROP INDEX IF EXISTS idx_events_service;",
		"DROP INDEX IF EXISTS idx_events_timestamp;",
	}

	for _, sql := range dropIndexSQL {
		if err := db.Exec(sql).Error; err != nil {
			log.Printf("⚠️  Warning: Failed to drop index: %v", err)
		}
	}

	// Drop table
	dropTableSQL := "DROP TABLE IF EXISTS events;"
	if err := db.Exec(dropTableSQL).Error; err != nil {
		return fmt.Errorf("failed to drop events table: %w", err)
	}

	log.Println("✅ Events table rolled back")

	return nil
}

func init() {
	// Check for rollback flag
	if len(os.Args) > 1 && os.Args[1] == "--rollback" {
		log.Println("🔄 Running migration rollback...")
		db := postgres.GetDB()
		if db == nil {
			log.Fatal("❌ Failed to connect to database")
		}
		if err := migrateDown(db); err != nil {
			log.Fatalf("❌ Rollback failed: %v", err)
		}
		log.Println("✅ Rollback completed successfully")
		os.Exit(0)
	}
}

