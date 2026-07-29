// Package migrate applies forward-only core schema migrations recorded in
// schema_migrations_core. Production deployments must run cmd/migrate rather
// than relying on GORM AutoMigrate-on-connect.
package migrate

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"gorm.io/gorm"
)

const ledgerTable = "schema_migrations_core"

// Migration is a single forward-only schema step.
type Migration struct {
	Version string
	Name    string
	Apply   func(db *gorm.DB) error
}

// Migrations returns the ordered core migration list.
func Migrations() []Migration {
	return []Migration{
		{Version: "001_baseline", Name: "GORM AutoMigrate core models", Apply: applyBaseline},
		{Version: "002_source_attribution", Name: "Source attribution columns on junction tables", Apply: apply002},
		{Version: "003_enhanced_junction_tables", Name: "Ensure enhanced junction table shape", Apply: apply003},
		{Version: "004_add_sbom_schema", Name: "SBOM and fingerprint columns on hosts", Apply: apply004},
		{Version: "005_fix_critical_schema_issues", Name: "Critical schema fixes (ports.number, indexes)", Apply: apply005},
		{Version: "006_add_events_table", Name: "Events table and indexes", Apply: apply006},
		{Version: "007_add_vulnerability_stats_indexes", Name: "Vulnerability statistics indexes", Apply: apply007},
	}
}

// Up applies all pending migrations against the given DB.
func Up(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}
	if err := ensureLedger(db); err != nil {
		return err
	}

	for _, m := range Migrations() {
		applied, err := isApplied(db, m.Version)
		if err != nil {
			return err
		}
		if applied {
			slog.Info("Migration already applied", "version", m.Version)
			continue
		}

		slog.Info("Applying migration", "version", m.Version, "name", m.Name)
		if err := m.Apply(db); err != nil {
			return fmt.Errorf("migration %s failed: %w", m.Version, err)
		}
		if err := recordApplied(db, m.Version); err != nil {
			return fmt.Errorf("failed to record migration %s: %w", m.Version, err)
		}
		slog.Info("Migration applied", "version", m.Version)
	}

	return nil
}

// UpFromDefault connects via postgres package and runs Up.
func UpFromDefault() error {
	db := postgres.GetDB()
	if db == nil {
		err := postgres.GetConnectionError()
		if err == nil {
			err = fmt.Errorf("database not connected")
		}
		return err
	}
	return Up(db)
}

func ensureLedger(db *gorm.DB) error {
	return db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations_core (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`).Error
}

func isApplied(db *gorm.DB, version string) (bool, error) {
	var count int64
	err := db.Raw(
		`SELECT COUNT(1) FROM schema_migrations_core WHERE version = ?`,
		version,
	).Scan(&count).Error
	return count > 0, err
}

func recordApplied(db *gorm.DB, version string) error {
	return db.Exec(
		`INSERT INTO schema_migrations_core (version, applied_at) VALUES (?, ?)`,
		version,
		time.Now().UTC(),
	).Error
}

func applyBaseline(db *gorm.DB) error {
	return postgres.AutoMigrateSchemaDB(db)
}
