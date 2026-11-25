// Package migrate applies forward-only core schema migrations recorded in
// schema_migrations_core. Production deployments must run cmd/migrate rather
// than relying on GORM AutoMigrate-on-connect.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"gorm.io/gorm"
)

const ledgerTable = "schema_migrations_core"

// The two-int PostgreSQL key space is separate from the single-bigint host
// report locks. Both constants are reserved for the core migration ledger.
const (
	migrationLockNamespace int32 = 0x53495249 // SIRI
	migrationLockKey       int32 = 0x434f5245 // CORE
)

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
		{Version: "008_host_port_state", Name: "Host and source scoped port state", Apply: apply008},
		{Version: "009_host_vulnerability_finding", Name: "Preserve source-specific vulnerability evidence", Apply: apply009},
		{Version: "010_host_resource_scope", Name: "Host resource attribution", Apply: apply010},
	}
}

// Up applies all pending migrations using the database handle's context.
func Up(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}
	return UpContext(db.Statement.Context, db)
}

// UpContext applies all pending core migrations. With a pool, each version
// commits independently and releases the database-wide migration lock.
// A caller-owned read-committed transaction uses savepoints and retains the
// successful changes and advisory lock until the caller ends that transaction.
func UpContext(ctx context.Context, db *gorm.DB) error {
	return up(ctx, db, Migrations())
}

func up(ctx context.Context, db *gorm.DB, migrations []Migration) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}

	runner := db.WithContext(ctx)
	if _, inTransaction := runner.Statement.ConnPool.(gorm.TxCommitter); inTransaction {
		// A fixed snapshot could miss a version committed by the previous
		// lock holder. A savepoint cannot change its parent's isolation.
		var isolation string
		if err := runner.Raw("SHOW transaction_isolation").Scan(&isolation).Error; err != nil {
			return fmt.Errorf("check migration transaction isolation: %w", err)
		}
		if isolation != "read committed" && isolation != "read uncommitted" {
			return fmt.Errorf("core migrations require read-committed visibility, got %s", isolation)
		}
		// WithContext cloned the GORM settings. Enable step savepoints even
		// when the caller has disabled GORM's nested transactions.
		runner.DisableNestedTransaction = false
	}

	for _, m := range migrations {
		var applied bool
		err := runner.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", migrationLockNamespace, migrationLockKey).Error; err != nil {
				return fmt.Errorf("acquire core migration lock: %w", err)
			}
			if err := ensureLedger(tx); err != nil {
				return fmt.Errorf("ensure migration ledger: %w", err)
			}
			var err error
			applied, err = isApplied(tx, m.Version)
			if err != nil {
				return fmt.Errorf("read migration ledger: %w", err)
			}
			if applied {
				return nil
			}

			slog.Info("Applying migration", "version", m.Version, "name", m.Name)
			// The transactions in steps 008–010 participate as savepoints.
			if err := m.Apply(tx); err != nil {
				return err
			}
			if err := recordApplied(tx, m.Version); err != nil {
				return fmt.Errorf("record migration: %w", err)
			}
			return nil
		}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			return fmt.Errorf("migration %s failed: %w", m.Version, err)
		}
		if applied {
			slog.Info("Migration already applied", "version", m.Version)
		} else {
			slog.Info("Migration applied", "version", m.Version)
		}
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
