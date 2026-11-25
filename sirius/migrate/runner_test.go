package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func migrationTestPool(t *testing.T, config *pgx.ConnConfig) *gorm.DB {
	t.Helper()
	pool := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = pool.Close() })
	db, err := gorm.Open(pgdriver.New(pgdriver.Config{Conn: pool}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func migrationTestSchema(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv("SIRIUS_PORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_PORT_TEST_DSN to a disposable PostgreSQL instance")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := migrationTestPool(t, config)
	schema := fmt.Sprintf("migration_runner_%d", time.Now().UnixNano())
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Error(err)
		}
	})
	config = config.Copy()
	config.RuntimeParams["search_path"] = schema
	return config
}

func TestMigrationRunnerConcurrent(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "pre_010"
		}
		t.Run(name, func(t *testing.T) {
			config := migrationTestSchema(t)
			first := migrationTestPool(t, config)
			second := migrationTestPool(t, config)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			migrations := Migrations()
			if upgrade {
				if err := up(ctx, first, migrations[:len(migrations)-1]); err != nil {
					t.Fatal(err)
				}
				if err := first.Exec(`INSERT INTO hosts (h_id, ip) VALUES ('upgrade-host', '192.0.2.1')`).Error; err != nil {
					t.Fatal(err)
				}
			}

			start := make(chan struct{})
			results := make(chan error, 2)
			for _, db := range []*gorm.DB{first, second} {
				go func() {
					<-start
					results <- UpContext(ctx, db)
				}()
			}
			close(start)
			for range 2 {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			if t.Failed() {
				return
			}

			var versions []string
			if err := first.Table(ledgerTable).Order("version").Pluck("version", &versions).Error; err != nil {
				t.Fatal(err)
			}
			if len(versions) != len(migrations) {
				t.Fatalf("ledger versions = %v", versions)
			}
			for i, migration := range migrations {
				if versions[i] != migration.Version {
					t.Fatalf("ledger version[%d] = %s, want %s", i, versions[i], migration.Version)
				}
			}
			if upgrade {
				var owners []string
				result := first.Table("hosts").Where("h_id = ?", "upgrade-host").Pluck("owner_subject_id", &owners)
				if result.Error != nil || len(owners) != 1 || owners[0] != "" {
					t.Fatalf("legacy host owners = %v, error = %v", owners, result.Error)
				}
			}
		})
	}
}

func TestMigrationRunnerRollsBackFailedStep(t *testing.T) {
	config := migrationTestSchema(t)
	db := migrationTestPool(t, config)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first := Migration{Version: "001_test", Apply: func(tx *gorm.DB) error {
		return tx.Exec("CREATE TABLE committed_step (id integer)").Error
	}}
	step := Migration{Version: "002_test", Apply: func(tx *gorm.DB) error {
		return tx.Exec("CREATE TABLE pending_step (id integer)").Error
	}}

	afterDDL := step
	afterDDL.Apply = func(tx *gorm.DB) error {
		if err := step.Apply(tx); err != nil {
			return err
		}
		return tx.Exec("SELECT 1 / 0").Error
	}
	err := up(ctx, db, []Migration{first, afterDDL})
	if err == nil || !strings.Contains(err.Error(), "002_test") {
		t.Fatalf("expected versioned DDL error, got %v", err)
	}
	assertMigrationRollback(t, db, first.Version)

	if err := db.Exec(`ALTER TABLE schema_migrations_core ADD CONSTRAINT reject_pending CHECK (version <> '002_test')`).Error; err != nil {
		t.Fatal(err)
	}
	err = up(ctx, db, []Migration{first, step})
	if err == nil || !strings.Contains(err.Error(), "002_test") || !strings.Contains(err.Error(), "record migration") {
		t.Fatalf("expected versioned ledger error, got %v", err)
	}
	assertMigrationRollback(t, db, first.Version)

	if err := db.Exec("ALTER TABLE schema_migrations_core DROP CONSTRAINT reject_pending").Error; err != nil {
		t.Fatal(err)
	}
	if err := up(ctx, db, []Migration{first, step}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	applied, err := isApplied(db, step.Version)
	if err != nil || !applied || !db.Migrator().HasTable("pending_step") {
		t.Fatalf("retry applied = %v, ledger error = %v", applied, err)
	}
}

func assertMigrationRollback(t *testing.T, db *gorm.DB, committedVersion string) {
	t.Helper()
	var versions []string
	if err := db.Table(ledgerTable).Pluck("version", &versions).Error; err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0] != committedVersion {
		t.Fatalf("ledger versions after failure = %v", versions)
	}
	if !db.Migrator().HasTable("committed_step") || db.Migrator().HasTable("pending_step") {
		t.Fatal("failed step changed the schema or rolled back the previous step")
	}
}

func TestMigrationRunnerCancelsLockWait(t *testing.T) {
	config := migrationTestSchema(t)
	holder := migrationTestPool(t, config).Begin()
	if holder.Error != nil {
		t.Fatal(holder.Error)
	}
	t.Cleanup(func() { _ = holder.Rollback().Error })
	if err := holder.Exec("SELECT pg_advisory_xact_lock(?, ?)", migrationLockNamespace, migrationLockKey).Error; err != nil {
		t.Fatal(err)
	}

	db := migrationTestPool(t, config)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := UpContext(ctx, db)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait returned %v, want context deadline exceeded", err)
	}
	if db.Migrator().HasTable(ledgerTable) {
		t.Fatal("canceled runner created the ledger")
	}
	if err := holder.Rollback().Error; err != nil {
		t.Fatal(err)
	}

	retryCtx, retryCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer retryCancel()
	if err := UpContext(retryCtx, db); err != nil {
		t.Fatalf("retry after cancellation: %v", err)
	}
}
