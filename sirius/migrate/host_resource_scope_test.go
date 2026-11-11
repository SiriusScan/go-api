package migrate

import (
	"os"
	"testing"

	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestHostResourceScopeMigrationPreservesLegacyAndIsIdempotent(t *testing.T) {
	dsn := os.Getenv("SIRIUS_PORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_PORT_TEST_DSN to a disposable Postgres instance")
	}
	db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	t.Cleanup(func() { _ = tx.Rollback().Error })
	for _, q := range []string{`SET LOCAL search_path TO pg_temp`, `CREATE TEMP TABLE hosts (id bigint PRIMARY KEY, ip text, deleted_at timestamptz) ON COMMIT DROP`, `INSERT INTO hosts VALUES (1, '192.0.2.1', NULL), (2, '192.0.2.1', NULL)`} {
		if err := tx.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := apply010(tx); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	if err := tx.Raw(`SELECT count(*) FROM hosts WHERE owner_subject_id = ''`).Scan(&count).Error; err != nil || count != 2 {
		t.Fatalf("legacy count=%d err=%v", count, err)
	}
	if err := tx.Exec(`INSERT INTO hosts (id,ip,owner_subject_id) VALUES (3,'192.0.2.1','alice'),(4,'192.0.2.1','bob')`).Error; err != nil {
		t.Fatal(err)
	}
}
