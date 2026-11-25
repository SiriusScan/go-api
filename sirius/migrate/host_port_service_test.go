package migrate

import (
	"os"
	"testing"

	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestHostPortServiceMigrationPreservesLegacyAndIsIdempotent(t *testing.T) {
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
	for _, q := range []string{
		`SET LOCAL search_path TO pg_temp`,
		`CREATE TEMP TABLE host_ports (host_id bigint NOT NULL, port_id bigint NOT NULL, source text NOT NULL DEFAULT 'unknown', state text NOT NULL DEFAULT 'unknown', PRIMARY KEY (host_id, port_id, source)) ON COMMIT DROP`,
		`INSERT INTO host_ports (host_id, port_id, source, state) VALUES (1, 10, 'nmap', 'open'), (1, 10, 'naabu', 'open')`,
	} {
		if err := tx.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := apply011(tx); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	if err := tx.Raw(`SELECT count(*) FROM host_ports WHERE service_name = '' AND service_product = '' AND service_version = '' AND service_extrainfo = ''`).Scan(&count).Error; err != nil || count != 2 {
		t.Fatalf("legacy count=%d err=%v", count, err)
	}
	if err := tx.Exec(`UPDATE host_ports SET service_name='rpcbind', service_product='rpcbind', service_version='2-4', service_extrainfo='RPC #100000' WHERE host_id=1 AND port_id=10 AND source='nmap'`).Error; err != nil {
		t.Fatal(err)
	}
}
