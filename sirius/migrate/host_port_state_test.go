package migrate

import (
	"github.com/SiriusScan/go-api/sirius/postgres"
	"os"
	"testing"

	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func portMigrationFixture(t *testing.T, key string) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("SIRIUS_PORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_PORT_TEST_DSN to a disposable Postgres instance")
	}
	db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
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
	for _, sql := range []string{
		`SET LOCAL search_path TO pg_temp`,
		`CREATE TEMP TABLE ports (id bigint PRIMARY KEY, number int, protocol text, state text, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE host_ports (host_id bigint, port_id bigint, source text, PRIMARY KEY (` + key + `)) ON COMMIT DROP`,
		`INSERT INTO ports (id,number,protocol,state) VALUES (1,443,'tcp','open'),(2,53,'udp',NULL)`,
		`INSERT INTO host_ports VALUES (1,1,'nmap'),(2,1,'nmap'),(1,2,'agent'),(3,99,'orphan')`,
	} {
		if err := tx.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

func TestPortStateMigrationBackfillAndRerun(t *testing.T) {
	for _, key := range []string{"host_id, port_id", "host_id, port_id, source"} {
		t.Run(key, func(t *testing.T) {
			db := portMigrationFixture(t, key)
			if err := apply008(db); err != nil {
				t.Fatal(err)
			}
			var rows []struct {
				HostID uint
				PortID uint
				State  string
			}
			if err := db.Table("host_ports").Order("host_id,port_id").Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if len(rows) != 4 || rows[0].State != "open" || rows[1].State != "unknown" || rows[2].State != "open" || rows[3].State != "unknown" {
				t.Fatalf("backfill=%+v", rows)
			}
			for _, sql := range []string{
				`INSERT INTO host_ports (host_id,port_id,source,state) VALUES(1,1,'agent','filtered')`,
				`UPDATE host_ports SET state='closed' WHERE host_id=2 AND port_id=1`,
				`UPDATE ports SET state='filtered'`,
			} {
				if err := db.Exec(sql).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := apply008(db); err != nil {
				t.Fatal(err)
			}
			var state string
			if err := db.Raw(`SELECT state FROM host_ports WHERE host_id=2 AND port_id=1`).Scan(&state).Error; err != nil {
				t.Fatal(err)
			}
			if state != "closed" {
				t.Fatalf("rerun overwrote observation: %s", state)
			}
		})
	}
}

func TestPortStateMigrationRejectsDuplicateCatalog(t *testing.T) {
	db := portMigrationFixture(t, "host_id, port_id")
	if err := db.Exec(`INSERT INTO ports (id,number,protocol,state) VALUES(3,443,'tcp','closed')`).Error; err != nil {
		t.Fatal(err)
	}
	if err := apply008(db); err == nil {
		t.Fatal("expected duplicate catalog rejection")
	}
	var count int64
	if err := db.Table("ports").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("migration changed catalog: %d", count)
	}
	var exists bool
	if err := db.Raw(`SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='host_ports'::regclass AND attname='state' AND NOT attisdropped)`).Scan(&exists).Error; err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("failed migration left partial schema change")
	}
}

func TestPortStateMigrationRejectsUnexpectedKey(t *testing.T) {
	db := portMigrationFixture(t, "port_id, host_id")
	if err := apply008(db); err == nil {
		t.Fatal("expected unexpected key rejection")
	}
	var exists bool
	if err := db.Raw(`SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='host_ports'::regclass AND attname='state' AND NOT attisdropped)`).Scan(&exists).Error; err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("failed migration did not roll back schema")
	}
}

func TestPortStateFreshLedger(t *testing.T) {
	dsn := os.Getenv("SIRIUS_PORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_PORT_TEST_DSN to a disposable Postgres instance")
	}
	db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
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
	// Full baseline migration needs a real schema for GORM metadata queries.
	// This schema, all tables and the ledger are rolled back on the disposable DB.
	if err := tx.Exec(`CREATE SCHEMA port_state_fresh_test`).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Exec(`SET LOCAL search_path TO port_state_fresh_test`).Error; err != nil {
		t.Fatal(err)
	}
	if err := Up(tx); err != nil {
		t.Fatal(err)
	}
	if err := Up(tx); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := tx.Table(ledgerTable).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != int64(len(Migrations())) {
		t.Fatalf("ledger count=%d", count)
	}
	var columns string
	if err := tx.Raw(`SELECT string_agg(a.attname, ',' ORDER BY k.position)
		FROM pg_constraint c CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, position)
		JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
		WHERE c.conrelid='host_ports'::regclass AND c.contype='p'`).Scan(&columns).Error; err != nil {
		t.Fatal(err)
	}
	if columns != "host_id,port_id,source" {
		t.Fatalf("fresh key=%s", columns)
	}
}

func TestPortStatePopulatedLegacyBaselineUpgrade(t *testing.T) {
	dsn := os.Getenv("SIRIUS_PORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_PORT_TEST_DSN to a disposable Postgres instance")
	}
	db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
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
	for _, sql := range []string{`CREATE SCHEMA port_state_legacy_test`, `SET LOCAL search_path TO port_state_legacy_test`} {
		if err := tx.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Build the populated pre-008 schema without a migration ledger. These same
	// models must not materialize state before 008 can backfill it.
	if err := postgres.AutoMigrateSchemaDB(tx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := tx.Raw(`SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='host_ports'::regclass AND attname='state' AND NOT attisdropped)`).Scan(&exists).Error; err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("baseline AutoMigrate must leave observation state to migration 008")
	}
	for _, sql := range []string{
		`ALTER TABLE host_ports DROP CONSTRAINT host_ports_pkey`,
		`ALTER TABLE host_ports ADD PRIMARY KEY(host_id,port_id)`,
		`INSERT INTO hosts (id,h_id,ip) VALUES(1,'legacy-a','192.0.2.1'),(2,'legacy-b','192.0.2.2')`,
		`INSERT INTO ports (id,number,protocol,state) VALUES(1,443,'tcp','closed')`,
		`INSERT INTO host_ports (host_id,port_id,source) VALUES(1,1,'nmap'),(2,1,'nmap')`,
		`ALTER TABLE host_ports ALTER COLUMN source DROP NOT NULL`,
		`ALTER TABLE host_ports ALTER COLUMN source DROP DEFAULT`,
		`UPDATE host_ports SET source=NULL WHERE host_id=2`,
	} {
		if err := tx.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	// Up must run baseline AutoMigrate again, then all pending migrations.
	if err := Up(tx); err != nil {
		t.Fatal(err)
	}
	var states []string
	if err := tx.Table("host_ports").Order("host_id").Pluck("state", &states).Error; err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[0] != "closed" || states[1] != "closed" {
		t.Fatalf("legacy backfill=%v", states)
	}
	var source string
	if err := tx.Raw(`SELECT source FROM host_ports WHERE host_id=2`).Scan(&source).Error; err != nil {
		t.Fatal(err)
	}
	if source != "unknown" {
		t.Fatalf("legacy null source=%q", source)
	}
	if err := tx.Exec(`UPDATE host_ports SET state='unknown' WHERE host_id=1`).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Exec(`UPDATE ports SET state='filtered'`).Error; err != nil {
		t.Fatal(err)
	}
	// Opt-in AutoMigrate after upgrade and a retried 008 must not change genuine unknown.
	if err := postgres.AutoMigrateSchemaDB(tx); err != nil {
		t.Fatal(err)
	}
	if err := apply008(tx); err != nil {
		t.Fatal(err)
	}
	states = nil
	if err := tx.Table("host_ports").Order("host_id").Pluck("state", &states).Error; err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[0] != "unknown" || states[1] != "closed" {
		t.Fatalf("retry changed real observations=%v", states)
	}
}

func TestPortStateMigrationRejectsRetiredCatalog(t *testing.T) {
	db := portMigrationFixture(t, "host_id, port_id")
	if err := db.Exec(`UPDATE ports SET deleted_at=now() WHERE id=1`).Error; err != nil {
		t.Fatal(err)
	}
	if err := apply008(db); err == nil {
		t.Fatal("expected retired catalog preflight rejection")
	}
	var exists bool
	if err := db.Raw(`SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='host_ports'::regclass AND attname='state' AND NOT attisdropped)`).Scan(&exists).Error; err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("preflight failure changed schema")
	}
}
