package migrate

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScanHistoryJournalMigrationFrom010(t *testing.T) {
	config := migrationTestSchema(t)
	db := migrationTestPool(t, config)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	steps := Migrations()
	next := slices.IndexFunc(steps, func(step Migration) bool { return step.Version == "011_host_port_service" })
	if next < 0 {
		t.Fatal("missing 011 migration")
	}
	if err := up(ctx, db, steps[:next]); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`INSERT INTO hosts (id, h_id, ip) VALUES (1, 'legacy-host', '192.0.2.1')`,
		`INSERT INTO scan_history_entries (host_id, source, scan_time, findings_count, deleted_at) VALUES
			(1, 'legacy-live', NULL, NULL, NULL),
			(1, 'legacy-deleted', '2025-01-01', 0, '2025-01-02')`,
	} {
		if err := db.WithContext(ctx).Exec(query).Error; err != nil {
			t.Fatal(err)
		}
	}

	holder := migrationTestPool(t, config).WithContext(ctx).Begin()
	if holder.Error != nil {
		t.Fatal(holder.Error)
	}
	t.Cleanup(func() { _ = holder.Rollback().Error })
	if err := holder.Exec("LOCK TABLE scan_history_entries IN ROW EXCLUSIVE MODE").Error; err != nil {
		t.Fatal(err)
	}

	migrationCtx, stopMigration := context.WithCancel(ctx)
	defer stopMigration()
	result := make(chan error, 1)
	go func() { result <- UpContext(migrationCtx, db) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for waiting := false; !waiting; {
		if err := db.WithContext(ctx).Raw(`SELECT EXISTS (SELECT 1 FROM pg_locks
			WHERE relation = 'scan_history_entries'::regclass AND mode = 'ShareLock' AND NOT granted)`).Scan(&waiting).Error; err != nil {
			t.Fatal(err)
		}
		if !waiting {
			select {
			case err := <-result:
				t.Fatalf("migration finished before the index lock wait: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-ticker.C:
			}
		}
	}
	stopMigration()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "012_scan_history_journal") {
			t.Fatalf("migration lock wait returned %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := holder.Rollback().Error; err != nil {
		t.Fatal(err)
	}

	var indexExists bool
	if err := db.Raw("SELECT to_regclass('idx_scan_history_entries_live_host_time_id') IS NOT NULL").Scan(&indexExists).Error; err != nil || indexExists {
		t.Fatalf("index exists after cancellation = %v, error = %v", indexExists, err)
	}
	if applied, err := isApplied(db, "012_scan_history_journal"); err != nil || applied {
		t.Fatalf("migration recorded after cancellation = %v, error = %v", applied, err)
	}

	for range 2 {
		if err := UpContext(ctx, db); err != nil {
			t.Fatalf("retry: %v", err)
		}
	}
	var definition string
	if err := db.Raw(`SELECT pg_get_indexdef(indexrelid) FROM pg_index
		WHERE indexrelid = 'idx_scan_history_entries_live_host_time_id'::regclass
			AND indrelid = 'scan_history_entries'::regclass AND indisvalid AND indisready AND indislive`).Scan(&definition).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(definition, "USING btree (host_id, scan_time DESC NULLS LAST, id DESC) WHERE (deleted_at IS NULL)") {
		t.Fatalf("unexpected index definition: %s", definition)
	}
	var count int64
	if err := db.Table(ledgerTable).Where("version = ?", "012_scan_history_journal").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("journal migration ledger rows = %d, error = %v", count, err)
	}
	if err := db.Exec(`INSERT INTO scan_history_entries (host_id, source, scan_time, findings_count)
		VALUES (1, 'after-migration', NOW(), 0)`).Error; err != nil {
		t.Fatal(err)
	}
	resultRows := db.Table("scan_history_entries").Where(`
		(source = 'legacy-live' AND scan_time IS NULL AND findings_count IS NULL AND deleted_at IS NULL)
		OR (source = 'legacy-deleted' AND scan_time IS NOT NULL AND findings_count = 0 AND deleted_at IS NOT NULL)
		OR (source = 'after-migration' AND scan_time IS NOT NULL AND findings_count = 0 AND deleted_at IS NULL)`).Count(&count)
	if resultRows.Error != nil || count != 3 {
		t.Fatalf("old and new journal rows = %d, error = %v", count, resultRows.Error)
	}
}
