package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/migrate"
	"github.com/SiriusScan/go-api/sirius/scope"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const journalIndex = "idx_scan_history_entries_live_host_time_id"

// This is the pre-012 dated page query. First and undated pages retain their original SQL.
const baselineDatedJournal = `
	SELECT target_host.id AS host_id, target_host.ip AS host_ip, target_host.created_at AS host_created_at,
		journal.report_id, journal.source, journal.source_version, journal.accepted_at, journal.submitted_item_count
	FROM (
		SELECT hosts.id, hosts.ip, hosts.created_at FROM hosts
		WHERE hosts.ip = ? AND hosts.owner_subject_id = ? AND hosts.deleted_at IS NULL
		ORDER BY hosts.id ASC LIMIT 1
	) AS target_host
	LEFT JOIN LATERAL (
		SELECT entry.id AS report_id, entry.source, entry.source_version, entry.scan_time AS accepted_at,
			entry.findings_count AS submitted_item_count
		FROM scan_history_entries AS entry
		WHERE entry.host_id = target_host.id AND entry.deleted_at IS NULL
			AND ((entry.scan_time, entry.id) < (?, ?) OR entry.scan_time IS NULL)
		ORDER BY entry.scan_time DESC NULLS LAST, entry.id DESC
		LIMIT ?
	) AS journal ON TRUE
	ORDER BY journal.accepted_at DESC NULLS LAST, journal.report_id DESC`

func journalPostgresFixture(t *testing.T) (*HostRepository, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("SIRIUS_REPORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_REPORT_TEST_DSN to disposable PostgreSQL")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("journal_test_%d", time.Now().UnixNano())
	cfg.RuntimeParams["search_path"] = schema
	pool := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = pool.Close() })
	db, err := gorm.Open(pgdriver.New(pgdriver.Config{Conn: pool}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Error(err)
		}
	})
	if err := migrate.Up(db); err != nil {
		t.Fatal(err)
	}
	return &HostRepository{db: db}, pool
}

func TestAcceptedReportHistoryPostgresPlans(t *testing.T) {
	repo, pool := journalPostgresFixture(t)
	db := repo.db
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db = db.WithContext(ctx)

	var applyIndex func(*gorm.DB) error
	for _, step := range migrate.Migrations() {
		if step.Version == "012_scan_history_journal" {
			applyIndex = step.Apply
			break
		}
	}
	if applyIndex == nil {
		t.Fatal("missing journal migration")
	}

	for _, query := range []string{
		"DROP INDEX " + journalIndex, // Isolated schema. Recreate via the real migration for the after plans.
		`INSERT INTO hosts (id, owner_subject_id, ip, h_id)
			SELECT g, CASE g WHEN 1 THEN 'alice' WHEN 2 THEN 'bob' ELSE 'fixture' END,
				CASE WHEN g <= 2 THEN '192.0.2.1' ELSE '198.51.100.' || g END,
				'fixture-' || g
			FROM generate_series(1, 8) AS seq(g)`,
		`INSERT INTO scan_history_entries (host_id, source, source_version, scan_time, findings_count, deleted_at)
			SELECT (g - 1) % 8 + 1, 'fixture', 'v1',
				CASE WHEN batch % 20 <> 0 THEN TIMESTAMPTZ '2025-01-01' + (batch / 4) * INTERVAL '1 second' END,
				batch % 7, CASE WHEN batch % 17 = 0 THEN TIMESTAMPTZ '2026-01-01' END
			FROM generate_series(1, 800000) AS seq(g)
			CROSS JOIN LATERAL (SELECT (g - 1) / 8 AS batch) AS b`,
		"ANALYZE hosts, scan_history_entries",
	} {
		if err := db.Exec(query).Error; err != nil {
			t.Fatal(err)
		}
	}

	const ip, limit = "192.0.2.1", 20
	alice := scope.ForSubject("alice")
	cursorAt := func(query string) *acceptedReportCursor {
		t.Helper()
		cursor := acceptedReportCursor{HostID: 1}
		if err := db.Raw(query).Scan(&cursor).Error; err != nil || cursor.ReportID == 0 {
			t.Fatalf("fixture cursor = %+v, error = %v", cursor, err)
		}
		return &cursor
	}
	dated := cursorAt(`SELECT id AS report_id, scan_time AS accepted_at FROM scan_history_entries
		WHERE host_id = 1 AND deleted_at IS NULL AND scan_time IS NOT NULL
		ORDER BY scan_time DESC, id DESC OFFSET 80000 LIMIT 1`)
	tail := cursorAt(`SELECT id AS report_id, scan_time AS accepted_at FROM scan_history_entries
		WHERE host_id = 1 AND deleted_at IS NULL AND scan_time IS NOT NULL
		ORDER BY scan_time ASC, id ASC LIMIT 1`)
	undated := cursorAt(`SELECT id AS report_id FROM scan_history_entries
		WHERE host_id = 1 AND deleted_at IS NULL AND scan_time IS NULL
		ORDER BY id DESC OFFSET 2000 LIMIT 1`)

	cases := []struct {
		name     string
		position *acceptedReportCursor
		seeks    []string
	}{
		{"first", nil, []string{"host_id ="}},
		{"deep_dated", dated, []string{"ROW(", "scan_time IS NULL"}},
		{"null_tail", tail, []string{"ROW(", "scan_time IS NULL"}},
		{"deep_undated", undated, []string{"scan_time IS NULL", "id <"}},
	}

	plansAndPages := func(before bool) []AcceptedReportHistoryPage {
		t.Helper()
		pages := make([]AcceptedReportHistoryPage, 0, len(cases))
		for _, tc := range cases {
			query := func(db *gorm.DB) *gorm.DB {
				if before && tc.position != nil && tc.position.AcceptedAt != nil {
					return db.Raw(baselineDatedJournal, ip, alice.OwnerSubjectID, *tc.position.AcceptedAt, tc.position.ReportID, limit+1)
				}
				return acceptedReportHistoryQuery(db, alice, ip, limit, tc.position)
			}
			var rows []acceptedReportHistoryRow
			stmt := query(db.Session(&gorm.Session{DryRun: true})).Find(&rows).Statement
			plan := explainJournalQuery(t, ctx, pool, stmt)
			t.Logf("before=%t %s\n%s", before, tc.name, plan)
			if !before {
				if !strings.Contains(plan, "Index Scan using "+journalIndex) {
					t.Errorf("%s did not use the journal index", tc.name)
				}
				for _, seek := range tc.seeks {
					found := false
					for _, line := range strings.Split(plan, "\n") {
						if strings.Contains(line, "Index Cond:") && strings.Contains(line, seek) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("%s missing seek condition %q", tc.name, seek)
					}
				}
			}
			if err := query(db).Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			page, err := projectAcceptedReportHistory(rows, limit, tc.position)
			if err != nil || len(page.Reports) != limit || page.NextCursor == "" {
				t.Fatalf("%s page = %+v, error = %v", tc.name, page, err)
			}
			pages = append(pages, page)
		}
		return pages
	}

	before := plansAndPages(true)
	if err := db.Transaction(applyIndex); err != nil {
		t.Fatal(err)
	}
	after := plansAndPages(false)
	for i := range cases {
		if !reflect.DeepEqual(before[i], after[i]) {
			t.Errorf("%s page or cursor changed\nbefore = %+v\nafter = %+v", cases[i].name, before[i], after[i])
		}
	}
}

func explainJournalQuery(t *testing.T, ctx context.Context, pool *sql.DB, stmt *gorm.Statement) string {
	t.Helper()
	rows, err := pool.QueryContext(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+stmt.SQL.String(), stmt.Vars...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func TestAcceptedReportHistoryCancelsRelationLockWait(t *testing.T) {
	repo, _ := journalPostgresFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db := repo.db.WithContext(ctx)
	if err := db.Exec(`INSERT INTO hosts (owner_subject_id, ip, h_id) VALUES ('alice', '192.0.2.1', 'fixture')`).Error; err != nil {
		t.Fatal(err)
	}

	holder := db.Begin()
	if holder.Error != nil {
		t.Fatal(holder.Error)
	}
	t.Cleanup(func() { _ = holder.Rollback().Error })
	if err := holder.Exec("LOCK TABLE scan_history_entries IN ACCESS EXCLUSIVE MODE").Error; err != nil {
		t.Fatal(err)
	}

	alice := scope.ForSubject("alice")
	readCtx, stopRead := context.WithCancel(ctx)
	defer stopRead()
	result := make(chan error, 1)
	go func() {
		_, err := repo.ListAcceptedReportHistory(readCtx, alice, "192.0.2.1", 20, "")
		result <- err
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for waiting := false; !waiting; {
		if err := db.Raw(`SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation = 'scan_history_entries'::regclass
			AND mode = 'AccessShareLock' AND NOT granted)`).Scan(&waiting).Error; err != nil {
			t.Fatal(err)
		}
		if !waiting {
			select {
			case err := <-result:
				t.Fatalf("history read finished before the lock wait: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-ticker.C:
			}
		}
	}
	stopRead()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "read accepted report history") {
			t.Fatalf("blocked read error = %v, want wrapped context cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := holder.Rollback().Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ListAcceptedReportHistory(ctx, alice, "192.0.2.1", 20, ""); err != nil {
		t.Fatalf("follow-up read: %v", err)
	}
}
