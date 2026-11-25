package host

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/scope"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestAcceptedReportHistoryQuery(t *testing.T) {
	db, err := gorm.Open(pgdriver.Open("host=127.0.0.1 port=1 user=fixture dbname=fixture sslmode=disable"),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	scoped := scope.ForSubject("alice")
	when := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	const ip = "192.0.2.1"
	for _, tc := range []struct {
		name         string
		position     *acceptedReportCursor
		clauses      []string
		journalReads int
		args         []any
	}{
		{"first page", nil, nil, 1, []any{ip, scoped.OwnerSubjectID, 1, 3}},
		{"timed cursor", &acceptedReportCursor{ReportID: 8, AcceptedAt: &when}, []string{
			"(entry.scan_time, entry.id) < ($4, $5) ORDER BY entry.scan_time DESC NULLS LAST, entry.id DESC LIMIT $6",
			"UNION ALL",
			"entry.scan_time IS NULL ORDER BY entry.scan_time DESC NULLS LAST, entry.id DESC LIMIT $7",
			"ORDER BY candidate.accepted_at DESC NULLS LAST, candidate.report_id DESC LIMIT $8",
		}, 2, []any{ip, scoped.OwnerSubjectID, 1, when, uint(8), 3, 3, 3}},
		{"undated cursor", &acceptedReportCursor{ReportID: 8}, []string{
			"entry.scan_time IS NULL AND entry.id < $4",
		}, 1, []any{ip, scoped.OwnerSubjectID, 1, uint(8), 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows []acceptedReportHistoryRow
			statement := acceptedReportHistoryQuery(db, scoped, ip, 2, tc.position).Find(&rows).Statement
			sql := strings.ReplaceAll(statement.SQL.String(), `"`, "")
			for _, part := range append([]string{
				"hosts.ip = $1 AND hosts.owner_subject_id = $2",
				"hosts.deleted_at IS NULL",
				"ORDER BY hosts.id ASC LIMIT $3",
				"LEFT JOIN LATERAL",
				"entry.host_id = target_host.id AND entry.deleted_at IS NULL",
				"entry.findings_count AS submitted_item_count",
				"ORDER BY entry.scan_time DESC NULLS LAST, entry.id DESC LIMIT ",
				"ORDER BY journal.accepted_at DESC NULLS LAST, journal.report_id DESC",
			}, tc.clauses...) {
				if !strings.Contains(sql, part) {
					t.Errorf("query missing %q: %s", part, sql)
				}
			}
			if got := strings.Count(sql, "entry.host_id = target_host.id AND entry.deleted_at IS NULL"); got != tc.journalReads {
				t.Errorf("scoped journal reads = %d, want %d: %s", got, tc.journalReads, sql)
			}
			if !slices.Equal(statement.Vars, tc.args) {
				t.Errorf("bound parameters = %#v, want %#v", statement.Vars, tc.args)
			}
			for _, column := range []string{"scan_config", "notes", "host_ports", "host_vulnerabilities"} {
				if strings.Contains(sql, column) {
					t.Errorf("query includes unrelated data %q: %s", column, sql)
				}
			}
		})
	}
}

func TestAcceptedReportHistoryPageProjection(t *testing.T) {
	when := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	newID, oldID, zero := uint(2), uint(1), 0
	rows := []acceptedReportHistoryRow{
		{HostID: 9, HostIP: "192.0.2.1", ReportID: &newID, Source: "fixture", SourceVersion: "v2", AcceptedAt: &when, SubmittedItemCount: &zero},
		{HostID: 9, HostIP: "192.0.2.1", ReportID: &oldID},
	}
	page, err := projectAcceptedReportHistory(rows, 1, nil)
	if err != nil || len(page.Reports) != 1 {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
	cursor, err := decodeAcceptedReportCursor(page.NextCursor)
	if err != nil || cursor == nil || cursor.HostID != 9 || cursor.ReportID != newID || cursor.AcceptedAt == nil || !cursor.AcceptedAt.Equal(when) {
		t.Fatalf("cursor = %+v, err = %v", cursor, err)
	}
	if _, err := projectAcceptedReportHistory(rows, 2, &acceptedReportCursor{HostID: 8}); !errors.Is(err, ErrInvalidAcceptedReportPage) {
		t.Fatalf("cross-host cursor error = %v", err)
	}
	page, err = projectAcceptedReportHistory(rows, 2, nil)
	if err != nil || len(page.Reports) != 2 || page.NextCursor != "" {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
	body, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"submitted_item_count":0`, `"submitted_item_count":null`, `"accepted_at":null`,
		`"source":"fixture"`, `"source_version":"v2"`,
	} {
		if !strings.Contains(string(body), field) {
			t.Errorf("page missing %s: %s", field, body)
		}
	}
	if strings.Count(string(body), `"assessment_coverage":"unknown"`) != 2 {
		t.Errorf("coverage = %s", body)
	}

	empty, err := projectAcceptedReportHistory([]acceptedReportHistoryRow{{HostID: 9}}, 2, nil)
	if err != nil || empty.Reports == nil || len(empty.Reports) != 0 || empty.NextCursor != "" {
		t.Fatalf("empty history = %+v, err = %v", empty, err)
	}
	if _, err := projectAcceptedReportHistory(nil, 2, nil); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing host error = %v", err)
	}
}

func TestAcceptedReportHistoryValidatesBeforeDatabase(t *testing.T) {
	repo := &HostRepository{}
	ctx := context.Background()
	for _, request := range []struct {
		limit  int
		cursor string
	}{
		{0, ""},
		{MaxAcceptedReportLimit + 1, ""},
		{2, "not a base64 cursor"},
		{2, strings.Repeat("a", maxAcceptedReportCursorLength+1)},
		{2, "e30"}, // base64url for an empty JSON object
	} {
		if _, err := repo.ListAcceptedReportHistory(ctx, scope.Global(), "192.0.2.1", request.limit, request.cursor); !errors.Is(err, ErrInvalidAcceptedReportPage) {
			t.Fatalf("invalid page request returned %v", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := repo.ListAcceptedReportHistory(canceled, scope.Global(), "192.0.2.1", 2, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request returned %v", err)
	}
}

func TestAcceptedReportHistoryPostgres(t *testing.T) {
	repo := reportFixture(t)
	ctx := context.Background()
	alice, bob := scope.ForSubject("alice"), scope.ForSubject("bob")
	const ip = "192.0.2.1"
	for _, q := range []string{
		`INSERT INTO hosts (id, owner_subject_id, ip, created_at, deleted_at) VALUES
			(1, 'alice', '192.0.2.1', '2026-11-23 15:00:00+00', NULL),
			(2, 'bob', '192.0.2.1', NULL, NULL),
			(3, 'alice', '192.0.2.2', NULL, NULL),
			(4, 'alice', '192.0.2.3', NULL, '2026-11-23 15:00:00+00')`,
		`INSERT INTO scan_history_entries
			(id, host_id, source, source_version, scan_time, findings_count, scan_config, notes, deleted_at) VALUES
			(1, 1, 'empty', 'v1', '2026-11-24 18:00:00+00', 0, 'config-fixture', 'notes-fixture', NULL),
			(2, 1, 'network', 'v2', '2026-11-24 18:00:00+00', 3, NULL, NULL, NULL),
			(3, 2, 'agent', 'v3', '2026-11-24 19:00:00+00', 99, NULL, NULL, NULL),
			(4, 1, 'deleted', 'v4', '2026-11-24 19:00:00+00', 1, NULL, NULL, '2026-11-24 20:00:00+00'),
			(5, 4, 'deleted-host', 'v5', '2026-11-24 19:00:00+00', 1, NULL, NULL, NULL),
			(6, 1, 'historical', 'v6', NULL, NULL, NULL, NULL, NULL),
			(7, 1, 'undated', 'v7', NULL, 4, NULL, NULL, NULL),
			(8, 1, 'earlier', 'v8', '2026-11-24 17:00:00+00', 2, NULL, NULL, NULL)`,
	} {
		if err := repo.db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}

	read := func(s scope.ResourceScope, cursor string, ids ...uint) AcceptedReportHistoryPage {
		t.Helper()
		page, err := repo.ListAcceptedReportHistory(ctx, s, ip, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]uint, 0, len(page.Reports))
		for _, report := range page.Reports {
			got = append(got, report.ID)
			if report.AssessmentCoverage != "unknown" {
				t.Fatalf("coverage = %q", report.AssessmentCoverage)
			}
		}
		if !slices.Equal(got, ids) {
			t.Fatalf("report IDs = %v, want %v", got, ids)
		}
		return page
	}

	first := read(alice, "", 2, 1)
	if first.NextCursor == "" || first.HostID != 1 || first.HostIP != ip || first.HostCreatedAt == nil {
		t.Fatalf("first page = %+v", first)
	}
	emptyReport := first.Reports[1]
	if emptyReport.SubmittedItemCount == nil || *emptyReport.SubmittedItemCount != 0 || emptyReport.AcceptedAt == nil ||
		emptyReport.AcceptedAt.Format(time.RFC3339) != "2026-11-24T18:00:00Z" || emptyReport.Source != "empty" || emptyReport.SourceVersion != "v1" {
		t.Fatalf("zero-item report = %+v", emptyReport)
	}
	second := read(alice, first.NextCursor, 8, 7)
	if second.NextCursor == "" || second.Reports[1].AcceptedAt != nil {
		t.Fatalf("second page = %+v", second)
	}
	third := read(alice, second.NextCursor, 6)
	if third.NextCursor != "" || third.Reports[0].SubmittedItemCount != nil {
		t.Fatalf("third page = %+v", third)
	}
	read(bob, "", 3)

	empty, err := repo.ListAcceptedReportHistory(ctx, alice, "192.0.2.2", 2, "")
	if err != nil || empty.Reports == nil || len(empty.Reports) != 0 {
		t.Fatalf("empty history = %+v, err = %v", empty, err)
	}
	if _, err := repo.ListAcceptedReportHistory(ctx, alice, "192.0.2.2", 2, first.NextCursor); !errors.Is(err, ErrInvalidAcceptedReportPage) {
		t.Fatalf("cross-host cursor error = %v", err)
	}
	if _, err := repo.ListAcceptedReportHistory(ctx, scope.Global(), ip, 2, ""); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("cross-scope read error = %v", err)
	}
	if _, err := repo.ListAcceptedReportHistory(ctx, alice, "192.0.2.3", 2, ""); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("deleted host read error = %v", err)
	}

	if err := repo.db.Exec("DROP TABLE scan_history_entries").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ListAcceptedReportHistory(ctx, alice, ip, 2, ""); err == nil || errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("database failure returned %v", err)
	}
}
