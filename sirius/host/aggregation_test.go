package host

import (
	"math"
	"os"
	"strings"
	"testing"

	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestAggregationQueriesStaySourceNeutral(t *testing.T) {
	db, err := gorm.Open(pgdriver.Open("host=127.0.0.1 port=1 dbname=unused sslmode=disable"), &gorm.Config{
		DryRun: true, DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := map[string]*gorm.DB{
		"risk":     hostRiskStatisticsQuery(db, "192.0.2.1"),
		"severity": hostSeverityCountsQuery(db, "192.0.2.1"),
		"summary":  vulnerabilitySummariesQuery(db),
		"ranking":  mostVulnerableHostsQuery(db, 10),
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			stmt := query.Find(&[]map[string]interface{}{}).Statement
			sql := stmt.SQL.String()
			for _, required := range []string{
				"SELECT DISTINCT ON (host_id, vulnerability_id) host_id, vulnerability_id, finding", "status = $1",
				"hosts.deleted_at IS NULL", "vulnerabilities.deleted_at IS NULL",
			} {
				if !strings.Contains(sql, required) {
					t.Errorf("query missing %q: %s", required, sql)
				}
			}
			if len(stmt.Vars) == 0 || stmt.Vars[0] != "active" {
				t.Fatalf("query must bind active status: %v", stmt.Vars)
			}
			if strings.Contains(strings.ToUpper(sql), "SUM(DISTINCT") {
				t.Fatal("equal risk scores must not be deduplicated")
			}
		})
	}
}

// These integration tests use only temporary tables on an explicit connection.
// SIRIUS_AGGREGATION_TEST_DSN must point to a disposable Postgres instance. No
// postgres.GetDB call, migrations, or persistent table writes are involved.
func aggregationFixture(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("SIRIUS_AGGREGATION_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_AGGREGATION_TEST_DSN to a disposable Postgres instance")
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
		`CREATE TEMP TABLE hosts (id bigint PRIMARY KEY, h_id text, ip text, hostname text, updated_at timestamp, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE vulnerabilities (id bigint PRIMARY KEY, v_id text, title text, description text, risk_score double precision, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE host_vulnerabilities (host_id bigint, vulnerability_id bigint, source text, status text, confidence double precision, last_seen timestamp, finding jsonb) ON COMMIT DROP`,
		`INSERT INTO hosts (id, h_id, ip, hostname, updated_at, deleted_at) VALUES
		 (1, 'a', '192.0.2.1', 'active', now(), NULL),
		 (2, 'b', '192.0.2.2', 'inactive', now(), NULL),
		 (3, 'c', '192.0.2.3', 'deleted', now(), now()),
		 (4, NULL, '192.0.2.4', 'shared', now(), NULL),
		 (5, 'e', '192.0.2.5', 'only deleted CVE', now(), NULL),
		 (6, 'f', '192.0.2.6', 'empty', now(), NULL)`,
		`INSERT INTO vulnerabilities (id, v_id, title, description, risk_score) VALUES
		 (1, 'CVE-1', 'one', 'one', 9.8), (2, 'CVE-2', 'two', 'two', 9.8),
		 (3, 'CVE-3', 'high min', '', 7), (4, 'CVE-4', 'medium min', '', 4),
		 (5, 'CVE-5', 'low min', '', 0.1), (6, 'CVE-6', 'informational', '', 0),
		 (7, 'CVE-7', 'critical min', '', 9), (8, 'CVE-8', 'high max', '', 8.9),
		 (9, 'CVE-9', 'medium max', '', 6.9), (10, 'CVE-10', 'low max', '', 3.9),
		 (11, 'CVE-DELETED', '', '', 10), (12, 'CVE-INACTIVE', '', '', 10),
		 (13, 'CVE-NULL-STATUS', '', '', 10), (14, 'CVE-UNOBSERVED', '', '', 10)`,
		`UPDATE vulnerabilities SET deleted_at = now() WHERE id = 11`,
		`INSERT INTO host_vulnerabilities (host_id, vulnerability_id, source, status) VALUES
		 (1,1,'nmap','active'), (1,1,'agent','active'), (1,1,'manual','resolved'),
		 (1,2,'nmap','active'), (1,2,'agent','false_positive'),
		 (1,3,'nmap','active'), (1,4,'nmap','active'), (1,5,'nmap','active'),
		 (1,6,'nmap','active'), (1,7,'nmap','active'), (1,8,'nmap','active'),
		 (1,9,'nmap','active'), (1,10,'nmap','active'), (1,11,'nmap','active'),
		 (1,12,'nmap','resolved'), (1,12,'agent','false_positive'), (1,13,'nmap',NULL),
		 (2,1,'nmap','resolved'), (2,1,'agent','false_positive'), (2,2,'nmap','inactive'),
		 (3,1,'nmap','active'), (4,1,'nmap','active'), (4,1,'agent','active'),
		 (4,2,'nmap','active'), (5,11,'nmap','active'), (999,1,'nmap','active')`,
	} {
		if err := tx.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

func TestCurrentFindingAggregations(t *testing.T) {
	db := aggregationFixture(t)
	t.Run("risk counts identities rather than sources or scores", func(t *testing.T) {
		var got HostRiskStats
		if err := hostRiskStatisticsQuery(db, "192.0.2.1").Scan(&got).Error; err != nil {
			t.Fatal(err)
		}
		if got.VulnerabilityCount != 10 || math.Abs(got.TotalRiskScore-59.4) > 1e-9 || math.Abs(got.AverageRiskScore-5.94) > 1e-9 {
			t.Fatalf("unexpected statistics: %+v", got)
		}
	})
	t.Run("severity boundaries", func(t *testing.T) {
		var got HostVulnerabilitySeverityCounts
		if err := hostSeverityCountsQuery(db, "192.0.2.1").Scan(&got).Error; err != nil {
			t.Fatal(err)
		}
		want := HostVulnerabilitySeverityCounts{Critical: 3, High: 2, Medium: 2, Low: 2, Informational: 1}
		if got != want {
			t.Fatalf("severity = %+v, want %+v", got, want)
		}
	})
	t.Run("inactive deleted empty and missing hosts return zero", func(t *testing.T) {
		for _, ip := range []string{"192.0.2.2", "192.0.2.3", "192.0.2.5", "192.0.2.6", "192.0.2.99"} {
			var risk HostRiskStats
			var severity HostVulnerabilitySeverityCounts
			if err := hostRiskStatisticsQuery(db, ip).Scan(&risk).Error; err != nil {
				t.Fatal(err)
			}
			if err := hostSeverityCountsQuery(db, ip).Scan(&severity).Error; err != nil {
				t.Fatal(err)
			}
			if risk.VulnerabilityCount != 0 || risk.TotalRiskScore != 0 || risk.AverageRiskScore != 0 || severity != (HostVulnerabilitySeverityCounts{}) {
				t.Errorf("%s returned risk=%+v severity=%+v", ip, risk, severity)
			}
		}
	})
	t.Run("summary counts affected hosts and retains multi-host CVEs", func(t *testing.T) {
		var got []VulnerabilitySummary
		if err := vulnerabilitySummariesQuery(db).Scan(&got).Error; err != nil {
			t.Fatal(err)
		}
		if len(got) != 10 {
			t.Fatalf("got %d CVEs, want 10: %+v", len(got), got)
		}
		for _, row := range got {
			want := 1
			if row.VID == "CVE-1" || row.VID == "CVE-2" {
				want = 2
			}
			if row.HostCount != want || strings.Contains(row.VID, "DELETED") || strings.Contains(row.VID, "INACTIVE") {
				t.Errorf("unexpected summary: %+v", row)
			}
		}
	})
	t.Run("ranking excludes inactive and deleted findings", func(t *testing.T) {
		var got []HostVulnerabilityStats
		if err := mostVulnerableHostsQuery(db, 10).Scan(&got).Error; err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].HostID != "a" || got[1].HostID != "192.0.2.4" {
			t.Fatalf("unexpected ranked hosts: %+v", got)
		}
		for i, row := range got {
			var risk HostRiskStats
			if err := hostRiskStatisticsQuery(db, row.HostIP).Scan(&risk).Error; err != nil {
				t.Fatal(err)
			}
			if row.TotalVulnerabilities != risk.VulnerabilityCount || math.Abs(row.WeightedRiskScore-risk.TotalRiskScore) > 1e-9 {
				t.Errorf("ranking %d disagrees with host risk: %+v vs %+v", i, row, risk)
			}
		}
		for _, limit := range []int{0, 1} {
			got = nil
			if err := mostVulnerableHostsQuery(db, limit).Scan(&got).Error; err != nil {
				t.Fatal(err)
			}
			if len(got) != limit {
				t.Errorf("limit %d returned %d hosts", limit, len(got))
			}
		}
	})
}
