package host

import (
	"math"
	"testing"
)

// Exercise the same source precedence as preferVulnerabilityObservation with a
// real Postgres JSONB query. Catalog updates from host B must not alter host A.
func TestFindingRiskAggregationsUseSelectedObservation(t *testing.T) {
	cases := []struct {
		name, mutate string
		want         float64
	}{
		{"host isolation and confidence before recency", "", 9.2},
		{"equal confidence selects latest", "UPDATE host_vulnerabilities SET confidence = 0.9 WHERE source = 'beta'", 7.4},
		{"equal confidence and timestamp selects source bytewise", "UPDATE host_vulnerabilities SET confidence = 0.9, last_seen = '2026-01-01' WHERE host_id=1", 9.2},
		{"source tie break is not locale dependent", "UPDATE host_vulnerabilities SET confidence = 0.9, last_seen = '2026-01-01', source = CASE source WHEN 'alpha' THEN 'Zebra' ELSE 'alpha' END WHERE host_id=1", 9.2},
		{"resolved preferred source is ignored", "UPDATE host_vulnerabilities SET status = 'resolved' WHERE source = 'alpha' AND host_id=1", 7.4},
		{"explicit zero never falls back to catalog", "UPDATE host_vulnerabilities SET finding = '{\"vid\":\"CVE-1\",\"riskScore\":0}' WHERE source = 'alpha' AND host_id=1", 0},
		{"omitted zero never falls back to catalog", "UPDATE host_vulnerabilities SET finding = '{\"vid\":\"CVE-1\"}' WHERE source = 'alpha' AND host_id=1", 0},
		{"legacy null snapshot falls back to catalog", "UPDATE host_vulnerabilities SET finding = NULL WHERE host_id=1", 2.1},
		{"legacy null confidence compares as zero", "UPDATE host_vulnerabilities SET confidence = CASE source WHEN 'alpha' THEN NULL ELSE 0 END WHERE host_id=1", 7.4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := aggregationFixture(t)
			for _, q := range []string{
				"DELETE FROM host_vulnerabilities",
				"UPDATE vulnerabilities SET risk_score = 2.1 WHERE id=1",
				`INSERT INTO host_vulnerabilities (host_id,vulnerability_id,source,status,confidence,last_seen,finding) VALUES
     (1,1,'alpha','active',0.9,'2026-01-01','{"vid":"CVE-1","riskScore":9.2}'),
     (1,1,'beta','active',0.7,'2026-02-01','{"vid":"CVE-1","riskScore":7.4}'),
     (4,1,'alpha','active',0.9,'2026-03-01','{"vid":"CVE-1","riskScore":2.1}'),
     (3,1,'deleted-host','active',1,'2026-04-01','{"vid":"CVE-1","riskScore":10}')`,
			} {
				if err := db.Exec(q).Error; err != nil {
					t.Fatal(err)
				}
			}
			if tc.mutate != "" {
				if err := db.Exec(tc.mutate).Error; err != nil {
					t.Fatal(err)
				}
			}
			var risk HostRiskStats
			if err := hostRiskStatisticsQuery(db, "192.0.2.1").Scan(&risk).Error; err != nil {
				t.Fatal(err)
			}
			if risk.VulnerabilityCount != 1 || math.Abs(risk.TotalRiskScore-tc.want) > 1e-9 || math.Abs(risk.AverageRiskScore-tc.want) > 1e-9 {
				t.Fatalf("risk=%+v, want one finding at %v", risk, tc.want)
			}
			var severity HostVulnerabilitySeverityCounts
			if err := hostSeverityCountsQuery(db, "192.0.2.1").Scan(&severity).Error; err != nil {
				t.Fatal(err)
			}
			wantSeverity := HostVulnerabilitySeverityCounts{}
			switch {
			case tc.want >= 9:
				wantSeverity.Critical = 1
			case tc.want >= 7:
				wantSeverity.High = 1
			case tc.want >= 4:
				wantSeverity.Medium = 1
			case tc.want > 0:
				wantSeverity.Low = 1
			default:
				wantSeverity.Informational = 1
			}
			if severity != wantSeverity {
				t.Fatalf("severity=%+v, want %+v", severity, wantSeverity)
			}
			var ranking []HostVulnerabilityStats
			if err := mostVulnerableHostsQuery(db, 10).Scan(&ranking).Error; err != nil {
				t.Fatal(err)
			}
			if len(ranking) != 2 {
				t.Fatalf("ranked hosts=%+v", ranking)
			}
			for _, row := range ranking {
				want := tc.want
				if row.HostIP == "192.0.2.4" {
					want = 2.1
				}
				if row.TotalVulnerabilities != 1 || math.Abs(row.WeightedRiskScore-want) > 1e-9 {
					t.Fatalf("ranking=%+v, expected %v", row, want)
				}
			}
		})
	}
}
