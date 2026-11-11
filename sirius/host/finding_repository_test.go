package host

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

func TestFindingModelAndZeroJSON(t *testing.T) {
	s, err := schema.Parse(&models.HostVulnerability{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	f := s.LookUpField("Finding")
	if f == nil || !f.IgnoreMigration || !f.Readable || !f.Creatable {
		t.Fatalf("finding must be ledger owned: %+v", f)
	}
	b, err := json.Marshal(sirius.Vulnerability{VID: "TEST", Confidence: 0})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if value, ok := got["confidence"]; !ok || value != float64(0) {
		t.Fatalf("zero confidence lost: %s", b)
	}
}

func findingFixture(t *testing.T) *HostRepository {
	t.Helper()
	dsn := os.Getenv("SIRIUS_FINDING_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_FINDING_TEST_DSN to a disposable Postgres instance")
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
		`CREATE TEMP TABLE hosts (id bigint PRIMARY KEY, owner_subject_id text NOT NULL DEFAULT '', h_id text, ip text, hostname text, os text, os_version text, agent_id bigint,
          software_inventory jsonb, system_fingerprint jsonb, agent_metadata jsonb, created_at timestamp, updated_at timestamp, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE ports (id bigint PRIMARY KEY, number int, protocol text, state text, created_at timestamp, updated_at timestamp, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE host_ports (host_id bigint, port_id bigint, source text, source_version text, first_seen timestamp, last_seen timestamp, status text, notes text, state text) ON COMMIT DROP`,
		`CREATE TEMP TABLE vulnerabilities (id bigserial PRIMARY KEY, v_id text UNIQUE, title text, description text, risk_score double precision, created_at timestamp, updated_at timestamp, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE host_vulnerabilities (host_id bigint REFERENCES hosts(id), vulnerability_id bigint REFERENCES vulnerabilities(id), source text,
          source_version text, first_seen timestamp, last_seen timestamp, status text, confidence double precision DEFAULT 1.0, port int, service_info text, notes text, finding jsonb,
          PRIMARY KEY(host_id,vulnerability_id,source)) ON COMMIT DROP`,
		`INSERT INTO hosts (id,h_id,ip,hostname,os,os_version,agent_id,created_at,updated_at) VALUES
          (1,'a','192.0.2.1','','','',0,now(),now()),(2,'b','192.0.2.2','','','',0,now(),now())`,
	} {
		if err := tx.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	return &HostRepository{db: tx}
}

func fullFinding() sirius.Vulnerability {
	return sirius.Vulnerability{VID: "CVE-TEST-9", Title: "source title", Description: "source evidence", RiskScore: 7.5,
		CVEID: "CVE-TEST-9", CVSSScore: 7.5, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Severity: "high", Remediation: "Install the vendor patch", Category: "CWE-79", Tags: []string{"template", "web"}, Confidence: 0.87321,
		Metadata: map[string]interface{}{"references": []string{"https://example.test/advisory"}, "template_id": "test-template", "evidence": map[string]interface{}{"path": "/synthetic"}},
	}
}

func requireSameFinding(t *testing.T, got, want sirius.Vulnerability) {
	t.Helper()
	a, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("finding changed:\n got %s\nwant %s", a, b)
	}
}

func TestFindingRoundTripIsolationAndSelection(t *testing.T) {
	repo := findingFixture(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	finding := fullFinding()
	must(repo.UpsertHostVulnerability(1, finding, models.ScanSource{Name: "agent", Version: "1", Config: "one"}))
	other := finding
	other.Title = "other host"
	other.Description = "other evidence"
	other.Confidence = 0.97
	other.Metadata = map[string]interface{}{"references": []string{"https://example.test/other"}}
	must(repo.UpsertHostVulnerability(2, other, models.ScanSource{Name: "agent"}))
	lower := finding
	lower.Title = "lower confidence"
	lower.Confidence = 0.25
	lower.Remediation = "different action"
	must(repo.UpsertHostVulnerability(1, lower, models.ScanSource{Name: "nmap"}))
	// Recency must not defeat higher confidence; do not mix fields across sources.
	must(repo.db.Exec("UPDATE host_vulnerabilities SET last_seen=? WHERE source='nmap'", time.Now().Add(time.Hour)).Error)
	for ip, want := range map[string]sirius.Vulnerability{"192.0.2.1": finding, "192.0.2.2": other} {
		h, err := repo.GetHostWithRelations(ip)
		must(err)
		got := convertHostWithRelationsToSiriusHost(h)
		if len(got.Vulnerabilities) != 1 {
			t.Fatalf("host=%+v", got)
		}
		requireSameFinding(t, got.Vulnerabilities[0], want)
		if _, err := json.Marshal(got); err != nil {
			t.Fatal(err)
		}
	}
	sources, err := repo.getVulnerabilitySources(1)
	must(err)
	if len(sources) != 2 || sources[0].Finding == nil || sources[1].Finding == nil {
		t.Fatalf("sources=%+v", sources)
	}
	if sources[0].Title != finding.Title || sources[1].Title != lower.Title {
		t.Fatal("legacy source fields mixed evidence")
	}
	requireSameFinding(t, *sources[0].Finding, finding)
	requireSameFinding(t, *sources[1].Finding, lower)
	if sources[0].Confidence != finding.Confidence {
		t.Fatalf("confidence rounded: %.10f", sources[0].Confidence)
	}
	if _, err := json.Marshal(sources); err != nil {
		t.Fatal(err)
	}
	// Inactive evidence remains available in the source-aware response, not the canonical list.
	must(repo.db.Exec("UPDATE host_vulnerabilities SET status='resolved' WHERE host_id=1 AND source='agent'").Error)
	rels, err := repo.getVulnerabilityRelations(1)
	must(err)
	if len(rels) != 1 {
		t.Fatalf("relations=%+v", rels)
	}
	requireSameFinding(t, vulnerabilityFromRelation(rels[0]), lower)
	sources, err = repo.getVulnerabilitySources(1)
	must(err)
	if len(sources) != 2 {
		t.Fatalf("resolved source lost: %+v", sources)
	}
}

func TestFindingUpdateLegacyAndZeroConfidence(t *testing.T) {
	repo := findingFixture(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	source := models.ScanSource{Name: "agent", Version: "1"}
	finding := fullFinding()
	must(repo.UpsertHostVulnerability(1, finding, source))
	var before models.HostVulnerability
	must(repo.db.First(&before).Error)
	finding.Confidence = 0
	finding.Tags = nil
	finding.Remediation = ""
	finding.Metadata = nil
	finding.RiskScore = 0
	source.Version = "2"
	source.Config = "two"
	must(repo.UpsertHostVulnerability(1, finding, source))
	var after models.HostVulnerability
	must(repo.db.First(&after).Error)
	if !before.FirstSeen.Equal(after.FirstSeen) || after.LastSeen.Before(before.LastSeen) || after.SourceVersion != "2" || after.Notes != "two" || after.Confidence != 0 {
		t.Fatalf("attribution before=%+v after=%+v", before, after)
	}
	// A legacy touch must preserve modern evidence, including valid zero confidence.
	must(repo.LinkHostVulnerability(1, after.VulnerabilityID, source))
	rels, err := repo.getVulnerabilityRelations(1)
	must(err)
	requireSameFinding(t, vulnerabilityFromRelation(rels[0]), finding)
	must(repo.LinkHostVulnerability(2, after.VulnerabilityID, models.ScanSource{}))
	legacy, err := repo.getVulnerabilityRelations(2)
	must(err)
	if len(legacy) != 1 || legacy[0].Finding != nil || legacy[0].Confidence != 1 || legacy[0].Source != "unknown" {
		t.Fatalf("legacy=%+v", legacy)
	}
	if vulnerabilityFromRelation(legacy[0]).Remediation != "" {
		t.Fatal("legacy must not acquire another host's evidence")
	}
}

func TestFindingValidationAndRollback(t *testing.T) {
	repo := findingFixture(t)
	for _, confidence := range []float64{-0.1, 1.1, math.NaN(), math.Inf(1)} {
		finding := fullFinding()
		finding.Confidence = confidence
		if err := repo.UpsertHostVulnerability(1, finding, models.ScanSource{}); err == nil {
			t.Fatalf("accepted confidence %v", confidence)
		}
	}
	bad := fullFinding()
	bad.Metadata = map[string]interface{}{"invalid": make(chan int)}
	if err := repo.UpsertHostVulnerability(1, bad, models.ScanSource{}); err == nil {
		t.Fatal("accepted non-JSON evidence")
	}
	if err := repo.UpsertHostVulnerability(99, fullFinding(), models.ScanSource{}); err == nil {
		t.Fatal("accepted missing host")
	}
	var count int64
	if err := repo.db.Model(&models.Vulnerability{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial catalog write: %d", count)
	}
}

func TestFindingSelectionIsDeterministic(t *testing.T) {
	now := time.Now()
	a := VulnerabilityRelation{Confidence: .8, LastSeen: now, Source: "agent"}
	b := a
	b.Source = "nmap"
	if !preferVulnerabilityObservation(a, b) || preferVulnerabilityObservation(b, a) {
		t.Fatal("source tie breaker unstable")
	}
	b.LastSeen = now.Add(time.Hour)
	if preferVulnerabilityObservation(a, b) || !preferVulnerabilityObservation(b, a) {
		t.Fatal("equal confidence must use latest")
	}
	b.Confidence = .5
	if !preferVulnerabilityObservation(a, b) || preferVulnerabilityObservation(b, a) {
		t.Fatal("recency must not override confidence")
	}
	want := sirius.Vulnerability{VID: "old", Title: "old title", Confidence: .4}
	got := vulnerabilityFromRelation(VulnerabilityRelation{Vulnerability: models.Vulnerability{VID: "old", Title: "old title"}, Confidence: .4})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy fallback=%+v", got)
	}
}

// A separate ephemeral schema permits real concurrent connections while keeping
// all tables isolated from the disposable database's public schema.
func TestFindingConcurrentIngestion(t *testing.T) {
	dsn := os.Getenv("SIRIUS_FINDING_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_FINDING_TEST_DSN to a disposable Postgres instance")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("finding_concurrency_%d", time.Now().UnixNano())
	config.RuntimeParams["search_path"] = name
	pool := stdlib.OpenDB(*config)
	pool.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = pool.Close() })
	db, err := gorm.Open(pgdriver.New(pgdriver.Config{Conn: pool}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE SCHEMA " + name).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Exec("DROP SCHEMA " + name + " CASCADE").Error; err != nil {
			t.Error(err)
		}
	})
	for _, sql := range []string{
		`CREATE TABLE hosts(id bigint PRIMARY KEY)`,
		`INSERT INTO hosts VALUES(1),(2)`,
		`CREATE TABLE vulnerabilities(id bigserial PRIMARY KEY,v_id text UNIQUE,title text,description text,risk_score double precision,created_at timestamp,updated_at timestamp,deleted_at timestamp)`,
		`CREATE TABLE host_vulnerabilities(host_id bigint REFERENCES hosts(id),vulnerability_id bigint REFERENCES vulnerabilities(id),source text,source_version text,first_seen timestamp,last_seen timestamp,status text,confidence double precision,port int,service_info text,notes text,finding jsonb,PRIMARY KEY(host_id,vulnerability_id,source))`,
	} {
		if err := db.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	repo := &HostRepository{db: db}
	const workers = 16
	start := make(chan struct{})
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			<-start
			hostID := uint(1 + i%2)
			source := fmt.Sprintf("source-%d", (i/2)%2)
			finding := fullFinding()
			finding.Description = fmt.Sprintf("host=%d source=%s", hostID, source)
			results <- repo.UpsertHostVulnerability(hostID, finding, models.ScanSource{Name: source})
		}(i)
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	var count int64
	if err := db.Model(&models.Vulnerability{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("catalog rows=%d", count)
	}
	for hostID := uint(1); hostID <= 2; hostID++ {
		sources, err := repo.getVulnerabilitySources(hostID)
		if err != nil {
			t.Fatal(err)
		}
		if len(sources) != 2 {
			t.Fatalf("source rows=%d", len(sources))
		}
		for _, source := range sources {
			expected := fullFinding()
			expected.Description = fmt.Sprintf("host=%d source=%s", hostID, source.Source)
			if source.Finding == nil {
				t.Fatal("missing snapshot")
			}
			requireSameFinding(t, *source.Finding, expected)
		}
	}
}

func TestFindingPreservesNumericEvidence(t *testing.T) {
	repo := findingFixture(t)
	finding := fullFinding()
	finding.Metadata = map[string]interface{}{
		"id":     uint64(9007199254740993),
		"nested": map[string]interface{}{"number": json.Number("18446744073709551615"), "decimal": json.Number("0.12345678901234567890123456789")},
		"array":  []interface{}{json.Number("9007199254740995")},
	}
	if err := repo.UpsertHostVulnerability(1, finding, models.ScanSource{Name: "agent"}); err != nil {
		t.Fatal(err)
	}
	sources, err := repo.getVulnerabilitySources(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].Finding == nil {
		t.Fatal("finding missing")
	}
	requireSameFinding(t, *sources[0].Finding, finding)
	var stored models.HostVulnerability
	if err := repo.db.First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	var value map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(stored.Finding))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value["metadata"].(map[string]interface{})["id"] != json.Number("9007199254740993") {
		t.Fatalf("number changed: %s", stored.Finding)
	}
}
