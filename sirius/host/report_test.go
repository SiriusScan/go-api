package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func sampleReport() Report {
	return Report{Host: sirius.Host{IP: "192.0.2.171", HID: "atomic-fixture", Hostname: "new-host",
		Ports:           []sirius.Port{{Number: 443, Protocol: "tcp", State: "open"}, {Number: 8443, Protocol: "tcp", State: "closed"}},
		Vulnerabilities: []sirius.Vulnerability{{VID: "TEST-ATOMIC-A", Title: "first", Confidence: .9, RiskScore: 9.1}, {VID: "TEST-ATOMIC-Z", Title: "second", Confidence: .5, RiskScore: 5}}},
		Source:            models.ScanSource{Name: "atomic", Version: "v1", Config: "fixture"},
		SoftwareInventory: map[string]interface{}{"packages": []string{"one"}},
		SystemFingerprint: map[string]interface{}{"os": "fixture"},
		AgentMetadata:     map[string]interface{}{"agent": "fixture"},
		Catalog:           []sirius.Vulnerability{{VID: "TEST-ATOMIC-A", Title: "enriched catalog", RiskScore: 8.2}},
	}
}

func TestReportValidationBeforeDatabase(t *testing.T) {
	for name, mutate := range map[string]func(*Report){
		"late confidence":     func(r *Report) { r.Host.Vulnerabilities[1].Confidence = 1.5 },
		"negative confidence": func(r *Report) { r.Host.Vulnerabilities[1].Confidence = -.1 },
		"nan confidence":      func(r *Report) { r.Host.Vulnerabilities[1].Confidence = math.NaN() },
		"missing vid":         func(r *Report) { r.Host.Vulnerabilities[1].VID = " " },
		"nonfinite risk":      func(r *Report) { r.Host.Vulnerabilities[1].RiskScore = math.Inf(1) },
		"invalid metadata":    func(r *Report) { r.Host.Vulnerabilities[1].Metadata = map[string]interface{}{"bad": make(chan int)} },
		"invalid jsonb":       func(r *Report) { r.AgentMetadata["bad"] = make(chan int) },
		"negative port":       func(r *Report) { r.Host.Ports[1].Number = -1 },
		"oversized port":      func(r *Report) { r.Host.Ports[1].Number = 65536 },
		"unrelated catalog":   func(r *Report) { r.Catalog[0].VID = "unrelated" },
	} {
		t.Run(name, func(t *testing.T) {
			r := sampleReport()
			mutate(&r)
			if err := (&HostRepository{}).addReport(r); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("validation must precede db: %v", err)
			}
		})
	}
	for _, confidence := range []float64{0, 1} {
		r := sampleReport()
		r.Host.Vulnerabilities[1].Confidence = confidence
		if err := ValidateReport(r); err != nil {
			t.Fatal(err)
		}
	}
}

// One connection owns temporary tables. The report itself uses real BEGIN /
// COMMIT / ROLLBACK, and pg_temp-only search_path cannot touch installed data.
func reportFixture(t *testing.T) *HostRepository {
	t.Helper()
	dsn := os.Getenv("SIRIUS_REPORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_REPORT_TEST_DSN to disposable PostgreSQL")
	}
	db, err := gorm.Open(pgdriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.Exec("SET search_path TO pg_temp").Error; err != nil {
		t.Fatal(err)
	}
	createReportTables(t, db, true)
	return &HostRepository{db: db}
}

func reportState(t *testing.T, r *HostRepository) map[string]string {
	t.Helper()
	state := map[string]string{}
	for _, table := range []string{"hosts", "ports", "host_ports", "vulnerabilities", "host_vulnerabilities", "scan_history_entries"} {
		var rows string
		if err := r.db.Raw(fmt.Sprintf("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM %s t", table)).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		state[table] = rows
	}
	return state
}

func TestReportRollbackAndRetry(t *testing.T) {
	for name, failure := range map[string]string{
		"jsonb":              `ALTER TABLE hosts ADD CONSTRAINT injected_failure CHECK (agent_metadata IS NULL OR agent_metadata->>'agent' <> 'fixture')`,
		"second port":        `ALTER TABLE host_ports ADD CONSTRAINT injected_failure CHECK (state <> 'closed')`,
		"second finding":     `ALTER TABLE host_vulnerabilities ADD CONSTRAINT injected_failure CHECK (finding->>'title' <> 'second')`,
		"catalog enrichment": `ALTER TABLE vulnerabilities ADD CONSTRAINT injected_failure CHECK (title <> 'enriched catalog')`,
		"scan history":       `ALTER TABLE scan_history_entries ADD CONSTRAINT injected_failure CHECK (source <> 'atomic' OR source_version <> 'v2')`,
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", name, existing), func(t *testing.T) {
				repo := reportFixture(t)
				if existing {
					old := sampleReport()
					old.Host.Hostname = "original"
					old.Host.Ports[1].State = "open"
					old.Host.Vulnerabilities[1].Title = "old"
					old.Catalog = nil
					old.AgentMetadata = map[string]interface{}{"agent": "old"}
					old.Source.Config = "original source config"
					if err := repo.addReport(old); err != nil {
						t.Fatal(err)
					}
				}
				before := reportState(t, repo)
				if err := repo.db.Exec(failure).Error; err != nil {
					t.Fatal(err)
				}
				report := sampleReport()
				report.Source.Version = "v2"
				if err := repo.addReport(report); err == nil {
					t.Fatal("expected injected persistence failure")
				}
				if after := reportState(t, repo); !reflect.DeepEqual(before, after) {
					t.Fatalf("rejected report changed state:\nbefore=%v\nafter=%v", before, after)
				}
				var table string
				if _, err := fmt.Sscanf(failure, "ALTER TABLE %s", &table); err != nil {
					t.Fatalf("parse injected failure table: %v", err)
				}
				if err := repo.db.Exec("ALTER TABLE " + table + " DROP CONSTRAINT injected_failure").Error; err != nil {
					t.Fatal(err)
				}
				if err := repo.addReport(report); err != nil {
					t.Fatalf("exact retry failed: %v", err)
				}
				if err := repo.addReport(report); err != nil {
					t.Fatalf("repeat failed: %v", err)
				}
				var n int64
				for table, want := range map[string]int64{"hosts": 1, "ports": 2, "vulnerabilities": 2} {
					repo.db.Table(table).Count(&n)
					if n != want {
						t.Fatalf("%s count=%d want=%d", table, n, want)
					}
				}
				for _, table := range []string{"host_ports", "host_vulnerabilities"} {
					repo.db.Table(table).Where("source=?", report.Source.Name).Count(&n)
					if n != 2 {
						t.Fatalf("%s duplicates after retry: %d", table, n)
					}
				}
				repo.db.Table("scan_history_entries").Where("source=? AND source_version=?", report.Source.Name, report.Source.Version).Count(&n)
				if n != 2 {
					t.Fatalf("each accepted report needs one history event, got %d", n)
				}
				var got models.Host
				if err := repo.db.First(&got).Error; err != nil {
					t.Fatal(err)
				}
				if got.Hostname != "new-host" || got.AgentMetadata["agent"] != "fixture" {
					t.Fatalf("retry did not save full host: %+v", got)
				}
				var observation string
				if err := repo.db.Table("host_vulnerabilities").Select("finding::text").Where("source=?", report.Source.Name).Order("vulnerability_id").Limit(1).Scan(&observation).Error; err != nil {
					t.Fatal(err)
				}
				var finding sirius.Vulnerability
				if err := json.Unmarshal([]byte(observation), &finding); err != nil {
					t.Fatal(err)
				}
				if finding.Title != "first" || finding.RiskScore != 9.1 {
					t.Fatalf("catalog enrichment changed scanner evidence: %+v", finding)
				}
			})
		}
	}
}

func TestReportInvalidLateFindingWritesNothing(t *testing.T) {
	repo := reportFixture(t)
	before := reportState(t, repo)
	report := sampleReport()
	report.Host.Vulnerabilities[1].Confidence = 1.5
	if err := repo.addReport(report); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("got %v", err)
	}
	if after := reportState(t, repo); !reflect.DeepEqual(before, after) {
		t.Fatal("invalid report changed data")
	}
	report.Host.Vulnerabilities[1].Confidence = .5
	if err := repo.addReport(report); err != nil {
		t.Fatal(err)
	}
}

func createReportTables(t *testing.T, db *gorm.DB, temporary bool) {
	t.Helper()
	for _, q := range []string{
		`CREATE TEMP TABLE hosts (id bigserial PRIMARY KEY, owner_subject_id text NOT NULL DEFAULT '', h_id text UNIQUE, client_id bigint, ip text, hostname text, os text, os_version text, agent_id bigint, software_inventory jsonb, system_fingerprint jsonb, agent_metadata jsonb, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz)`,
		`CREATE TEMP TABLE ports (id bigserial PRIMARY KEY, number int NOT NULL, protocol text NOT NULL, state text, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz, UNIQUE(number,protocol))`,
		`CREATE TEMP TABLE host_ports (host_id bigint REFERENCES hosts(id), port_id bigint REFERENCES ports(id), source text, source_version text, first_seen timestamptz, last_seen timestamptz, status text, notes text, state text, PRIMARY KEY(host_id,port_id,source))`,
		`CREATE TEMP TABLE vulnerabilities (id bigserial PRIMARY KEY, v_id text UNIQUE, title text, description text, risk_score double precision, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz)`,
		`CREATE TEMP TABLE host_vulnerabilities (host_id bigint REFERENCES hosts(id), vulnerability_id bigint REFERENCES vulnerabilities(id), source text, source_version text, first_seen timestamptz, last_seen timestamptz, status text, confidence double precision, port int, service_info text, notes text, finding jsonb, PRIMARY KEY(host_id,vulnerability_id,source))`,
		`CREATE TEMP TABLE scan_history_entries (id bigserial PRIMARY KEY, host_id bigint REFERENCES hosts(id), source text, source_version text, scan_time timestamptz, findings_count int, scan_config text, notes text, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz)`,
	} {
		if !temporary {
			q = strings.Replace(q, "CREATE TEMP TABLE", "CREATE TABLE", 1)
		}
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestReportDefaultProtocolKeepsDuplicateOrder(t *testing.T) {
	repo := reportFixture(t)
	report := sampleReport()
	report.Host.Ports = []sirius.Port{{Number: 443, Protocol: "tcp", State: "open"}, {Number: 443, State: "closed"}}
	if err := repo.addReport(report); err != nil {
		t.Fatal(err)
	}
	var rows []models.HostPort
	if err := repo.db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].State != "closed" {
		t.Fatalf("last observation lost: %+v", rows)
	}
	if report.Host.Ports[1].Protocol != "" {
		t.Fatal("report input mutated")
	}
}

func TestReportCommitFailureRollsBackAll(t *testing.T) {
	repo := reportFixture(t)
	before := reportState(t, repo)
	for _, q := range []string{
		`CREATE FUNCTION pg_temp.reject_report_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$`,
		`CREATE CONSTRAINT TRIGGER reject_report_commit AFTER INSERT ON scan_history_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_report_commit()`,
	} {
		if err := repo.db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.addReport(sampleReport()); err == nil || !strings.Contains(err.Error(), "injected commit failure") {
		t.Fatalf("expected commit error, got %v", err)
	}
	if after := reportState(t, repo); !reflect.DeepEqual(before, after) {
		t.Fatalf("commit failure partially persisted: %v", after)
	}
	if err := repo.db.Exec("DROP TRIGGER reject_report_commit ON scan_history_entries").Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.addReport(sampleReport()); err != nil {
		t.Fatalf("retry after failed commit: %v", err)
	}
}

func TestReportConcurrentRetryAndReversedFindings(t *testing.T) {
	dsn := os.Getenv("SIRIUS_REPORT_TEST_DSN")
	if dsn == "" {
		t.Skip("set SIRIUS_REPORT_TEST_DSN to disposable PostgreSQL")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("report_concurrency_%d", time.Now().UnixNano())
	cfg.RuntimeParams["search_path"] = name
	cfg.RuntimeParams["statement_timeout"] = "5000"
	pool := stdlib.OpenDB(*cfg)
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
	createReportTables(t, db, false)
	repo := &HostRepository{db: db}
	const workers = 16
	start := make(chan struct{})
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			<-start
			report := sampleReport()
			report.Host.IP = fmt.Sprintf("192.0.2.%d", 1+i%4)
			report.Host.HID = fmt.Sprintf("concurrent-%d", i%4)
			report.Source.Name = fmt.Sprintf("scanner-%d", (i/4)%2)
			// Duplicate host/source reports contend alongside reversed finding order.
			if i%2 == 0 {
				report.Host.Vulnerabilities[0], report.Host.Vulnerabilities[1] = report.Host.Vulnerabilities[1], report.Host.Vulnerabilities[0]
			}
			if i%2 == 1 {
				report.Host.Ports[0].Protocol = ""
			}
			results <- repo.addReport(report)
		}(i)
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	for table, want := range map[string]int64{"hosts": 4, "ports": 2, "vulnerabilities": 2, "host_ports": 16, "host_vulnerabilities": 16, "scan_history_entries": workers} {
		var n int64
		if err := db.Table(table).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("%s rows=%d want=%d", table, n, want)
		}
	}
}
