package host

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

func TestPortObservationModelKey(t *testing.T) {
	s, err := schema.Parse(&models.HostPort{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	state := s.LookUpField("State")
	if state == nil || !state.IgnoreMigration || !state.Creatable || !state.Readable {
		t.Fatalf("state must remain readable/writable but ledger-owned: %+v", state)
	}
	if len(s.PrimaryFields) != 3 {
		t.Fatalf("expected host/port/source key: %v", s.PrimaryFieldDBNames)
	}
	for i, name := range []string{"host_id", "port_id", "source"} {
		if s.PrimaryFieldDBNames[i] != name {
			t.Fatalf("key = %v", s.PrimaryFieldDBNames)
		}
	}
}

// Only explicitly supplied disposable Postgres is used. Every fixture is a
// transaction with temporary tables and pg_temp-only search_path.
func portFixture(t *testing.T) *HostRepository {
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
		`CREATE TEMP TABLE hosts (id bigint PRIMARY KEY, h_id text, ip text, hostname text, os text, os_version text, agent_id bigint,
		 software_inventory jsonb, system_fingerprint jsonb, agent_metadata jsonb, created_at timestamp, updated_at timestamp, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE ports (id bigserial PRIMARY KEY, number int NOT NULL, protocol text NOT NULL, state text,
		 created_at timestamptz, updated_at timestamptz, deleted_at timestamptz, UNIQUE(number, protocol)) ON COMMIT DROP`,
		`CREATE TEMP TABLE host_ports (host_id bigint REFERENCES hosts(id), port_id bigint REFERENCES ports(id), source text NOT NULL,
		 source_version text, first_seen timestamptz, last_seen timestamptz, status text, notes text, state text NOT NULL DEFAULT 'unknown',
		 PRIMARY KEY(host_id, port_id, source)) ON COMMIT DROP`,
		`CREATE TEMP TABLE vulnerabilities (id bigint, v_id text, title text, description text, risk_score double precision,
		 created_at timestamp, updated_at timestamp, deleted_at timestamp) ON COMMIT DROP`,
		`CREATE TEMP TABLE host_vulnerabilities (host_id bigint, vulnerability_id bigint, source text, source_version text,
		 first_seen timestamp, last_seen timestamp, status text, confidence double precision, port int, service_info text, notes text, finding jsonb) ON COMMIT DROP`,
		`INSERT INTO hosts (id,h_id,ip,hostname,os,os_version,agent_id,created_at,updated_at) VALUES
		 (1,'a','192.0.2.1','','','',0,now(),now()), (2,'b','192.0.2.2','','','',0,now(),now())`,
	} {
		if err := tx.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	return &HostRepository{db: tx}
}

func TestPortObservationIsolation(t *testing.T) {
	repo := portFixture(t)
	nmap := models.ScanSource{Name: "nmap", Version: "1", Config: "first"}
	agent := models.ScanSource{Name: "agent"}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(repo.UpsertHostPort(1, 443, "tcp", "open", nmap))
	must(repo.UpsertHostPort(2, 443, "tcp", "closed", nmap))
	for ip, state := range map[string]string{"192.0.2.1": "open", "192.0.2.2": "closed"} {
		h, err := repo.GetHostWithRelations(ip)
		must(err)
		if len(h.Ports) != 1 || h.Ports[0].Port.State != state {
			t.Fatalf("host %s state: %+v, want %s", ip, h.Ports, state)
		}
	}
	must(repo.UpsertHostPort(1, 443, "tcp", "filtered", agent))
	var before models.HostPort
	must(repo.db.Where("host_id=1 AND source='nmap'").First(&before).Error)
	nmap.Version, nmap.Config = "2", "updated"
	must(repo.UpsertHostPort(1, 443, "tcp", "closed", nmap))
	var after models.HostPort
	must(repo.db.Where("host_id=1 AND source='nmap'").First(&after).Error)
	if !after.FirstSeen.Equal(before.FirstSeen) || after.LastSeen.Before(before.LastSeen) || after.SourceVersion != "2" || after.Notes != "updated" {
		t.Fatalf("update lost attribution: before=%+v after=%+v", before, after)
	}
	// A legacy catalog update cannot contaminate any observation.
	id, err := repo.UpsertPort(443, "tcp", "open")
	must(err)
	must(repo.LinkHostPort(1, id, nmap))
	must(repo.LinkHostPort(2, id, models.ScanSource{Name: "legacy"}))
	var observations []models.HostPort
	must(repo.db.Order("host_id, source").Find(&observations).Error)
	want := map[string]string{"1/agent": "filtered", "1/nmap": "closed", "2/legacy": "unknown", "2/nmap": "closed"}
	if len(observations) != len(want) {
		t.Fatalf("observations=%+v", observations)
	}
	for _, o := range observations {
		key := fmt.Sprintf("%d/%s", o.HostID, o.Source)
		if o.State != want[key] {
			t.Fatalf("%s state=%s want=%s", key, o.State, want[key])
		}
	}
	var count int64
	must(repo.db.Model(&models.Port{}).Count(&count).Error)
	if count != 1 {
		t.Fatalf("shared identity count=%d", count)
	}
	// Force known timestamps so the aggregate view selects the latest source.
	must(repo.db.Exec("UPDATE host_ports SET last_seen = ? WHERE host_id=1 AND source='agent'", time.Now().Add(time.Hour)).Error)
	host, err := repo.GetHostWithRelations("192.0.2.1")
	must(err)
	if len(host.Ports) != 1 || host.Ports[0].Port.State != "filtered" || host.Ports[0].Source != "agent" {
		t.Fatalf("aggregate=%+v", host.Ports)
	}
	sources, err := repo.getPortSources(1)
	must(err)
	if len(sources) != 2 || sources[0].State != "filtered" || sources[1].State != "closed" {
		t.Fatalf("sources=%+v", sources)
	}
	host, err = repo.GetHostWithRelations("192.0.2.2")
	must(err)
	if len(host.Ports) != 1 {
		t.Fatalf("host2=%+v", host.Ports)
	}
	// No fallback to shared catalog, even when an observation is unknown.
	must(repo.db.Exec("UPDATE ports SET state='open'").Error)
	sources, err = repo.getPortSources(2)
	must(err)
	if len(sources) != 2 || sources[0].State != "unknown" || sources[1].State != "closed" {
		t.Fatalf("host2 sources=%+v", sources)
	}
}

func TestPortObservationDefaultsAndRollback(t *testing.T) {
	repo := portFixture(t)
	if err := repo.UpsertHostPort(1, 53, "", "", models.ScanSource{}); err != nil {
		t.Fatal(err)
	}
	var got models.HostPort
	if err := repo.db.First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Source != "unknown" || got.State != "open" {
		t.Fatalf("defaults=%+v", got)
	}
	if err := repo.UpsertHostPort(99, 9999, "tcp", "closed", models.ScanSource{Name: "nmap"}); err == nil {
		t.Fatal("expected invalid host FK error")
	}
	var count int64
	if err := repo.db.Model(&models.Port{}).Where("number=9999").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed observation left a catalog row")
	}
}

func TestPortObservationRejectsRetiredIdentity(t *testing.T) {
	repo := portFixture(t)
	source := models.ScanSource{Name: "nmap"}
	if err := repo.UpsertHostPort(1, 443, "tcp", "open", source); err != nil {
		t.Fatal(err)
	}
	var port models.Port
	if err := repo.db.First(&port).Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.db.Delete(&port).Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertHostPort(2, 443, "tcp", "closed", source); !errors.Is(err, ErrPortIdentityDeleted) {
		t.Fatalf("expected explicit retired identity error, got %v", err)
	}
	var stillRetired models.Port
	if err := repo.db.Unscoped().First(&stillRetired, port.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !stillRetired.DeletedAt.Valid {
		t.Fatal("new host observation resurrected shared identity")
	}
	rows, err := repo.getPortSources(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("retired host observations reappeared: %+v", rows)
	}
	var count int64
	if err := repo.db.Table("host_ports").Where("host_id=2").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rejected observation changed host2")
	}
}

func TestPortObservationKeepsProtocolIdentity(t *testing.T) {
	repo := portFixture(t)
	// Do not silently normalize historical protocol values in a state-only fix.
	first, err := repo.UpsertPort(443, "TCP", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.UpsertPort(443, "TCP", "")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("legacy protocol identity forked")
	}
	var port models.Port
	if err := repo.db.First(&port, first).Error; err != nil {
		t.Fatal(err)
	}
	if port.Protocol != "TCP" {
		t.Fatalf("protocol changed: %s", port.Protocol)
	}
}
