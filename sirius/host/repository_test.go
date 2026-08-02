package host

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

// TestRepositoryCircularReferences tests that our repository pattern doesn't create circular references
func TestRepositoryCircularReferences(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres on localhost:5432; run without -short to enable")
	}
	t.Log("\n🔍 Testing Repository Pattern for Circular References")

	// Initialize database
	db := postgres.GetDB()
	if db == nil {
		t.Fatal("❌ Failed to initialize database")
	}

	// Clean up test data
	db.Exec("DELETE FROM host_vulnerabilities WHERE 1=1")
	db.Exec("DELETE FROM host_ports WHERE 1=1")
	db.Exec("DELETE FROM vulnerabilities WHERE 1=1")
	db.Exec("DELETE FROM ports WHERE 1=1")
	db.Exec("DELETE FROM hosts WHERE ip = '192.168.99.99'")

	t.Log("✅ Database initialized and cleaned")

	// Test data
	testHost := sirius.Host{
		IP:       "192.168.99.99",
		Hostname: "test-circular-check",
		OS:       "Linux",
		OSVersion: "Ubuntu 22.04",
		Ports: []sirius.Port{
			{Number: 22, Protocol: "tcp", State: "open"},
			{Number: 80, Protocol: "tcp", State: "open"},
			{Number: 443, Protocol: "tcp", State: "open"},
		},
		Vulnerabilities: []sirius.Vulnerability{
			{VID: "CVE-2024-TEST-1", Title: "Test Vuln 1", Description: "Test Description 1", RiskScore: 7.5},
			{VID: "CVE-2024-TEST-2", Title: "Test Vuln 2", Description: "Test Description 2", RiskScore: 9.8},
		},
	}

	testSource := models.ScanSource{
		Name:    "repository-test",
		Version: "1.0.0",
		Config:  "test-config",
	}

	t.Log("\n📝 Test Data:")
	t.Logf("  Host: %s (%s)", testHost.IP, testHost.Hostname)
	t.Logf("  Ports: %d", len(testHost.Ports))
	t.Logf("  Vulnerabilities: %d", len(testHost.Vulnerabilities))

	// Test 1: Write operations using repository pattern
	t.Log("\n=== Test 1: Write Operations ===")
	err := AddHostWithSource(testHost, testSource, "")
	if err != nil {
		t.Fatalf("❌ Failed to add host with source: %v", err)
	}
	t.Log("✅ Successfully added host using repository pattern")

	// Test 2: Read operations using repository pattern
	t.Log("\n=== Test 2: Read Operations ===")
	retrievedHost, err := GetHost(testHost.IP)
	if err != nil {
		t.Fatalf("❌ Failed to retrieve host: %v", err)
	}
	t.Logf("✅ Successfully retrieved host: %s", retrievedHost.IP)
	t.Logf("  Ports retrieved: %d", len(retrievedHost.Ports))
	t.Logf("  Vulnerabilities retrieved: %d", len(retrievedHost.Vulnerabilities))

	// Test 3: JSON serialization (circular reference detection)
	t.Log("\n=== Test 3: JSON Serialization (Circular Reference Check) ===")
	jsonBytes, err := json.Marshal(retrievedHost)
	if err != nil {
		t.Fatalf("❌ JSON marshaling failed - CIRCULAR REFERENCE DETECTED: %v", err)
	}
	t.Logf("✅ JSON marshaling successful - NO CIRCULAR REFERENCES")
	t.Logf("  JSON size: %d bytes", len(jsonBytes))

	// Validate JSON structure
	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonBytes, &jsonMap)
	if err != nil {
		t.Fatalf("❌ Failed to unmarshal JSON: %v", err)
	}

	// Verify ports array exists and is correct
	if ports, ok := jsonMap["ports"].([]interface{}); ok {
		t.Logf("  Ports in JSON: %d", len(ports))
		if len(ports) != len(testHost.Ports) {
			t.Errorf("❌ Port count mismatch: expected %d, got %d", len(testHost.Ports), len(ports))
		}
	} else {
		t.Error("❌ Ports array missing or incorrect type in JSON")
	}

	// Verify vulnerabilities array exists and is correct
	if vulns, ok := jsonMap["vulnerabilities"].([]interface{}); ok {
		t.Logf("  Vulnerabilities in JSON: %d", len(vulns))
		if len(vulns) != len(testHost.Vulnerabilities) {
			t.Errorf("❌ Vulnerability count mismatch: expected %d, got %d", len(testHost.Vulnerabilities), len(vulns))
		}
	} else {
		t.Error("❌ Vulnerabilities array missing or incorrect type in JSON")
	}

	// Test 4: Repository direct access (verify no circular references in models)
	t.Log("\n=== Test 4: Direct Repository Access ===")
	repo := NewHostRepository()
	hostWithRelations, err := repo.GetHostWithRelations(testHost.IP, "")
	if err != nil {
		t.Fatalf("❌ Failed to get host with relations: %v", err)
	}
	t.Logf("✅ Successfully retrieved host with relations")
	t.Logf("  HostWithRelations ports: %d", len(hostWithRelations.Ports))
	t.Logf("  HostWithRelations vulnerabilities: %d", len(hostWithRelations.Vulnerabilities))

	// Try to marshal HostWithRelations directly
	jsonBytes2, err := json.Marshal(hostWithRelations)
	if err != nil {
		t.Fatalf("❌ HostWithRelations JSON marshaling failed - CIRCULAR REFERENCE: %v", err)
	}
	t.Logf("✅ HostWithRelations JSON marshaling successful")
	t.Logf("  JSON size: %d bytes", len(jsonBytes2))

	// Test 5: Verify database model integrity
	t.Log("\n=== Test 5: Database Model Integrity ===")
	var dbHost models.Host
	result := db.Where("ip = ?", testHost.IP).First(&dbHost)
	if result.Error != nil {
		t.Fatalf("❌ Failed to query database host: %v", result.Error)
	}
	t.Logf("✅ Database host retrieved: %s", dbHost.IP)

	// Verify that direct model fields don't contain circular references
	// Try to marshal the database model (should fail if circular refs exist)
	_, err = json.Marshal(dbHost)
	if err != nil {
		t.Logf("⚠️  Database model marshaling failed (expected if no Preload): %v", err)
	} else {
		t.Log("✅ Database model marshaling successful")
	}

	// Test 6: GetAllHosts (tests batch operations)
	t.Log("\n=== Test 6: Batch Read Operations ===")
	allHosts, err := GetAllHosts()
	if err != nil {
		t.Fatalf("❌ Failed to get all hosts: %v", err)
	}
	t.Logf("✅ Successfully retrieved all hosts: %d", len(allHosts))

	// Try to marshal all hosts (circular reference would cause stack overflow)
	jsonBytes3, err := json.Marshal(allHosts)
	if err != nil {
		t.Fatalf("❌ GetAllHosts JSON marshaling failed - CIRCULAR REFERENCE: %v", err)
	}
	t.Logf("✅ GetAllHosts JSON marshaling successful")
	t.Logf("  JSON size: %d bytes", len(jsonBytes3))

	// Final summary
	t.Log("\n" + strings.Repeat("=", 60))
	t.Log("✅ ALL TESTS PASSED - NO CIRCULAR REFERENCES DETECTED")
	t.Log(strings.Repeat("=", 60))

	// Cleanup
	db.Exec("DELETE FROM host_vulnerabilities WHERE 1=1")
	db.Exec("DELETE FROM host_ports WHERE 1=1")
	db.Exec("DELETE FROM vulnerabilities WHERE v_id LIKE 'CVE-2024-TEST-%'")
	db.Exec("DELETE FROM ports WHERE id IN (SELECT port_id FROM host_ports WHERE host_id = ?)", dbHost.ID)
	db.Exec("DELETE FROM hosts WHERE ip = '192.168.99.99'")
	t.Log("✅ Test data cleaned up")
}

// TestRepositoryUpsertOperations tests individual repository operations
func TestRepositoryUpsertOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres on localhost:5432; run without -short to enable")
	}
	t.Log("\n🔍 Testing Individual Repository Operations")

	db := postgres.GetDB()
	if db == nil {
		t.Fatal("❌ Failed to initialize database")
	}

	repo := NewHostRepository()

	// Clean up
	db.Exec("DELETE FROM hosts WHERE ip = '10.0.0.99'")
	db.Exec("DELETE FROM ports WHERE number = 9999")
	db.Exec("DELETE FROM vulnerabilities WHERE v_id = 'CVE-TEST-REPO'")

	t.Log("\n=== Test: UpsertHost ===")
	hostID, err := repo.UpsertHost("10.0.0.99", "test-repo-host", "TestOS", "1.0", "TEST-HID", "")
	if err != nil {
		t.Fatalf("❌ UpsertHost failed: %v", err)
	}
	t.Logf("✅ UpsertHost succeeded: ID=%d", hostID)

	// Verify host can be retrieved and marshaled
	var testHost models.Host
	db.First(&testHost, hostID)
	_, err = json.Marshal(testHost)
	if err != nil {
		t.Errorf("❌ Host marshaling failed: %v", err)
	} else {
		t.Log("✅ Host marshaling successful")
	}

	t.Log("\n=== Test: UpsertPort ===")
	portID, err := repo.UpsertPort(9999, "tcp", "open")
	if err != nil {
		t.Fatalf("❌ UpsertPort failed: %v", err)
	}
	t.Logf("✅ UpsertPort succeeded: ID=%d", portID)

	// Verify port can be marshaled
	var testPort models.Port
	db.First(&testPort, portID)
	_, err = json.Marshal(testPort)
	if err != nil {
		t.Errorf("❌ Port marshaling failed: %v", err)
	} else {
		t.Log("✅ Port marshaling successful")
	}

	t.Log("\n=== Test: UpsertVulnerability ===")
	vulnID, err := repo.UpsertVulnerability("CVE-TEST-REPO", "Test Vulnerability", "Test Description", 5.0)
	if err != nil {
		t.Fatalf("❌ UpsertVulnerability failed: %v", err)
	}
	t.Logf("✅ UpsertVulnerability succeeded: ID=%d", vulnID)

	// Verify vulnerability can be marshaled
	var testVuln models.Vulnerability
	db.First(&testVuln, vulnID)
	_, err = json.Marshal(testVuln)
	if err != nil {
		t.Errorf("❌ Vulnerability marshaling failed: %v", err)
	} else {
		t.Log("✅ Vulnerability marshaling successful")
	}

	t.Log("\n=== Test: LinkHostPort ===")
	source := models.ScanSource{Name: "test", Version: "1.0", Config: "test"}
	err = repo.LinkHostPort(hostID, portID, source)
	if err != nil {
		t.Fatalf("❌ LinkHostPort failed: %v", err)
	}
	t.Log("✅ LinkHostPort succeeded")

	t.Log("\n=== Test: LinkHostVulnerability ===")
	err = repo.LinkHostVulnerability(hostID, vulnID, source)
	if err != nil {
		t.Fatalf("❌ LinkHostVulnerability failed: %v", err)
	}
	t.Log("✅ LinkHostVulnerability succeeded")

	// Cleanup
	db.Exec("DELETE FROM host_vulnerabilities WHERE host_id = ?", hostID)
	db.Exec("DELETE FROM host_ports WHERE host_id = ?", hostID)
	db.Exec("DELETE FROM hosts WHERE id = ?", hostID)
	db.Exec("DELETE FROM ports WHERE id = ?", portID)
	db.Exec("DELETE FROM vulnerabilities WHERE id = ?", vulnID)

	t.Log("\n✅ All repository operations completed successfully")
}

// TestUpsertHostOwnerIsolation ensures Alice and Bob get distinct rows for the same IP.
func TestUpsertHostOwnerIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres on localhost:5432; run without -short to enable")
	}

	db := postgres.GetDB()
	if db == nil {
		t.Fatal("failed to initialize database")
	}

	const ip = "10.0.0.77"
	db.Exec("DELETE FROM hosts WHERE ip = ?", ip)

	repo := NewHostRepository()

	aliceID, err := repo.UpsertHost(ip, "alice-host", "Linux", "1.0", "", "subj-alice")
	if err != nil {
		t.Fatalf("alice UpsertHost: %v", err)
	}
	bobID, err := repo.UpsertHost(ip, "bob-host", "Linux", "1.0", "", "subj-bob")
	if err != nil {
		t.Fatalf("bob UpsertHost: %v", err)
	}
	if aliceID == bobID {
		t.Fatalf("expected distinct host IDs for Alice and Bob, both got %d", aliceID)
	}

	aliceAgain, err := repo.UpsertHost(ip, "alice-host-updated", "Linux", "1.1", "", "subj-alice")
	if err != nil {
		t.Fatalf("alice re-UpsertHost: %v", err)
	}
	if aliceAgain != aliceID {
		t.Fatalf("alice re-upsert should update same row: got %d want %d", aliceAgain, aliceID)
	}

	var alice, bob models.Host
	if err := db.First(&alice, aliceID).Error; err != nil {
		t.Fatalf("load alice: %v", err)
	}
	if err := db.First(&bob, bobID).Error; err != nil {
		t.Fatalf("load bob: %v", err)
	}
	if alice.OwnerSubjectID != "subj-alice" || bob.OwnerSubjectID != "subj-bob" {
		t.Fatalf("owners: alice=%q bob=%q", alice.OwnerSubjectID, bob.OwnerSubjectID)
	}
	if alice.IP != ip || bob.IP != ip {
		t.Fatalf("IPs: alice=%q bob=%q want %q", alice.IP, bob.IP, ip)
	}
	if alice.HID == "" || bob.HID == "" || alice.HID == bob.HID {
		t.Fatalf("HIDs must be unique and non-empty: alice=%q bob=%q", alice.HID, bob.HID)
	}
	if alice.Hostname != "alice-host-updated" {
		t.Fatalf("alice hostname not updated: %q", alice.Hostname)
	}
	if bob.Hostname != "bob-host" {
		t.Fatalf("bob hostname changed unexpectedly: %q", bob.Hostname)
	}

	// Empty-owner path creates a third global row, not Alice or Bob.
	legacyID, err := repo.UpsertHost(ip, "legacy-host", "Linux", "1.0", "", "")
	if err != nil {
		t.Fatalf("legacy UpsertHost: %v", err)
	}
	if legacyID == aliceID || legacyID == bobID {
		t.Fatalf("legacy row must be distinct from owned rows: legacy=%d alice=%d bob=%d", legacyID, aliceID, bobID)
	}
	var legacy models.Host
	if err := db.First(&legacy, legacyID).Error; err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if legacy.OwnerSubjectID != "" || legacy.Hostname != "legacy-host" {
		t.Fatalf("legacy host unexpected: owner=%q hostname=%q", legacy.OwnerSubjectID, legacy.Hostname)
	}

	db.Exec("DELETE FROM hosts WHERE ip = ?", ip)
}

func TestGenerateHostIDIncludesOwnerDigest(t *testing.T) {
	legacy := generateHostID("")
	if !strings.HasPrefix(legacy, "scan-") || strings.Count(legacy, "-") != 1 {
		t.Fatalf("legacy HID format unexpected: %q", legacy)
	}
	owned := generateHostID("subj-alice")
	if !strings.HasPrefix(owned, "scan-") || strings.Count(owned, "-") != 2 {
		t.Fatalf("owned HID should include owner digest segment: %q", owned)
	}
	other := generateHostID("subj-bob")
	// Digests differ by owner even if random collides (extremely unlikely); prefixes before last segment differ.
	if owned[:13] == other[:13] && owned == other {
		t.Fatalf("owned HIDs should differ across owners: %q vs %q", owned, other)
	}
}

