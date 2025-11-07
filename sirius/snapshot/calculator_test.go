package snapshot

import (
	"encoding/json"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
)

func TestVulnerabilitySnapshotSerialization(t *testing.T) {
	t.Log("\n🔍 Testing VulnerabilitySnapshot serialization...")

	snapshot := &store.VulnerabilitySnapshot{
		SnapshotID: "2025-01-03",
		Counts: store.VulnerabilityCounts{
			Total:         100,
			Critical:      10,
			High:          20,
			Medium:        30,
			Low:           35,
			Informational: 5,
		},
		ByHost: []store.HostVulnerabilityStat{
			{
				HostIP:        "192.168.1.1",
				Hostname:      "test-host",
				Total:         5,
				Critical:      1,
				High:          2,
				Medium:        1,
				Low:           1,
				Informational: 0,
			},
		},
		Metadata: store.SnapshotMetadata{
			TotalHosts:               10,
			HostsWithVulnerabilities: 8,
			ScanCoveragePercent:      80.0,
			SnapshotDurationMs:       1234,
		},
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("❌ Failed to marshal VulnerabilitySnapshot: %v", err)
	}

	// Test JSON deserialization
	var deserialized store.VulnerabilitySnapshot
	if err := json.Unmarshal(jsonData, &deserialized); err != nil {
		t.Fatalf("❌ Failed to unmarshal VulnerabilitySnapshot: %v", err)
	}

	// Verify data integrity
	if deserialized.SnapshotID != snapshot.SnapshotID {
		t.Errorf("❌ SnapshotID mismatch: expected %s, got %s", snapshot.SnapshotID, deserialized.SnapshotID)
	}

	if deserialized.Counts.Total != snapshot.Counts.Total {
		t.Errorf("❌ Total count mismatch: expected %d, got %d", snapshot.Counts.Total, deserialized.Counts.Total)
	}

	if len(deserialized.ByHost) != len(snapshot.ByHost) {
		t.Errorf("❌ ByHost length mismatch: expected %d, got %d", len(snapshot.ByHost), len(deserialized.ByHost))
	}

	t.Log("\n✅ VulnerabilitySnapshot serialization test passed")
}

func TestVulnerabilityCountsStructure(t *testing.T) {
	t.Log("\n🔍 Testing VulnerabilityCounts structure...")

	counts := store.VulnerabilityCounts{
		Total:         100,
		Critical:      10,
		High:          20,
		Medium:        30,
		Low:           35,
		Informational: 5,
	}

	// Verify sum equals total
	sum := counts.Critical + counts.High + counts.Medium + counts.Low + counts.Informational
	if sum != counts.Total {
		t.Errorf("❌ Severity counts don't sum to total: expected %d, got %d", counts.Total, sum)
	}

	t.Log("\n✅ VulnerabilityCounts structure test passed")
}

func TestHostVulnerabilityStatStructure(t *testing.T) {
	t.Log("\n🔍 Testing HostVulnerabilityStat structure...")

	hostStat := store.HostVulnerabilityStat{
		HostIP:        "192.168.1.1",
		Hostname:      "test-host",
		Total:         5,
		Critical:      1,
		High:          2,
		Medium:        1,
		Low:           1,
		Informational: 0,
	}

	// Verify sum equals total
	sum := hostStat.Critical + hostStat.High + hostStat.Medium + hostStat.Low + hostStat.Informational
	if sum != hostStat.Total {
		t.Errorf("❌ Host severity counts don't sum to total: expected %d, got %d", hostStat.Total, sum)
	}

	t.Log("\n✅ HostVulnerabilityStat structure test passed")
}

