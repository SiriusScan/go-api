package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

// MockKVStore is a simple in-memory implementation of KVStore for testing
type MockKVStore struct {
	data map[string]string
}

func NewMockKVStore() *MockKVStore {
	return &MockKVStore{
		data: make(map[string]string),
	}
}

func (m *MockKVStore) SetValue(ctx context.Context, key, value string) error {
	m.data[key] = value
	return nil
}

func (m *MockKVStore) SetValueWithTTL(ctx context.Context, key, value string, ttlSeconds int) error {
	m.data[key] = value
	return nil
}

func (m *MockKVStore) GetValue(ctx context.Context, key string) (store.ValkeyResponse, error) {
	value, exists := m.data[key]
	if !exists {
		return store.ValkeyResponse{}, fmt.Errorf("key '%s' not found", key)
	}
	return store.ValkeyResponse{
		Message: store.ValkeyValue{Value: value},
	}, nil
}

func (m *MockKVStore) GetTTL(ctx context.Context, key string) (int, error) {
	return -1, nil // Mock always returns -1 (no expiry)
}

func (m *MockKVStore) SetExpire(ctx context.Context, key string, ttlSeconds int) error {
	return nil
}

func (m *MockKVStore) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	keys := make([]string, 0)
	prefix := strings.ReplaceAll(pattern, "*", "")
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *MockKVStore) DeleteValue(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *MockKVStore) Close() error {
	return nil
}

func TestSnapshotManagerCreateAndRetrieve(t *testing.T) {
	t.Log("\n🔍 Testing SnapshotManager create and retrieve...")

	mockStore := NewMockKVStore()
	manager := NewSnapshotManager(mockStore)
	ctx := context.Background()

	// Create a test snapshot manually
	testSnapshot := &store.VulnerabilitySnapshot{
		SnapshotID: "2025-01-03",
		Timestamp:  time.Now().UTC(),
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
				HostIP:   "192.168.1.1",
				Hostname: "test-host",
				Total:    5,
			},
		},
		Metadata: store.SnapshotMetadata{
			TotalHosts:               10,
			HostsWithVulnerabilities: 8,
			ScanCoveragePercent:      80.0,
			SnapshotDurationMs:       1234,
		},
	}

	// Save snapshot manually
	key := "vuln:snapshot:2025-01-03"
	data, err := json.Marshal(testSnapshot)
	if err != nil {
		t.Fatalf("❌ Failed to marshal test snapshot: %v", err)
	}

	if err := mockStore.SetValue(ctx, key, string(data)); err != nil {
		t.Fatalf("❌ Failed to save test snapshot: %v", err)
	}

	// Retrieve snapshot
	retrieved, err := manager.GetSnapshot(ctx, "2025-01-03")
	if err != nil {
		t.Fatalf("❌ Failed to retrieve snapshot: %v", err)
	}

	// Verify data integrity
	if retrieved.SnapshotID != testSnapshot.SnapshotID {
		t.Errorf("❌ SnapshotID mismatch: expected %s, got %s", testSnapshot.SnapshotID, retrieved.SnapshotID)
	}

	if retrieved.Counts.Total != testSnapshot.Counts.Total {
		t.Errorf("❌ Total count mismatch: expected %d, got %d", testSnapshot.Counts.Total, retrieved.Counts.Total)
	}

	t.Log("\n✅ SnapshotManager create and retrieve test passed")
}

func TestSnapshotManagerListSnapshots(t *testing.T) {
	t.Log("\n🔍 Testing SnapshotManager list snapshots...")

	mockStore := NewMockKVStore()
	manager := NewSnapshotManager(mockStore)
	ctx := context.Background()

	// Create multiple test snapshots
	testDates := []string{"2025-01-01", "2025-01-02", "2025-01-03"}
	for _, date := range testDates {
		snapshot := &store.VulnerabilitySnapshot{
			SnapshotID: date,
			Timestamp:  time.Now().UTC(),
			Counts:     store.VulnerabilityCounts{Total: 10},
		}
		key := "vuln:snapshot:" + date
		data, _ := json.Marshal(snapshot)
		mockStore.SetValue(ctx, key, string(data))
	}

	// List snapshots
	dates, err := manager.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("❌ Failed to list snapshots: %v", err)
	}

	// Verify we got all dates
	if len(dates) != len(testDates) {
		t.Errorf("❌ Expected %d snapshots, got %d", len(testDates), len(dates))
	}

	// Verify dates are sorted descending (most recent first)
	if len(dates) > 1 && dates[0] < dates[1] {
		t.Errorf("❌ Dates not sorted descending: %v", dates)
	}

	t.Log("\n✅ SnapshotManager list snapshots test passed")
}

func TestSnapshotManagerCleanup(t *testing.T) {
	t.Log("\n🔍 Testing SnapshotManager cleanup...")

	mockStore := NewMockKVStore()
	manager := NewSnapshotManager(mockStore)
	ctx := context.Background()

	// Create 12 snapshots (more than the 10 limit)
	for i := 1; i <= 12; i++ {
		date := time.Date(2025, 1, i, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
		snapshot := &store.VulnerabilitySnapshot{
			SnapshotID: date,
			Timestamp:  time.Now().UTC(),
			Counts:     store.VulnerabilityCounts{Total: 10},
		}
		key := "vuln:snapshot:" + date
		data, _ := json.Marshal(snapshot)
		mockStore.SetValue(ctx, key, string(data))
	}

	// Run cleanup
	if err := manager.CleanupOldSnapshots(ctx); err != nil {
		t.Fatalf("❌ Cleanup failed: %v", err)
	}

	// Verify only 10 snapshots remain
	dates, err := manager.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("❌ Failed to list snapshots after cleanup: %v", err)
	}

	if len(dates) != 10 {
		t.Errorf("❌ Expected 10 snapshots after cleanup, got %d", len(dates))
	}

	t.Log("\n✅ SnapshotManager cleanup test passed")
}

