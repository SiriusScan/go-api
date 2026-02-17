package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/SiriusScan/go-api/sirius/store"
)

// SnapshotManager handles snapshot CRUD operations and lifecycle management
type SnapshotManager struct {
	kvStore    store.KVStore
	calculator *SnapshotCalculator
}

// NewSnapshotManager creates a new SnapshotManager instance
func NewSnapshotManager(kvStore store.KVStore) *SnapshotManager {
	return &SnapshotManager{
		kvStore:    kvStore,
		calculator: NewSnapshotCalculator(kvStore),
	}
}

// CreateSnapshot generates and stores a new snapshot
// snapshotID can be empty (will auto-generate timestamp-based ID) or a specific ID
func (sm *SnapshotManager) CreateSnapshot(ctx context.Context, snapshotID string) (*store.VulnerabilitySnapshot, error) {
	snapshot, err := sm.calculator.CalculateSnapshot(snapshotID)
	if err != nil {
		return nil, err
	}

	if err := sm.calculator.SaveSnapshot(ctx, snapshot); err != nil {
		return nil, err
	}

	// Cleanup old snapshots after creating new one
	if err := sm.CleanupOldSnapshots(ctx); err != nil {
		// Log but don't fail on cleanup error
		slog.Warn("Failed to cleanup old snapshots", "error", err)
	}

	return snapshot, nil
}

// GetSnapshot retrieves a specific snapshot by snapshot ID
func (sm *SnapshotManager) GetSnapshot(ctx context.Context, snapshotID string) (*store.VulnerabilitySnapshot, error) {
	key := fmt.Sprintf("vuln:snapshot:%s", snapshotID)

	resp, err := sm.kvStore.GetValue(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("snapshot not found for ID %s: %w", snapshotID, err)
	}

	var snapshot store.VulnerabilitySnapshot
	if err := json.Unmarshal([]byte(resp.Message.Value), &snapshot); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}

	return &snapshot, nil
}

// ListSnapshots retrieves all available snapshot IDs
func (sm *SnapshotManager) ListSnapshots(ctx context.Context) ([]string, error) {
	keys, err := sm.kvStore.ListKeys(ctx, "vuln:snapshot:*")
	if err != nil {
		return nil, err
	}

	snapshotIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		// Extract snapshot ID from key (vuln:snapshot:YYYY-MM-DD-HHMMSS)
		parts := strings.Split(key, ":")
		if len(parts) >= 3 {
			// Join back in case snapshot ID contains colons (unlikely but safe)
			snapshotID := strings.Join(parts[2:], ":")
			snapshotIDs = append(snapshotIDs, snapshotID)
		}
	}

	// Sort descending (most recent first) - timestamp format is sortable
	sort.Slice(snapshotIDs, func(i, j int) bool {
		return snapshotIDs[i] > snapshotIDs[j]
	})

	return snapshotIDs, nil
}

// GetTrendData retrieves multiple snapshots for trend analysis
// Returns up to the specified number of most recent snapshots
func (sm *SnapshotManager) GetTrendData(ctx context.Context, limit int) ([]*store.VulnerabilitySnapshot, error) {
	if limit > 10 {
		limit = 10 // Maximum 10 snapshots
	}

	availableIDs, err := sm.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}

	// Limit to requested number (most recent first)
	if len(availableIDs) > limit {
		availableIDs = availableIDs[:limit]
	}

	snapshots := make([]*store.VulnerabilitySnapshot, 0, len(availableIDs))
	for _, snapshotID := range availableIDs {
		snapshot, err := sm.GetSnapshot(ctx, snapshotID)
		if err != nil {
			// Skip snapshots that fail to load
			continue
		}
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

// CleanupOldSnapshots keeps only the 10 most recent snapshots
func (sm *SnapshotManager) CleanupOldSnapshots(ctx context.Context) error {
	snapshotIDs, err := sm.ListSnapshots(ctx)
	if err != nil {
		return err
	}

	if len(snapshotIDs) <= 10 {
		return nil // Nothing to cleanup
	}

	// Delete oldest snapshots (keep only first 10, which are most recent due to sorting)
	toDelete := snapshotIDs[10:]
	for _, snapshotID := range toDelete {
		key := fmt.Sprintf("vuln:snapshot:%s", snapshotID)
		if err := sm.kvStore.DeleteValue(ctx, key); err != nil {
			// Log but continue cleanup
			slog.Warn("Failed to delete old snapshot", "key", key, "error", err)
		}
	}

	return nil
}

// GetLatestSnapshot retrieves the most recent snapshot
func (sm *SnapshotManager) GetLatestSnapshot(ctx context.Context) (*store.VulnerabilitySnapshot, error) {
	snapshotIDs, err := sm.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}

	if len(snapshotIDs) == 0 {
		return nil, fmt.Errorf("no snapshots available")
	}

	return sm.GetSnapshot(ctx, snapshotIDs[0])
}
