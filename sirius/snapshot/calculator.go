package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/store"
)

// SnapshotCalculator handles the calculation and storage of vulnerability snapshots
type SnapshotCalculator struct {
	kvStore store.KVStore
}

// NewSnapshotCalculator creates a new SnapshotCalculator instance
func NewSnapshotCalculator(kvStore store.KVStore) *SnapshotCalculator {
	return &SnapshotCalculator{kvStore: kvStore}
}

// CalculateSnapshot queries PostgreSQL and generates snapshot
// snapshotID can be empty (will auto-generate timestamp-based ID) or a specific ID
func (sc *SnapshotCalculator) CalculateSnapshot(snapshotID string) (*store.VulnerabilitySnapshot, error) {
	db := postgres.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	startTime := time.Now()
	now := time.Now().UTC()

	// Generate timestamp-based snapshot ID if not provided
	if snapshotID == "" {
		// Format: YYYY-MM-DD-HHMMSS (e.g., 2025-11-03-143025)
		snapshotID = now.Format("2006-01-02-150405")
	}

	snapshot := &store.VulnerabilitySnapshot{
		SnapshotID: snapshotID,
		Timestamp:  now,
	}

	// Query 1: Global vulnerability counts by severity
	err := db.Table("vulnerabilities").
		Select(`
			COUNT(*) as total,
			SUM(CASE WHEN risk_score >= 9 THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN risk_score >= 7 AND risk_score < 9 THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN risk_score >= 4 AND risk_score < 7 THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN risk_score > 0 AND risk_score < 4 THEN 1 ELSE 0 END) as low,
			SUM(CASE WHEN risk_score = 0 THEN 1 ELSE 0 END) as informational
		`).
		Joins("JOIN host_vulnerabilities ON vulnerabilities.id = host_vulnerabilities.vulnerability_id").
		Where("host_vulnerabilities.status = ?", "active").
		Scan(&snapshot.Counts).Error

	if err != nil {
		return nil, fmt.Errorf("failed to calculate global counts: %w", err)
	}

	// Query 2: Per-host vulnerability breakdown
	type hostStat struct {
		HostIP        string
		Hostname      string
		Total         int
		Critical      int
		High          int
		Medium        int
		Low           int
		Informational int
	}

	var hostStats []hostStat
	err = db.Table("hosts").
		Select(`
			hosts.ip as host_ip,
			hosts.hostname,
			COUNT(vulnerabilities.id) as total,
			SUM(CASE WHEN vulnerabilities.risk_score >= 9 THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN vulnerabilities.risk_score >= 7 AND vulnerabilities.risk_score < 9 THEN 1 ELSE 0 END) as high,
			SUM(CASE WHEN vulnerabilities.risk_score >= 4 AND vulnerabilities.risk_score < 7 THEN 1 ELSE 0 END) as medium,
			SUM(CASE WHEN vulnerabilities.risk_score > 0 AND vulnerabilities.risk_score < 4 THEN 1 ELSE 0 END) as low,
			SUM(CASE WHEN vulnerabilities.risk_score = 0 THEN 1 ELSE 0 END) as informational
		`).
		Joins("JOIN host_vulnerabilities ON host_vulnerabilities.host_id = hosts.id").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = host_vulnerabilities.vulnerability_id").
		Where("host_vulnerabilities.status = ?", "active").
		Group("hosts.id, hosts.ip, hosts.hostname").
		Having("COUNT(vulnerabilities.id) > 0").
		Scan(&hostStats).Error

	if err != nil {
		return nil, fmt.Errorf("failed to calculate per-host stats: %w", err)
	}

	// Convert to snapshot format
	snapshot.ByHost = make([]store.HostVulnerabilityStat, len(hostStats))
	for i, hs := range hostStats {
		snapshot.ByHost[i] = store.HostVulnerabilityStat{
			HostIP:        hs.HostIP,
			Hostname:      hs.Hostname,
			Total:         hs.Total,
			Critical:      hs.Critical,
			High:          hs.High,
			Medium:        hs.Medium,
			Low:           hs.Low,
			Informational: hs.Informational,
		}
	}

	// Query 3: Metadata
	var totalHosts, hostsWithVulns int64
	db.Table("hosts").Count(&totalHosts)
	db.Table("hosts").
		Joins("JOIN host_vulnerabilities ON host_vulnerabilities.host_id = hosts.id").
		Where("host_vulnerabilities.status = ?", "active").
		Distinct("hosts.id").
		Count(&hostsWithVulns)

	var scanCoveragePercent float64
	if totalHosts > 0 {
		scanCoveragePercent = float64(hostsWithVulns) / float64(totalHosts) * 100
	}

	snapshot.Metadata = store.SnapshotMetadata{
		TotalHosts:               int(totalHosts),
		HostsWithVulnerabilities: int(hostsWithVulns),
		ScanCoveragePercent:      scanCoveragePercent,
		SnapshotDurationMs:       time.Since(startTime).Milliseconds(),
	}

	return snapshot, nil
}

// SaveSnapshot stores snapshot in Valkey
func (sc *SnapshotCalculator) SaveSnapshot(ctx context.Context, snapshot *store.VulnerabilitySnapshot) error {
	key := fmt.Sprintf("vuln:snapshot:%s", snapshot.SnapshotID)

	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	return sc.kvStore.SetValue(ctx, key, string(data))
}

