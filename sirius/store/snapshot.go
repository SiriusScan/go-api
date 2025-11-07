package store

import "time"

// VulnerabilitySnapshot represents a point-in-time vulnerability state
type VulnerabilitySnapshot struct {
	SnapshotID string                  `json:"snapshot_id"` // YYYY-MM-DD format
	Timestamp  time.Time               `json:"timestamp"`
	Counts    VulnerabilityCounts     `json:"counts"`
	ByHost     []HostVulnerabilityStat `json:"by_host"`
	Metadata   SnapshotMetadata        `json:"metadata"`
}

// VulnerabilityCounts represents the total counts of vulnerabilities by severity
type VulnerabilityCounts struct {
	Total         int `json:"total"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

// HostVulnerabilityStat represents vulnerability statistics for a specific host
type HostVulnerabilityStat struct {
	HostIP        string `json:"host_ip"`
	Hostname      string `json:"hostname,omitempty"`
	Total         int    `json:"total"`
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	Medium        int    `json:"medium"`
	Low           int    `json:"low"`
	Informational int    `json:"informational"`
}

// SnapshotMetadata contains metadata about the snapshot
type SnapshotMetadata struct {
	TotalHosts               int     `json:"total_hosts"`
	HostsWithVulnerabilities int     `json:"hosts_with_vulnerabilities"`
	ScanCoveragePercent      float64 `json:"scan_coverage_percent"`
	SnapshotDurationMs       int64   `json:"snapshot_duration_ms"`
}

