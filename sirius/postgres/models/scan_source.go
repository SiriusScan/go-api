// File: scan_source.go
package models

import (
	"time"

	"gorm.io/gorm"
)

// ScanSource represents the metadata about a scan source
type ScanSource struct {
	Name    string `json:"name"`    // "nmap", "agent", "rustscan", "manual"
	Version string `json:"version"` // Tool version
	Config  string `json:"config"`  // Scan configuration used
}

// SourceAttribution contains source and temporal information for any finding
type SourceAttribution struct {
	Source        string    `json:"source"`
	SourceVersion string    `json:"source_version"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
	Confidence    float64   `json:"confidence"`
	Notes         string    `json:"notes,omitempty"`
}

// HostWithSources represents a host with source-attributed data
type HostWithSources struct {
	Host
	VulnerabilitySources []VulnerabilityWithSource `json:"vulnerability_sources"`
	PortSources          []PortWithSource          `json:"port_sources"`
	Sources              []string                  `json:"sources"` // List of all sources that scanned this host
}

// VulnerabilityWithSource represents a vulnerability with its source attribution
type VulnerabilityWithSource struct {
	Vulnerability
	SourceAttribution
	Port        *int   `json:"port,omitempty"`
	ServiceInfo string `json:"service_info,omitempty"`
}

// PortWithSource represents a port with its source attribution
type PortWithSource struct {
	Port
	SourceAttribution
}

// ScanHistory represents the timeline of scans for a host
type ScanHistoryEntry struct {
	gorm.Model               // Provides ID, CreatedAt, UpdatedAt, DeletedAt
	HostID        uint      `json:"host_id"`
	Source        string    `json:"source"`
	SourceVersion string    `json:"source_version"`
	ScanTime      time.Time `json:"scan_time"`
	FindingsCount int       `json:"findings_count"`
	ScanConfig    string    `json:"scan_config,omitempty"`
	Notes         string    `json:"notes,omitempty"`
}

// SourceCoverage represents statistics about source coverage
type SourceCoverageStats struct {
	Source            string    `json:"source"`
	HostsScanned      int       `json:"hosts_scanned"`
	VulnsFound        int       `json:"vulnerabilities_found"`
	PortsDiscovered   int       `json:"ports_discovered"`
	LastScanTime      time.Time `json:"last_scan_time"`
	AverageConfidence float64   `json:"average_confidence"`
}

// VulnerabilitySourceInfo represents information about sources that reported a vulnerability
type VulnerabilitySourceInfo struct {
	Source            string    `json:"source"`
	SourceVersion     string    `json:"source_version"`
	AffectedHosts     int       `json:"affected_hosts"`
	FirstDetected     time.Time `json:"first_detected"`
	LastConfirmed     time.Time `json:"last_confirmed"`
	AverageConfidence float64   `json:"average_confidence"`
	TotalReports      int       `json:"total_reports"`
}
 