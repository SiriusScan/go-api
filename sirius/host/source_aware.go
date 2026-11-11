package host

import (
	"fmt"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

// AddHostWithSource atomically persists one source-attributed report.
func AddHostWithSource(host sirius.Host, source models.ScanSource) error {
	return AddReport(Report{Host: host, Source: source})
}

// REMOVED: UpdateVulnerabilitiesWithSource and UpdatePortsWithSource
// These functions have been replaced by repository pattern methods:
// - HostRepository.UpsertVulnerability() and LinkHostVulnerability()
// - HostRepository.UpsertHostPort()

// GetHostWithSources retrieves a host with all source-attributed data
func GetHostWithSources(ip string) (models.HostWithSources, error) {
	db := postgres.GetDB()
	var result models.HostWithSources

	// Get the host
	err := db.Where("ip = ? AND owner_subject_id = ?", ip, "").First(&result.Host).Error
	if err != nil {
		return result, fmt.Errorf("host %s not found: %w", ip, err)
	}

	// Get vulnerabilities with source attribution
	vulnSources, err := (&HostRepository{db: db}).getVulnerabilitySources(result.Host.ID)
	if err != nil {
		return result, fmt.Errorf("error retrieving vulnerability sources: %w", err)
	}
	result.VulnerabilitySources = vulnSources

	// Get ports with source attribution
	portSources, err := (&HostRepository{db: db}).getPortSources(result.Host.ID)
	if err != nil {
		return result, fmt.Errorf("error retrieving port sources: %w", err)
	}
	result.PortSources = portSources

	// Get list of all sources that have scanned this host
	var sources []string
	db.Table("host_vulnerabilities").
		Select("DISTINCT source").
		Where("host_id = ?", result.Host.ID).
		Pluck("source", &sources)

	var portSourcesList []string
	db.Table("host_ports").
		Select("DISTINCT source").
		Where("host_id = ?", result.Host.ID).
		Pluck("source", &portSourcesList)

	// Merge and deduplicate sources
	sourceMap := make(map[string]bool)
	for _, s := range sources {
		sourceMap[s] = true
	}
	for _, s := range portSourcesList {
		sourceMap[s] = true
	}

	result.Sources = make([]string, 0, len(sourceMap))
	for source := range sourceMap {
		result.Sources = append(result.Sources, source)
	}

	return result, nil
}

// GetVulnerabilityHistory gets the source history for a specific vulnerability on a host
func GetVulnerabilityHistory(hostID uint, vulnID uint) ([]models.SourceAttribution, error) {
	db := postgres.GetDB()
	var history []models.SourceAttribution

	err := db.Table("host_vulnerabilities hv").
		Select("hv.source, hv.source_version, hv.first_seen, hv.last_seen, hv.status, hv.confidence, hv.notes").
		Joins("JOIN hosts h ON h.id = hv.host_id").
		Where("hv.host_id = ? AND hv.vulnerability_id = ? AND h.owner_subject_id = ? AND h.deleted_at IS NULL", hostID, vulnID, "").
		Order("first_seen ASC").
		Scan(&history).Error

	return history, err
}

// GetSourceCoverageStats gets statistics about scan source coverage
func GetSourceCoverageStats() ([]models.SourceCoverageStats, error) {
	db := postgres.GetDB()
	var stats []models.SourceCoverageStats

	err := db.Raw(`
		SELECT 
			source,
			COUNT(DISTINCT host_id) as hosts_scanned,
			COUNT(DISTINCT vulnerability_id) as vulns_found,
			MAX(last_seen) as last_scan_time,
			AVG(confidence) as average_confidence
		FROM host_vulnerabilities 
		WHERE status = 'active' AND host_id IN (SELECT id FROM hosts WHERE owner_subject_id = '' AND deleted_at IS NULL)
		GROUP BY source
		UNION ALL
		SELECT 
			source,
			COUNT(DISTINCT host_id) as hosts_scanned,
			0 as vulns_found,
			MAX(last_seen) as last_scan_time,
			1.0 as average_confidence
		FROM host_ports 
		WHERE status = 'active' AND host_id IN (SELECT id FROM hosts WHERE owner_subject_id = '' AND deleted_at IS NULL) AND source NOT IN (
			SELECT DISTINCT source FROM host_vulnerabilities WHERE status = 'active' AND host_id IN (SELECT id FROM hosts WHERE owner_subject_id = '' AND deleted_at IS NULL)
		)
		GROUP BY source
	`).Scan(&stats).Error

	return stats, err
}

// GetVulnerabilitySources gets all sources that have reported a specific vulnerability
func GetVulnerabilitySources(vulnID string) ([]models.VulnerabilitySourceInfo, error) {
	db := postgres.GetDB()
	var sources []models.VulnerabilitySourceInfo

	err := db.Table("host_vulnerabilities hv").
		Select(`hv.source, hv.source_version, 
				COUNT(DISTINCT hv.host_id) as affected_hosts,
				MIN(hv.first_seen) as first_detected,
				MAX(hv.last_seen) as last_confirmed,
				AVG(hv.confidence) as average_confidence,
				COUNT(*) as total_reports`).
		Joins("JOIN vulnerabilities v ON hv.vulnerability_id = v.id").
		Joins("JOIN hosts h ON hv.host_id = h.id AND h.deleted_at IS NULL AND h.owner_subject_id = ''").
		Where("v.v_id = ? AND hv.status = 'active'", vulnID).
		Group("hv.source, hv.source_version").
		Order("first_detected ASC").
		Scan(&sources).Error

	return sources, err
}

// DetermineSourceFromContext attempts to determine scan source from various context clues
func DetermineSourceFromContext(userAgent, referer, ipAddress string) models.ScanSource {
	// Default fallback source
	source := models.ScanSource{
		Name:    "unknown",
		Version: "unknown",
		Config:  "",
	}

	// Try to determine source from various context clues
	if userAgent != "" {
		if contains(userAgent, "nmap") {
			source.Name = "nmap"
			source.Version = extractVersion(userAgent, "nmap")
		} else if contains(userAgent, "rustscan") {
			source.Name = "rustscan"
			source.Version = extractVersion(userAgent, "rustscan")
		} else if contains(userAgent, "agent") {
			source.Name = "agent"
			source.Version = extractVersion(userAgent, "agent")
		}
	}

	// Add context information
	if referer != "" {
		source.Config += fmt.Sprintf("referer:%s", referer)
	}
	if ipAddress != "" {
		source.Config += fmt.Sprintf(" ip:%s", ipAddress)
	}

	return source
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

func extractVersion(userAgent, tool string) string {
	// Simple version extraction - can be enhanced
	if userAgent == "" {
		return "unknown"
	}
	// For now, return a placeholder
	return "detected"
}

// AddHostWithSourceAndJSONB atomically persists the report and enhanced inventory.
func AddHostWithSourceAndJSONB(host sirius.Host, source models.ScanSource,
	softwareInventory, systemFingerprint, agentMetadata map[string]interface{}) error {
	return AddReport(Report{Host: host, Source: source,
		SoftwareInventory: softwareInventory, SystemFingerprint: systemFingerprint, AgentMetadata: agentMetadata})
}
