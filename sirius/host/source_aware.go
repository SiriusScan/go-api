package host

import (
	"fmt"
	"log"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

// AddHostWithSource adds or updates a host with source attribution using repository pattern
func AddHostWithSource(host sirius.Host, source models.ScanSource) error {
	log.Printf("Adding/updating host %s with source %s (version: %s)", host.IP, source.Name, source.Version)

	repo := NewHostRepository()

	// 1. Upsert host entity (basic fields only)
	hostID, err := repo.UpsertHost(host.IP, host.Hostname, host.OS, host.OSVersion, host.HID)
	if err != nil {
		return fmt.Errorf("failed to upsert host: %w", err)
	}

	// 2. Process ports
	for _, port := range host.Ports {
		portID, err := repo.UpsertPort(port.Number, port.Protocol, port.State)
		if err != nil {
			return fmt.Errorf("failed to upsert port %d/%s: %w", port.Number, port.Protocol, err)
		}

		// Link host-port with source attribution
		err = repo.LinkHostPort(hostID, portID, source)
		if err != nil {
			return fmt.Errorf("failed to link host-port: %w", err)
		}
	}

	// 3. Process vulnerabilities
	for _, vuln := range host.Vulnerabilities {
		vulnID, err := repo.UpsertVulnerability(vuln.VID, vuln.Title, vuln.Description, vuln.RiskScore)
		if err != nil {
			return fmt.Errorf("failed to upsert vulnerability %s: %w", vuln.VID, err)
		}

		// Link host-vulnerability with source attribution
		err = repo.LinkHostVulnerability(hostID, vulnID, source)
		if err != nil {
			return fmt.Errorf("failed to link host-vulnerability: %w", err)
		}
	}

	// 4. Record scan history
	err = recordScanHistory(hostID, source, len(host.Vulnerabilities)+len(host.Ports))
	if err != nil {
		log.Printf("Warning: Failed to record scan history for %s: %v", host.IP, err)
	}

	log.Printf("Successfully processed host %s with source %s", host.IP, source.Name)
	return nil
}

// REMOVED: UpdateVulnerabilitiesWithSource and UpdatePortsWithSource
// These functions have been replaced by repository pattern methods:
// - HostRepository.UpsertVulnerability() and LinkHostVulnerability()
// - HostRepository.UpsertPort() and LinkHostPort()

// GetHostWithSources retrieves a host with all source-attributed data
func GetHostWithSources(ip string) (models.HostWithSources, error) {
	db := postgres.GetDB()
	var result models.HostWithSources

	// Get the host
	err := db.Where("ip = ?", ip).First(&result.Host).Error
	if err != nil {
		return result, fmt.Errorf("host %s not found: %w", ip, err)
	}

	// Get vulnerabilities with source attribution
	var vulnSources []models.VulnerabilityWithSource
	err = db.Table("host_vulnerabilities hv").
		Select(`v.*, hv.source, hv.source_version, hv.first_seen, hv.last_seen, 
				hv.status, hv.confidence, hv.port, hv.service_info, hv.notes`).
		Joins("JOIN vulnerabilities v ON hv.vulnerability_id = v.id").
		Where("hv.host_id = ?", result.Host.ID).
		Scan(&vulnSources).Error
	if err != nil {
		return result, fmt.Errorf("error retrieving vulnerability sources: %w", err)
	}
	result.VulnerabilitySources = vulnSources

	// Get ports with source attribution
	var portSources []models.PortWithSource
	err = db.Table("host_ports hp").
		Select(`p.*, hp.source, hp.source_version, hp.first_seen, hp.last_seen, 
				hp.status, hp.notes`).
		Joins("JOIN ports p ON hp.port_id = p.id").
		Where("hp.host_id = ?", result.Host.ID).
		Scan(&portSources).Error
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

	err := db.Table("host_vulnerabilities").
		Select("source, source_version, first_seen, last_seen, status, confidence, notes").
		Where("host_id = ? AND vulnerability_id = ?", hostID, vulnID).
		Order("first_seen ASC").
		Scan(&history).Error

	return history, err
}

// recordScanHistory records a scan event in the scan history table
func recordScanHistory(hostID uint, source models.ScanSource, findingsCount int) error {
	db := postgres.GetDB()

	entry := models.ScanHistoryEntry{
		HostID:        hostID,
		Source:        source.Name,
		SourceVersion: source.Version,
		ScanTime:      time.Now(),
		FindingsCount: findingsCount,
		ScanConfig:    source.Config,
	}

	return db.Create(&entry).Error
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
		WHERE status = 'active'
		GROUP BY source
		UNION ALL
		SELECT 
			source,
			COUNT(DISTINCT host_id) as hosts_scanned,
			0 as vulns_found,
			MAX(last_seen) as last_scan_time,
			1.0 as average_confidence
		FROM host_ports 
		WHERE status = 'active' AND source NOT IN (
			SELECT DISTINCT source FROM host_vulnerabilities WHERE status = 'active'
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

// AddHostWithSourceAndJSONB adds or updates a host with source attribution and JSONB data using repository pattern
func AddHostWithSourceAndJSONB(host sirius.Host, source models.ScanSource,
	softwareInventory, systemFingerprint, agentMetadata map[string]interface{}) error {
	log.Printf("Adding/updating host %s with source %s and enhanced JSONB data", host.IP, source.Name)

	repo := NewHostRepository()

	// 1. Upsert host entity (basic fields only)
	hostID, err := repo.UpsertHost(host.IP, host.Hostname, host.OS, host.OSVersion, host.HID)
	if err != nil {
		return fmt.Errorf("failed to upsert host: %w", err)
	}

	// 2. Update JSONB fields if provided
	if len(softwareInventory) > 0 || len(systemFingerprint) > 0 || len(agentMetadata) > 0 {
		err = repo.UpdateHostJSONB(hostID, softwareInventory, systemFingerprint, agentMetadata)
		if err != nil {
			return fmt.Errorf("failed to update JSONB fields: %w", err)
		}
		if len(softwareInventory) > 0 {
			log.Printf("Added software inventory data for host %s (%d fields)", host.IP, len(softwareInventory))
		}
		if len(systemFingerprint) > 0 {
			log.Printf("Added system fingerprint data for host %s (%d fields)", host.IP, len(systemFingerprint))
		}
		if len(agentMetadata) > 0 {
			log.Printf("Added agent metadata for host %s (%d fields)", host.IP, len(agentMetadata))
		}
	}

	// 3. Process ports
	for _, port := range host.Ports {
		portID, err := repo.UpsertPort(port.Number, port.Protocol, port.State)
		if err != nil {
			return fmt.Errorf("failed to upsert port %d/%s: %w", port.Number, port.Protocol, err)
		}

		// Link host-port with source attribution
		err = repo.LinkHostPort(hostID, portID, source)
		if err != nil {
			return fmt.Errorf("failed to link host-port: %w", err)
		}
	}

	// 4. Process vulnerabilities
	for _, vuln := range host.Vulnerabilities {
		vulnID, err := repo.UpsertVulnerability(vuln.VID, vuln.Title, vuln.Description, vuln.RiskScore)
		if err != nil {
			return fmt.Errorf("failed to upsert vulnerability %s: %w", vuln.VID, err)
		}

		// Link host-vulnerability with source attribution
		err = repo.LinkHostVulnerability(hostID, vulnID, source)
		if err != nil {
			return fmt.Errorf("failed to link host-vulnerability: %w", err)
		}
	}

	// 5. Record scan history with enhanced data information
	findingsCount := len(host.Vulnerabilities) + len(host.Ports)
	if len(softwareInventory) > 0 {
		findingsCount += 1 // Count software inventory as a finding
	}
	if len(systemFingerprint) > 0 {
		findingsCount += 1 // Count system fingerprint as a finding
	}

	err = recordScanHistory(hostID, source, findingsCount)
	if err != nil {
		log.Printf("Warning: Failed to record scan history for %s: %v", host.IP, err)
	}

	log.Printf("Successfully processed host %s with source %s and JSONB data", host.IP, source.Name)
	return nil
}
