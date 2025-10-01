package host

import (
	"fmt"
	"log"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

// AddHostWithSource adds or updates a host with source attribution
func AddHostWithSource(host sirius.Host, source models.ScanSource) error {
	log.Printf("Adding/updating host %s with source %s (version: %s)", host.IP, source.Name, source.Version)

	dbHost := MapSiriusHostToDBHost(host)
	db := postgres.GetDB()

	// Find existing host
	var existingHost models.Host
	result := db.Where("ip = ?", host.IP).First(&existingHost)

	if result.Error == nil {
		// Host exists - update with source-aware logic
		log.Printf("Updating existing host %s with source-aware logic", host.IP)

		// Update host basic info
		err := db.Model(&existingHost).Updates(dbHost).Error
		if err != nil {
			return fmt.Errorf("error updating host %s: %w", host.IP, err)
		}

		// Update vulnerabilities with source awareness
		err = UpdateVulnerabilitiesWithSource(existingHost.ID, dbHost.Vulnerabilities, source)
		if err != nil {
			return fmt.Errorf("error updating vulnerabilities for host %s: %w", host.IP, err)
		}

		// Update ports with source awareness
		err = UpdatePortsWithSource(existingHost.ID, dbHost.Ports, source)
		if err != nil {
			return fmt.Errorf("error updating ports for host %s: %w", host.IP, err)
		}

		log.Printf("Successfully updated host %s with source %s", host.IP, source.Name)
	} else {
		// Create new host
		log.Printf("Creating new host %s with source %s", host.IP, source.Name)

		err := db.Create(&dbHost).Error
		if err != nil {
			return fmt.Errorf("error creating host %s: %w", host.IP, err)
		}

		// Add vulnerabilities with source info
		err = UpdateVulnerabilitiesWithSource(dbHost.ID, dbHost.Vulnerabilities, source)
		if err != nil {
			return fmt.Errorf("error adding vulnerabilities for new host %s: %w", host.IP, err)
		}

		// Add ports with source info
		err = UpdatePortsWithSource(dbHost.ID, dbHost.Ports, source)
		if err != nil {
			return fmt.Errorf("error adding ports for new host %s: %w", host.IP, err)
		}

		log.Printf("Successfully created host %s with source %s", host.IP, source.Name)
	}

	// Record scan history
	err := recordScanHistory(dbHost.ID, source, len(dbHost.Vulnerabilities)+len(dbHost.Ports))
	if err != nil {
		log.Printf("Warning: Failed to record scan history for %s: %v", host.IP, err)
	}

	return nil
}

// UpdateVulnerabilitiesWithSource updates vulnerability associations with source attribution
func UpdateVulnerabilitiesWithSource(hostID uint, vulnerabilities []models.Vulnerability, source models.ScanSource) error {
	db := postgres.GetDB()
	now := time.Now()

	for _, vuln := range vulnerabilities {
		// Ensure vulnerability exists in vulnerabilities table
		var existingVuln models.Vulnerability
		err := db.Where("v_id = ?", vuln.VID).First(&existingVuln).Error
		if err != nil {
			// Create vulnerability if it doesn't exist
			err = db.Create(&vuln).Error
			if err != nil {
				return fmt.Errorf("error creating vulnerability %s: %w", vuln.VID, err)
			}
			existingVuln = vuln
		}

		// Check if this host-vulnerability-source combination already exists
		var hostVuln models.HostVulnerability
		err = db.Where("host_id = ? AND vulnerability_id = ? AND source = ?",
			hostID, existingVuln.ID, source.Name).First(&hostVuln).Error

		if err != nil {
			// Create new host-vulnerability relationship with source
			hostVuln = models.HostVulnerability{
				HostID:          hostID,
				VulnerabilityID: existingVuln.ID,
				Source:          source.Name,
				SourceVersion:   source.Version,
				FirstSeen:       now,
				LastSeen:        now,
				Status:          "active",
				Confidence:      1.0,
				Notes:           source.Config,
			}
			err = db.Create(&hostVuln).Error
			if err != nil {
				return fmt.Errorf("error creating host-vulnerability relationship: %w", err)
			}
			log.Printf("Created new vulnerability %s for host %d from source %s",
				vuln.VID, hostID, source.Name)
		} else {
			// Update existing relationship - refresh last_seen time
			// Use Updates() instead of Save() to avoid primary key constraint issues
			err = db.Model(&models.HostVulnerability{}).
				Where("host_id = ? AND vulnerability_id = ? AND source = ?", hostID, existingVuln.ID, source.Name).
				Updates(map[string]interface{}{
					"last_seen":      now,
					"source_version": source.Version,
					"status":         "active", // Re-activate if it was previously resolved
					"notes":          source.Config,
				}).Error
			if err != nil {
				return fmt.Errorf("error updating host-vulnerability relationship: %w", err)
			}
			log.Printf("Updated existing vulnerability %s for host %d from source %s",
				vuln.VID, hostID, source.Name)
		}
	}

	return nil
}

// UpdatePortsWithSource updates port associations with source attribution
func UpdatePortsWithSource(hostID uint, ports []models.Port, source models.ScanSource) error {
	db := postgres.GetDB()
	now := time.Now()

	for _, port := range ports {
		// Ensure port exists in ports table using FirstOrCreate for upsert
		var existingPort models.Port
		err := db.Where("id = ? AND protocol = ?", port.ID, port.Protocol).FirstOrCreate(&existingPort, port).Error
		if err != nil {
			return fmt.Errorf("error ensuring port %d/%s exists: %w", port.ID, port.Protocol, err)
		}

		// Check if this host-port-source combination already exists
		var hostPort models.HostPort
		err = db.Where("host_id = ? AND port_id = ? AND source = ?",
			hostID, existingPort.ID, source.Name).First(&hostPort).Error

		if err != nil {
			// Create new host-port relationship with source
			hostPort = models.HostPort{
				HostID:        hostID,
				PortID:        uint(existingPort.ID),
				Source:        source.Name,
				SourceVersion: source.Version,
				FirstSeen:     now,
				LastSeen:      now,
				Status:        "active",
				Notes:         source.Config,
			}
			err = db.Create(&hostPort).Error
			if err != nil {
				return fmt.Errorf("error creating host-port relationship: %w", err)
			}
			log.Printf("Created new port %d/%s for host %d from source %s",
				port.ID, port.Protocol, hostID, source.Name)
		} else {
			// Update existing relationship - refresh last_seen time
			// Use Updates() instead of Save() to avoid primary key constraint issues
			err = db.Model(&models.HostPort{}).
				Where("host_id = ? AND port_id = ? AND source = ?", hostID, existingPort.ID, source.Name).
				Updates(map[string]interface{}{
					"last_seen":      now,
					"source_version": source.Version,
					"status":         "active", // Re-activate if it was previously closed
					"notes":          source.Config,
				}).Error
			if err != nil {
				return fmt.Errorf("error updating host-port relationship: %w", err)
			}
			log.Printf("Updated existing port %d/%s for host %d from source %s",
				port.ID, port.Protocol, hostID, source.Name)
		}
	}

	return nil
}

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

// AddHostWithSourceAndJSONB adds or updates a host with source attribution and JSONB data
func AddHostWithSourceAndJSONB(host sirius.Host, source models.ScanSource,
	softwareInventory, systemFingerprint, agentMetadata map[string]interface{}) error {
	log.Printf("Adding/updating host %s with source %s and enhanced JSONB data", host.IP, source.Name)

	dbHost := MapSiriusHostToDBHost(host)

	// Populate JSONB fields - Convert map[string]interface{} to JSONB type
	if len(softwareInventory) > 0 {
		dbHost.SoftwareInventory = models.JSONB(softwareInventory)
		log.Printf("Added software inventory data for host %s (%d fields)", host.IP, len(softwareInventory))
	}
	if len(systemFingerprint) > 0 {
		dbHost.SystemFingerprint = models.JSONB(systemFingerprint)
		log.Printf("Added system fingerprint data for host %s (%d fields)", host.IP, len(systemFingerprint))
	}
	if len(agentMetadata) > 0 {
		dbHost.AgentMetadata = models.JSONB(agentMetadata)
		log.Printf("Added agent metadata for host %s (%d fields)", host.IP, len(agentMetadata))
	}

	db := postgres.GetDB()

	// Find existing host
	var existingHost models.Host
	result := db.Where("ip = ?", host.IP).First(&existingHost)

	if result.Error == nil {
		// Host exists - update with source-aware logic and JSONB data
		log.Printf("Updating existing host %s with source-aware logic and JSONB data", host.IP)

		// Update host basic info and JSONB fields
		err := db.Model(&existingHost).Updates(dbHost).Error
		if err != nil {
			return fmt.Errorf("error updating host %s: %w", host.IP, err)
		}

		// Update vulnerabilities with source awareness
		err = UpdateVulnerabilitiesWithSource(existingHost.ID, dbHost.Vulnerabilities, source)
		if err != nil {
			return fmt.Errorf("error updating vulnerabilities for host %s: %w", host.IP, err)
		}

		// Update ports with source awareness
		err = UpdatePortsWithSource(existingHost.ID, dbHost.Ports, source)
		if err != nil {
			return fmt.Errorf("error updating ports for host %s: %w", host.IP, err)
		}

		log.Printf("Successfully updated host %s with source %s and JSONB data", host.IP, source.Name)
	} else {
		// Create new host with JSONB data
		log.Printf("Creating new host %s with source %s and JSONB data", host.IP, source.Name)

		err := db.Create(&dbHost).Error
		if err != nil {
			return fmt.Errorf("error creating host %s: %w", host.IP, err)
		}

		// Add vulnerabilities with source info
		err = UpdateVulnerabilitiesWithSource(dbHost.ID, dbHost.Vulnerabilities, source)
		if err != nil {
			return fmt.Errorf("error adding vulnerabilities for new host %s: %w", host.IP, err)
		}

		// Add ports with source info
		err = UpdatePortsWithSource(dbHost.ID, dbHost.Ports, source)
		if err != nil {
			return fmt.Errorf("error adding ports for new host %s: %w", host.IP, err)
		}

		log.Printf("Successfully created host %s with source %s and JSONB data", host.IP, source.Name)
	}

	// Record scan history with enhanced data information
	findingsCount := len(dbHost.Vulnerabilities) + len(dbHost.Ports)
	if len(softwareInventory) > 0 {
		findingsCount += 1 // Count software inventory as a finding
	}
	if len(systemFingerprint) > 0 {
		findingsCount += 1 // Count system fingerprint as a finding
	}

	err := recordScanHistory(dbHost.ID, source, findingsCount)
	if err != nil {
		log.Printf("Warning: Failed to record scan history for %s: %v", host.IP, err)
	}

	return nil
}
