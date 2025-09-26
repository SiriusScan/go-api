package host

import (
	"fmt"
	"log"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func GetHost(ip string) (sirius.Host, error) {
	db := postgres.GetDB()

	// Check if database is available
	if db == nil {
		log.Printf("Warning: Database not available, cannot retrieve host %s", ip)
		return sirius.Host{IP: ip}, fmt.Errorf("database connection not available")
	}

	var dbHost models.Host
	result := db.Preload("Ports").Preload("Vulnerabilities").Preload("Services").Where("ip = ?", ip).First(&dbHost)

	if result.Error != nil {
		return sirius.Host{}, result.Error
	}

	// Map the database host to a sirius.Host
	host := MapDBHostToSiriusHost(dbHost)

	return host, nil
}

func GetAllHosts() ([]sirius.Host, error) {
	db := postgres.GetDB()

	dbHosts, err := postgres.GetAllHosts(db)
	if err != nil {
		return nil, err
	}

	var siriusHosts []sirius.Host
	for _, dbHost := range dbHosts {
		siriusHosts = append(siriusHosts, MapDBHostToSiriusHost(dbHost))
	}

	return siriusHosts, nil
}

// HostVulnerabilitySeverityCounts holds the count of vulnerabilities by severity for a given host.
type HostVulnerabilitySeverityCounts struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

// HostRiskStats holds aggregated risk score statistics for vulnerabilities on a host.
type HostRiskStats struct {
	VulnerabilityCount int                             `json:"vulnerabilityCount" gorm:"column:vulnerability_count"`
	TotalRiskScore     float64                         `json:"totalRiskScore" gorm:"column:total_risk_score"`
	AverageRiskScore   float64                         `json:"averageRiskScore" gorm:"column:average_risk_score"`
	HostSeverityCounts HostVulnerabilitySeverityCounts `json:"hostSeverityCounts" gorm:"-"`
	SoftwareStats      *SoftwareStatistics             `json:"softwareStats,omitempty" gorm:"-"`
	LastUpdated        string                          `json:"lastUpdated,omitempty" gorm:"-"`
}

// GetHostRiskStatistics returns aggregated risk statistics for vulnerabilities on a given host identified by its IP.
func GetHostRiskStatistics(ip string) (HostRiskStats, error) {
	db := postgres.GetDB()

	var stats HostRiskStats
	// We join the hosts, host_vulnerabilities, and vulnerabilities tables in order to:
	//   - Filter on the host with the given IP
	//   - Aggregate the risk scores for vulnerabilities associated with that host.
	err := db.Table("hosts").
		Select("count(vulnerabilities.id) as vulnerability_count, sum(vulnerabilities.risk_score) as total_risk_score, avg(vulnerabilities.risk_score) as average_risk_score").
		Joins("JOIN host_vulnerabilities ON host_vulnerabilities.host_id = hosts.id").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = host_vulnerabilities.vulnerability_id").
		Where("hosts.ip = ?", ip).
		Scan(&stats).Error

	if err != nil {
		return stats, err
	}

	stats.HostSeverityCounts, err = GetHostVulnerabilitySeverityCounts(ip)
	if err != nil {
		return stats, err
	}

	// Add software inventory statistics if available
	softwareStats, err := GetHostSoftwareStatistics(ip)
	if err == nil && softwareStats.TotalPackages > 0 {
		stats.SoftwareStats = softwareStats
		if softwareStats.LastUpdated != "" {
			stats.LastUpdated = softwareStats.LastUpdated
		}
	}

	return stats, nil
}

// GetHostVulnerabilitySeverityCounts retrieves vulnerability severity counts for a host identified by its IP.
func GetHostVulnerabilitySeverityCounts(ip string) (HostVulnerabilitySeverityCounts, error) {
	db := postgres.GetDB()

	var severityCounts HostVulnerabilitySeverityCounts
	// Build the query:
	// 1. Start from the hosts table.
	// 2. Join with the host_vulnerabilities table, and then vulnerabilities.
	// 3. Filter by the provided IP.
	// 4. Use SUM with CASE expressions to count how many vulnerabilities fall into each severity bucket.
	err := db.Table("hosts").
		Select(
			`SUM(CASE WHEN vulnerabilities.risk_score >= 9 THEN 1 ELSE 0 END) as critical, 
             SUM(CASE WHEN vulnerabilities.risk_score >= 7 AND vulnerabilities.risk_score < 9 THEN 1 ELSE 0 END) as high, 
             SUM(CASE WHEN vulnerabilities.risk_score >= 4 AND vulnerabilities.risk_score < 7 THEN 1 ELSE 0 END) as medium, 
             SUM(CASE WHEN vulnerabilities.risk_score > 0 AND vulnerabilities.risk_score < 4 THEN 1 ELSE 0 END) as low, 
             SUM(CASE WHEN vulnerabilities.risk_score = 0 THEN 1 ELSE 0 END) as informational`).
		Joins("JOIN host_vulnerabilities ON host_vulnerabilities.host_id = hosts.id").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = host_vulnerabilities.vulnerability_id").
		Where("hosts.ip = ?", ip).
		Scan(&severityCounts).Error

	if err != nil {
		return severityCounts, err
	}

	return severityCounts, nil
}

// VulnerabilitySummary represents a vulnerability with its associated host count
type VulnerabilitySummary struct {
	VID         string  `json:"vid"`
	Title       string  `json:"title"`
	HostCount   int     `json:"hostCount"`
	Description string  `json:"description"`
	RiskScore   float64 `json:"riskScore"`
}

// GetAllVulnerabilities host/vulnerabilities SDK
func GetAllVulnerabilities() ([]VulnerabilitySummary, error) {
	db := postgres.GetDB()

	var vulnerabilityCounts []VulnerabilitySummary
	err := db.Model(&models.Vulnerability{}).
		Select("vulnerabilities.v_id, vulnerabilities.title, vulnerabilities.description, vulnerabilities.risk_score, count(host_vulnerabilities.host_id) as host_count").
		Joins("left join host_vulnerabilities on host_vulnerabilities.vulnerability_id = vulnerabilities.id").
		Group("vulnerabilities.id").
		Scan(&vulnerabilityCounts).Error

	if err != nil {
		return nil, err
	}
	// log.Println(vulnerabilityCounts)

	// Check for
	// err = db.Model(&models.Vulnerability{}).

	// *** Temporary Patch for NVD Remote Vulnerability Storage ***
	// For each vulnerability listed on a host there may be no corresponding database entry. If the DB entry is missing, retrieve the vulnerability from the NVD API and add it to the database

	// Shouldn't have to reformat the output, but the sql query is weird
	// For each vulnerabilityCounts check HostCount
	// If HostCount is 1 add vulnerabilityCount to new slice (vulnerabilityList) or increment HostCount by 1
	var vulnerabilityList []VulnerabilitySummary
	for _, vulnerabilityCount := range vulnerabilityCounts {
		if vulnerabilityCount.HostCount == 1 {
			// Check vulnerabilityList for existing vulnerabilityCount
			// If found, increment HostCount by 1
			// If not found, add vulnerabilityCount to vulnerabilityList
			var found bool
			for i, vulnerability := range vulnerabilityList {
				if vulnerability.VID == vulnerabilityCount.VID {
					vulnerabilityList[i].HostCount++
					found = true
					break
				}
			}
			if !found {
				vulnerabilityList = append(vulnerabilityList, vulnerabilityCount)
			}
		}
	}
	// log.Println("Vulnerability List:", vulnerabilityList)

	return vulnerabilityList, nil
}

// AddHost Chain: SDK Consumer (e.g. Sirius REST API) -> SDK go-api sirius/host (Here)
func AddHost(host sirius.Host) error {
	log.Printf("Adding or updating host %s in database", host.IP)

	// Get a database connection
	db := postgres.GetDB()

	// Check if database is available
	if db == nil {
		log.Printf("Warning: Database not available, cannot save host %s", host.IP)
		return fmt.Errorf("database connection not available")
	}

	// Map the host to a database model
	dbHost := MapSiriusHostToDBHost(host)

	// Create a separate host for the Where clause
	whereHost := models.Host{IP: dbHost.IP}

	// Find the first host with a matching IP
	var existingHost models.Host
	result := db.Where(&whereHost).First(&existingHost)

	// If a record was found, update it
	if result.RowsAffected > 0 {
		log.Printf("Updating existing host record for %s", host.IP)

		err := db.Model(&existingHost).Updates(&dbHost).Error
		if err != nil {
			log.Printf("Error updating host %s: %v", host.IP, err)
			return fmt.Errorf("error updating host: %w", err)
		}

		// Use source-aware functions instead of Replace (which overwrites ALL data)
		// Use "legacy" as the source for backward compatibility
		legacySource := models.ScanSource{
			Name:    "legacy",
			Version: "unknown",
			Config:  "backward_compatibility",
		}

		// Update vulnerabilities with source awareness (preserves existing data from other sources)
		err = UpdateVulnerabilitiesWithSource(existingHost.ID, dbHost.Vulnerabilities, legacySource)
		if err != nil {
			log.Printf("Error updating host-vulnerability associations for %s: %v", host.IP, err)
			return fmt.Errorf("error updating host-vulnerability associations: %w", err)
		}

		// Update ports with source awareness (preserves existing data from other sources)
		err = UpdatePortsWithSource(existingHost.ID, dbHost.Ports, legacySource)
		if err != nil {
			log.Printf("Error updating host-port associations for %s: %v", host.IP, err)
			return fmt.Errorf("error updating host-port associations: %w", err)
		}

		log.Printf("Successfully updated host %s and its relationships", host.IP)
	} else {
		// If no record was found, create a new one
		log.Printf("Creating new host record for %s", host.IP)

		err := db.Create(&dbHost).Error
		if err != nil {
			log.Printf("Error creating host %s: %v", host.IP, err)
			return fmt.Errorf("error creating host: %w", err)
		}

		// Use source-aware functions for new hosts too
		legacySource := models.ScanSource{
			Name:    "legacy",
			Version: "unknown",
			Config:  "backward_compatibility",
		}

		// Add vulnerabilities with source awareness
		err = UpdateVulnerabilitiesWithSource(dbHost.ID, dbHost.Vulnerabilities, legacySource)
		if err != nil {
			log.Printf("Error adding vulnerabilities for new host %s: %v", host.IP, err)
			return fmt.Errorf("error adding vulnerabilities for new host: %w", err)
		}

		// Add ports with source awareness
		err = UpdatePortsWithSource(dbHost.ID, dbHost.Ports, legacySource)
		if err != nil {
			log.Printf("Error adding ports for new host %s: %v", host.IP, err)
			return fmt.Errorf("error adding ports for new host: %w", err)
		}

		log.Printf("Successfully created host %s", host.IP)
	}

	return nil
}

// DeleteHost handles the POST /host/delete route
// DeleteHost Chain: SDK Consumer (e.g. Sirius REST API) -> SDK go-api sirius/host (Here)
func DeleteHost(ip string) error {
	// fmt.Printf("Deleting host %s from database\n", ip)

	db := postgres.GetDB()

	// Start a transaction
	tx := db.Begin()
	tx = tx.Debug()

	// Delete Host
	if err := tx.Where("ip = ?", ip).Delete(&models.Host{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	tx.Commit()

	return nil
}

// ! Legacy /// Functionality is now included in AddHost
/*
func UpdateHost(host sirius.Host) error {
	fmt.Printf("Updating host %s in database\n", host.IP)

	dbHost := MapSiriusHostToDBHost(host)

	db := postgres.GetDB()

	// Start a transaction
	tx := db.Begin()
	tx = tx.Debug()

	// Update Host
	if err := tx.Model(&models.Host{}).Where("ip = ?", dbHost.IP).Updates(dbHost).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Get the updated host to fetch its ID
	var updatedHost models.Host
	if err := tx.Where("ip = ?", dbHost.IP).First(&updatedHost).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Update or Insert Ports
	for _, port := range dbHost.Ports {
		port.HostID = updatedHost.ID // Set the foreign key
		if err := tx.Where(models.Port{ID: port.ID, HostID: updatedHost.ID}).FirstOrCreate(&port).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	// Update or Insert CVEs
	for _, cve := range dbHost.CVEs {
		cve.HostID = updatedHost.ID // Set the foreign key
		if err := tx.Where(models.HostVulnerability{VulnerabilityID: cve.VulnerabilityID, HostID: updatedHost.ID}).FirstOrCreate(&cve).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	// Commit the transaction
	tx.Commit()

	return nil
}
*/

/*	=========== Mapping Functions ============ */

// Update to match ToDBHost
func MapDBHostToSiriusHost(dbHost models.Host) sirius.Host {
	var siriusPorts []sirius.Port
	for _, dbPort := range dbHost.Ports {
		siriusPort := sirius.Port{
			ID:    dbPort.ID,
			State: "open",
		}
		siriusPorts = append(siriusPorts, siriusPort)
	}

	// Map models.Vulnerabilities to sirius.Vulnerabilities
	var siriusVulnerabilities []sirius.Vulnerability
	for _, dbVulnerability := range dbHost.Vulnerabilities {
		siriusVulnerability := sirius.Vulnerability{
			VID:         dbVulnerability.VID,
			Title:       dbVulnerability.Title,
			Description: dbVulnerability.Description,
			RiskScore:   dbVulnerability.RiskScore,
			// RiskScore: sirius.RiskScore{
			// 	CVSSV3: sirius.BaseMetricV3{
			// 		CVSSV3: sirius.CVSSV3{
			// 			Version:                       dbVulnerability.RiskScore.CVSSV3.CVSSV3.Version,
			// 			VectorString:                  dbVulnerability.RiskScore.CVSSV3.CVSSV3.VectorString,
			// 			AttackVector:                  dbVulnerability.RiskScore.CVSSV3.CVSSV3.AttackVector,
			// 			AttackComplexity:              dbVulnerability.RiskScore.CVSSV3.CVSSV3.AttackComplexity,
			// 			PrivilegesRequired:            dbVulnerability.RiskScore.CVSSV3.CVSSV3.PrivilegesRequired,
			// 			UserInteraction:               dbVulnerability.RiskScore.CVSSV3.CVSSV3.UserInteraction,
			// 			Scope:                         dbVulnerability.RiskScore.CVSSV3.CVSSV3.Scope,
			// 			ConfidentialityImpact:         dbVulnerability.RiskScore.CVSSV3.CVSSV3.ConfidentialityImpact,
			// 			IntegrityImpact:               dbVulnerability.RiskScore.CVSSV3.CVSSV3.IntegrityImpact,
			// 			AvailabilityImpact:            dbVulnerability.RiskScore.CVSSV3.CVSSV3.AvailabilityImpact,
			// 			BaseScore:                     dbVulnerability.RiskScore.CVSSV3.CVSSV3.BaseScore,
			// 			BaseSeverity:                  dbVulnerability.RiskScore.CVSSV3.CVSSV3.BaseSeverity,
			// 			ExploitCodeMaturity:           dbVulnerability.RiskScore.CVSSV3.CVSSV3.ExploitCodeMaturity,
			// 			RemediationLevel:              dbVulnerability.RiskScore.CVSSV3.CVSSV3.RemediationLevel,
			// 			ReportConfidence:              dbVulnerability.RiskScore.CVSSV3.CVSSV3.ReportConfidence,
			// 			TemporalScore:                 dbVulnerability.RiskScore.CVSSV3.CVSSV3.TemporalScore,
			// 			TemporalSeverity:              dbVulnerability.RiskScore.CVSSV3.CVSSV3.TemporalSeverity,
			// 			ConfidentialityRequirement:    dbVulnerability.RiskScore.CVSSV3.CVSSV3.ConfidentialityRequirement,
			// 			IntegrityRequirement:          dbVulnerability.RiskScore.CVSSV3.CVSSV3.IntegrityRequirement,
			// 			AvailabilityRequirement:       dbVulnerability.RiskScore.CVSSV3.CVSSV3.AvailabilityRequirement,
			// 			ModifiedAttackVector:          dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedAttackVector,
			// 			ModifiedAttackComplexity:      dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedAttackComplexity,
			// 			ModifiedPrivilegesRequired:    dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedPrivilegesRequired,
			// 			ModifiedUserInteraction:       dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedUserInteraction,
			// 			ModifiedScope:                 dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedScope,
			// 			ModifiedConfidentialityImpact: dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedConfidentialityImpact,
			// 			ModifiedIntegrityImpact:       dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedIntegrityImpact,
			// 			ModifiedAvailabilityImpact:    dbVulnerability.RiskScore.CVSSV3.CVSSV3.ModifiedAvailabilityImpact,
			// 			EnvironmentalScore:            dbVulnerability.RiskScore.CVSSV3.CVSSV3.EnvironmentalScore,
			// 			EnvironmentalSeverity:         dbVulnerability.RiskScore.CVSSV3.CVSSV3.EnvironmentalSeverity,
			// 		},
			// 		ExploitabilityScore: dbVulnerability.RiskScore.CVSSV3.ExploitabilityScore,
			// 		ImpactScore:         dbVulnerability.RiskScore.CVSSV3.ImpactScore,
			// 	},
			// 	CVSSV2: sirius.BaseMetricV2{
			// 		CVSSV2: sirius.CVSSV2{
			// 			Version:                    dbVulnerability.RiskScore.CVSSV2.CVSSV2.Version,
			// 			VectorString:               dbVulnerability.RiskScore.CVSSV2.CVSSV2.VectorString,
			// 			AccessVector:               dbVulnerability.RiskScore.CVSSV2.CVSSV2.AccessVector,
			// 			AccessComplexity:           dbVulnerability.RiskScore.CVSSV2.CVSSV2.AccessComplexity,
			// 			Authentication:             dbVulnerability.RiskScore.CVSSV2.CVSSV2.Authentication,
			// 			ConfidentialityImpact:      dbVulnerability.RiskScore.CVSSV2.CVSSV2.ConfidentialityImpact,
			// 			IntegrityImpact:            dbVulnerability.RiskScore.CVSSV2.CVSSV2.IntegrityImpact,
			// 			AvailabilityImpact:         dbVulnerability.RiskScore.CVSSV2.CVSSV2.AvailabilityImpact,
			// 			BaseScore:                  dbVulnerability.RiskScore.CVSSV2.CVSSV2.BaseScore,
			// 			Exploitability:             dbVulnerability.RiskScore.CVSSV2.CVSSV2.Exploitability,
			// 			RemediationLevel:           dbVulnerability.RiskScore.CVSSV2.CVSSV2.RemediationLevel,
			// 			ReportConfidence:           dbVulnerability.RiskScore.CVSSV2.CVSSV2.ReportConfidence,
			// 			TemporalScore:              dbVulnerability.RiskScore.CVSSV2.CVSSV2.TemporalScore,
			// 			CollateralDamagePotential:  dbVulnerability.RiskScore.CVSSV2.CVSSV2.CollateralDamagePotential,
			// 			TargetDistribution:         dbVulnerability.RiskScore.CVSSV2.CVSSV2.TargetDistribution,
			// 			ConfidentialityRequirement: dbVulnerability.RiskScore.CVSSV2.CVSSV2.ConfidentialityRequirement,
			// 			IntegrityRequirement:       dbVulnerability.RiskScore.CVSSV2.CVSSV2.IntegrityRequirement,
			// 			AvailabilityRequirement:    dbVulnerability.RiskScore.CVSSV2.CVSSV2.AvailabilityRequirement,
			// 			EnvironmentalScore:         dbVulnerability.RiskScore.CVSSV2.CVSSV2.EnvironmentalScore,
			// 		},
			// 		Severity:                dbVulnerability.RiskScore.CVSSV2.Severity,
			// 		ExploitabilityScore:     dbVulnerability.RiskScore.CVSSV2.ExploitabilityScore,
			// 		ImpactScore:             dbVulnerability.RiskScore.CVSSV2.ImpactScore,
			// 		AcInsufInfo:             dbVulnerability.RiskScore.CVSSV2.AcInsufInfo,
			// 		ObtainAllPrivilege:      dbVulnerability.RiskScore.CVSSV2.ObtainAllPrivilege,
			// 		ObtainUserPrivilege:     dbVulnerability.RiskScore.CVSSV2.ObtainUserPrivilege,
			// 		ObtainOtherPrivilege:    dbVulnerability.RiskScore.CVSSV2.ObtainOtherPrivilege,
			// 		UserInteractionRequired: dbVulnerability.RiskScore.CVSSV2.UserInteractionRequired,
			// 	},
			// },
		}
		siriusVulnerabilities = append(siriusVulnerabilities, siriusVulnerability)
	}

	return sirius.Host{
		OS:              dbHost.OS,
		OSVersion:       dbHost.OSVersion,
		IP:              dbHost.IP,
		Hostname:        dbHost.Hostname,
		Ports:           siriusPorts,
		Vulnerabilities: siriusVulnerabilities, // Use & to create a pointer
		// ... map other fields ...
	}
}

func MapSiriusHostToDBHost(siriusHost sirius.Host) models.Host {
	db := postgres.GetDB() // Enable DB connection to look up existing records

	// Initialize empty return value in case of database issues
	dbHost := models.Host{
		HID:       siriusHost.HID,
		OS:        siriusHost.OS,
		OSVersion: siriusHost.OSVersion,
		IP:        siriusHost.IP,
		Hostname:  siriusHost.Hostname,
	}

	// If we have no database connection, return basic host without relationship data
	if db == nil {
		log.Printf("Warning: Database connection not available in MapSiriusHostToDBHost for IP %s", siriusHost.IP)
		return dbHost
	}

	// Map Ports from sirius.Host to models.Host
	var dbPorts []models.Port
	for _, port := range siriusHost.Ports {
		// Try to find an existing port by ID and protocol
		var existingPort models.Port
		result := db.Where("id = ? AND protocol = ?", port.ID, port.Protocol).First(&existingPort)

		if result.RowsAffected > 0 {
			// Use the existing port if found
			dbPorts = append(dbPorts, existingPort)
		} else {
			// Otherwise create a new port entry
			dbPort := models.Port{
				ID:       port.ID,
				Protocol: port.Protocol,
				State:    port.State,
			}
			dbPorts = append(dbPorts, dbPort)
		}
	}

	// Update our return value with found ports
	dbHost.Ports = dbPorts

	// Map Services (assuming Service has a Name field)
	var dbServices []models.Service
	// ! Address dbServices later

	// Update our return value with found services
	dbHost.Services = dbServices

	// Map sirius.Vulnerabilities to models.Host.Vulnerabilities
	var dbVulnerabilities []models.Vulnerability
	for _, vulnerability := range siriusHost.Vulnerabilities {
		// Skip empty vulnerabilities
		if vulnerability.VID == "" {
			continue
		}

		// Create a vulnerability instance to look up
		var existingVuln models.Vulnerability

		// Try to find existing vulnerability by v_id field (must use column name)
		result := db.Where("v_id = ?", vulnerability.VID).First(&existingVuln)
		if result.RowsAffected > 0 {
			// Use the existing vulnerability if found
			dbVulnerabilities = append(dbVulnerabilities, existingVuln)
			continue
		}

		// If we can't find by VID, try title as a fallback
		result = db.Where("title = ?", vulnerability.Title).First(&existingVuln)
		if result.RowsAffected > 0 {
			// Use the existing vulnerability if found
			dbVulnerabilities = append(dbVulnerabilities, existingVuln)
			continue
		}

		// If vulnerability doesn't exist yet, create a new one
		newVuln := models.Vulnerability{
			VID:         vulnerability.VID,
			Description: vulnerability.Description,
			Title:       vulnerability.Title,
			RiskScore:   vulnerability.RiskScore,
		}

		// Save the new vulnerability to get an ID
		if err := db.Create(&newVuln).Error; err == nil {
			dbVulnerabilities = append(dbVulnerabilities, newVuln)
		} else {
			log.Printf("Failed to create vulnerability %s: %v", vulnerability.VID, err)
		}
	}

	// Update our return value with found vulnerabilities
	dbHost.Vulnerabilities = dbVulnerabilities

	// Return the host with all relationships set up
	return dbHost
}

// MapDBVulnerabilityToSiriusVulnerability maps a models.Vulnerability to a sirius.Vulnerability
/*
func MapDBVulnerabilityToSiriusVulnerability(dbVulnerability models.Vulnerability) sirius.Vulnerability {
	return sirius.Vulnerability{
		VID:         dbVulnerability.VID,
		Description: dbVulnerability.Description,
		Title:       dbVulnerability.Title,
		RiskScore: sirius.RiskScore{
			CVSSV3: MapDBBaseMetricV3ToSiriusBaseMetricV3(dbVulnerability.RiskScore.CVSSV3),
			CVSSV2: MapDBBaseMetricV2ToSiriusBaseMetricV2(dbVulnerability.RiskScore.CVSSV2),
		},
	}
}

// MapDBBaseMetricV3ToSiriusBaseMetricV3 maps a models.BaseMetricV3 to a sirius.BaseMetricV3
func MapDBBaseMetricV3ToSiriusBaseMetricV3(dbMetricV3 models.BaseMetricV3) sirius.BaseMetricV3 {
	return sirius.BaseMetricV3{
		CVSSV3:              MapDBCVSSV3ToSiriusCVSSV3(dbMetricV3.CVSSV3),
		ExploitabilityScore: dbMetricV3.ExploitabilityScore,
		ImpactScore:         dbMetricV3.ImpactScore,
	}
}

// MapDBBaseMetricV2ToSiriusBaseMetricV2 maps a models.BaseMetricV2 to a sirius.BaseMetricV2
func MapDBBaseMetricV2ToSiriusBaseMetricV2(dbMetricV2 models.BaseMetricV2) sirius.BaseMetricV2 {
	return sirius.BaseMetricV2{
		CVSSV2:              MapDBCVSSV2ToSiriusCVSSV2(dbMetricV2.CVSSV2),
		Severity:            dbMetricV2.Severity,
		ExploitabilityScore: dbMetricV2.ExploitabilityScore,
		ImpactScore:         dbMetricV2.ImpactScore,
	}
}

// MapDBCVSSV3ToSiriusCVSSV3 maps a models.CVSSV3 to a sirius.CVSSV3
func MapDBCVSSV3ToSiriusCVSSV3(dbCVSSV3 models.CVSSV3) sirius.CVSSV3 {
	return sirius.CVSSV3{
		Version:                       dbCVSSV3.Version,
		VectorString:                  dbCVSSV3.VectorString,
		AttackVector:                  dbCVSSV3.AttackVector,
		AttackComplexity:              dbCVSSV3.AttackComplexity,
		PrivilegesRequired:            dbCVSSV3.PrivilegesRequired,
		UserInteraction:               dbCVSSV3.UserInteraction,
		Scope:                         dbCVSSV3.Scope,
		ConfidentialityImpact:         dbCVSSV3.ConfidentialityImpact,
		IntegrityImpact:               dbCVSSV3.IntegrityImpact,
		AvailabilityImpact:            dbCVSSV3.AvailabilityImpact,
		BaseScore:                     dbCVSSV3.BaseScore,
		BaseSeverity:                  dbCVSSV3.BaseSeverity,
		ExploitCodeMaturity:           dbCVSSV3.ExploitCodeMaturity,
		RemediationLevel:              dbCVSSV3.RemediationLevel,
		ReportConfidence:              dbCVSSV3.ReportConfidence,
		TemporalScore:                 dbCVSSV3.TemporalScore,
		TemporalSeverity:              dbCVSSV3.TemporalSeverity,
		ConfidentialityRequirement:    dbCVSSV3.ConfidentialityRequirement,
		IntegrityRequirement:          dbCVSSV3.IntegrityRequirement,
		AvailabilityRequirement:       dbCVSSV3.AvailabilityRequirement,
		ModifiedAttackVector:          dbCVSSV3.ModifiedAttackVector,
		ModifiedAttackComplexity:      dbCVSSV3.ModifiedAttackComplexity,
		ModifiedPrivilegesRequired:    dbCVSSV3.ModifiedPrivilegesRequired,
		ModifiedUserInteraction:       dbCVSSV3.ModifiedUserInteraction,
		ModifiedScope:                 dbCVSSV3.ModifiedScope,
		ModifiedConfidentialityImpact: dbCVSSV3.ModifiedConfidentialityImpact,
		ModifiedIntegrityImpact:       dbCVSSV3.ModifiedIntegrityImpact,
		ModifiedAvailabilityImpact:    dbCVSSV3.ModifiedAvailabilityImpact,
		EnvironmentalScore:            dbCVSSV3.EnvironmentalScore,
		EnvironmentalSeverity:         dbCVSSV3.EnvironmentalSeverity,
	}
}

// MapDBCVSSV2ToSiriusCVSSV2 maps a models.CVSSV2 to a sirius.CVSSV2
func MapDBCVSSV2ToSiriusCVSSV2(dbCVSSV2 models.CVSSV2) sirius.CVSSV2 {
	return sirius.CVSSV2{
		Version:                    dbCVSSV2.Version,
		VectorString:               dbCVSSV2.VectorString,
		AccessVector:               dbCVSSV2.AccessVector,
		AccessComplexity:           dbCVSSV2.AccessComplexity,
		Authentication:             dbCVSSV2.Authentication,
		ConfidentialityImpact:      dbCVSSV2.ConfidentialityImpact,
		IntegrityImpact:            dbCVSSV2.IntegrityImpact,
		AvailabilityImpact:         dbCVSSV2.AvailabilityImpact,
		BaseScore:                  dbCVSSV2.BaseScore,
		Exploitability:             dbCVSSV2.Exploitability,
		RemediationLevel:           dbCVSSV2.RemediationLevel,
		ReportConfidence:           dbCVSSV2.ReportConfidence,
		TemporalScore:              dbCVSSV2.TemporalScore,
		CollateralDamagePotential:  dbCVSSV2.CollateralDamagePotential,
		TargetDistribution:         dbCVSSV2.TargetDistribution,
		ConfidentialityRequirement: dbCVSSV2.ConfidentialityRequirement,
		IntegrityRequirement:       dbCVSSV2.IntegrityRequirement,
		AvailabilityRequirement:    dbCVSSV2.AvailabilityRequirement,
		EnvironmentalScore:         dbCVSSV2.EnvironmentalScore,
	}
}

// MapSiriusVulnerabilityToDBVulnerability maps a sirius.Vulnerability to a models.Vulnerability
func MapSiriusVulnerabilityToDBVulnerability(siriusVulnerability sirius.Vulnerability) models.Vulnerability {
	return models.Vulnerability{
		VID:         siriusVulnerability.VID,
		Description: siriusVulnerability.Description,
		Title:       siriusVulnerability.Title,
		RiskScore: models.RiskScore{
			CVSSV3: MapSiriusBaseMetricV3ToDBBaseMetricV3(siriusVulnerability.RiskScore.CVSSV3),
			CVSSV2: MapSiriusBaseMetricV2ToDBBaseMetricV2(siriusVulnerability.RiskScore.CVSSV2),
		},
	}
}

// MapSiriusBaseMetricV3ToDBBaseMetricV3 maps a sirius.BaseMetricV3 to a models.BaseMetricV3
func MapSiriusBaseMetricV3ToDBBaseMetricV3(siriusMetricV3 sirius.BaseMetricV3) models.BaseMetricV3 {
	return models.BaseMetricV3{
		CVSSV3:              MapSiriusCVSSV3ToDBCVSSV3(siriusMetricV3.CVSSV3),
		ExploitabilityScore: siriusMetricV3.ExploitabilityScore,
		ImpactScore:         siriusMetricV3.ImpactScore,
	}
}

// MapSiriusBaseMetricV2ToDBBaseMetricV2 maps a sirius.BaseMetricV2 to a models.BaseMetricV2
func MapSiriusBaseMetricV2ToDBBaseMetricV2(siriusMetricV2 sirius.BaseMetricV2) models.BaseMetricV2 {
	return models.BaseMetricV2{
		CVSSV2:              MapSiriusCVSSV2ToDBCVSSV2(siriusMetricV2.CVSSV2),
		Severity:            siriusMetricV2.Severity,
		ExploitabilityScore: siriusMetricV2.ExploitabilityScore,
		ImpactScore:         siriusMetricV2.ImpactScore,
	}
}
*/

// EnhancedHostData represents host data with JSONB fields
type EnhancedHostData struct {
	Host              sirius.Host            `json:"host"`
	SoftwareInventory map[string]interface{} `json:"software_inventory,omitempty"`
	SystemFingerprint map[string]interface{} `json:"system_fingerprint,omitempty"`
	AgentMetadata     map[string]interface{} `json:"agent_metadata,omitempty"`
}

// GetHostWithEnhancedData retrieves host information including JSONB fields
func GetHostWithEnhancedData(ip string, includeFields []string) (*EnhancedHostData, error) {
	db := postgres.GetDB()

	// Check if database is available
	if db == nil {
		log.Printf("Warning: Database not available, cannot retrieve host %s", ip)
		return nil, fmt.Errorf("database connection not available")
	}

	var dbHost models.Host
	result := db.Preload("Ports").Preload("Vulnerabilities").Preload("Services").Where("ip = ?", ip).First(&dbHost)

	if result.Error != nil {
		return nil, result.Error
	}

	// Map the database host to a sirius.Host
	host := MapDBHostToSiriusHost(dbHost)

	// Create enhanced data structure
	enhancedData := &EnhancedHostData{
		Host: host,
	}

	// Include JSONB fields based on request
	if len(includeFields) == 0 || stringSliceContains(includeFields, "software_inventory") || stringSliceContains(includeFields, "packages") {
		if len(dbHost.SoftwareInventory) > 0 {
			enhancedData.SoftwareInventory = dbHost.SoftwareInventory
		}
	}

	if len(includeFields) == 0 || stringSliceContains(includeFields, "system_fingerprint") || stringSliceContains(includeFields, "fingerprint") {
		if len(dbHost.SystemFingerprint) > 0 {
			enhancedData.SystemFingerprint = dbHost.SystemFingerprint
		}
	}

	if len(includeFields) == 0 || stringSliceContains(includeFields, "agent_metadata") || stringSliceContains(includeFields, "metadata") {
		if len(dbHost.AgentMetadata) > 0 {
			enhancedData.AgentMetadata = dbHost.AgentMetadata
		}
	}

	return enhancedData, nil
}

// SoftwareInventoryData represents structured software inventory information
type SoftwareInventoryData struct {
	Packages     []map[string]interface{} `json:"packages"`
	PackageCount int                      `json:"package_count"`
	CollectedAt  string                   `json:"collected_at"`
	Source       string                   `json:"source"`
	Statistics   map[string]interface{}   `json:"statistics,omitempty"`
}

// GetHostSoftwareInventory retrieves only software inventory data for a host
func GetHostSoftwareInventory(ip string) (*SoftwareInventoryData, error) {
	db := postgres.GetDB()

	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	var dbHost models.Host
	result := db.Select("software_inventory").Where("ip = ?", ip).First(&dbHost)

	if result.Error != nil {
		return nil, result.Error
	}

	if len(dbHost.SoftwareInventory) == 0 {
		return &SoftwareInventoryData{
			Packages:     []map[string]interface{}{},
			PackageCount: 0,
		}, nil
	}

	// Parse software inventory JSONB data
	inventory := &SoftwareInventoryData{}

	if packages, ok := dbHost.SoftwareInventory["packages"].([]interface{}); ok {
		for _, pkg := range packages {
			if pkgMap, ok := pkg.(map[string]interface{}); ok {
				inventory.Packages = append(inventory.Packages, pkgMap)
			}
		}
	}

	if count, ok := dbHost.SoftwareInventory["package_count"].(float64); ok {
		inventory.PackageCount = int(count)
	} else {
		inventory.PackageCount = len(inventory.Packages)
	}

	if collectedAt, ok := dbHost.SoftwareInventory["collected_at"].(string); ok {
		inventory.CollectedAt = collectedAt
	}

	if source, ok := dbHost.SoftwareInventory["source"].(string); ok {
		inventory.Source = source
	}

	if stats, ok := dbHost.SoftwareInventory["statistics"].(map[string]interface{}); ok {
		inventory.Statistics = stats
	}

	return inventory, nil
}

// SystemFingerprintData represents structured system fingerprint information
type SystemFingerprintData struct {
	Fingerprint          map[string]interface{} `json:"fingerprint"`
	CollectedAt          string                 `json:"collected_at"`
	Source               string                 `json:"source"`
	Platform             string                 `json:"platform"`
	CollectionDurationMs int64                  `json:"collection_duration_ms"`
	Summary              map[string]interface{} `json:"summary,omitempty"`
}

// GetHostSystemFingerprint retrieves only system fingerprint data for a host
func GetHostSystemFingerprint(ip string) (*SystemFingerprintData, error) {
	db := postgres.GetDB()

	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	var dbHost models.Host
	result := db.Select("system_fingerprint").Where("ip = ?", ip).First(&dbHost)

	if result.Error != nil {
		return nil, result.Error
	}

	if len(dbHost.SystemFingerprint) == 0 {
		return &SystemFingerprintData{
			Fingerprint: map[string]interface{}{},
		}, nil
	}

	// Parse system fingerprint JSONB data
	fingerprint := &SystemFingerprintData{}

	if fp, ok := dbHost.SystemFingerprint["fingerprint"].(map[string]interface{}); ok {
		fingerprint.Fingerprint = fp
	}

	if collectedAt, ok := dbHost.SystemFingerprint["collected_at"].(string); ok {
		fingerprint.CollectedAt = collectedAt
	}

	if source, ok := dbHost.SystemFingerprint["source"].(string); ok {
		fingerprint.Source = source
	}

	if platform, ok := dbHost.SystemFingerprint["platform"].(string); ok {
		fingerprint.Platform = platform
	}

	if duration, ok := dbHost.SystemFingerprint["collection_duration_ms"].(float64); ok {
		fingerprint.CollectionDurationMs = int64(duration)
	}

	if summary, ok := dbHost.SystemFingerprint["summary"].(map[string]interface{}); ok {
		fingerprint.Summary = summary
	}

	return fingerprint, nil
}

// SoftwareStatistics represents aggregated software inventory statistics
type SoftwareStatistics struct {
	TotalPackages    int            `json:"total_packages"`
	Architectures    map[string]int `json:"architectures"`
	Publishers       map[string]int `json:"publishers"`
	LastUpdated      string         `json:"last_updated"`
	PackagesBySource map[string]int `json:"packages_by_source,omitempty"`
}

// GetHostSoftwareStatistics retrieves aggregated software statistics for a host
func GetHostSoftwareStatistics(ip string) (*SoftwareStatistics, error) {
	inventory, err := GetHostSoftwareInventory(ip)
	if err != nil {
		return nil, err
	}

	stats := &SoftwareStatistics{
		TotalPackages:    inventory.PackageCount,
		Architectures:    make(map[string]int),
		Publishers:       make(map[string]int),
		PackagesBySource: make(map[string]int),
		LastUpdated:      inventory.CollectedAt,
	}

	// Aggregate statistics from packages
	for _, pkg := range inventory.Packages {
		if arch, ok := pkg["architecture"].(string); ok && arch != "" {
			stats.Architectures[arch]++
		}

		if publisher, ok := pkg["publisher"].(string); ok && publisher != "" {
			stats.Publishers[publisher]++
		}

		if source, ok := pkg["source"].(string); ok && source != "" {
			stats.PackagesBySource[source]++
		}
	}

	// Use statistics from JSONB if available
	if inventory.Statistics != nil {
		if archs, ok := inventory.Statistics["architectures"].(map[string]interface{}); ok {
			archStats := make(map[string]int)
			for k, v := range archs {
				if count, ok := v.(float64); ok {
					archStats[k] = int(count)
				}
			}
			if len(archStats) > 0 {
				stats.Architectures = archStats
			}
		}

		if pubs, ok := inventory.Statistics["publishers"].(map[string]interface{}); ok {
			pubStats := make(map[string]int)
			for k, v := range pubs {
				if count, ok := v.(float64); ok {
					pubStats[k] = int(count)
				}
			}
			if len(pubStats) > 0 {
				stats.Publishers = pubStats
			}
		}
	}

	return stats, nil
}

// Helper function to check if a slice contains a string
func stringSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
