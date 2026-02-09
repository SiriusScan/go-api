package host

import (
	"fmt"
	"log/slog"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func GetHost(ip string) (sirius.Host, error) {
	repo := NewHostRepository()

	// Get host with explicit JOIN query
	hostWithRelations, err := repo.GetHostWithRelations(ip)
	if err != nil {
		return sirius.Host{}, err
	}

	// Convert to sirius.Host (no circular references to load)
	return convertHostWithRelationsToSiriusHost(hostWithRelations), nil
}

func GetAllHosts() ([]sirius.Host, error) {
	repo := NewHostRepository()

	// Get all hosts with explicit JOIN queries
	hostsWithRelations, err := repo.GetAllHostsWithRelations()
	if err != nil {
		return nil, err
	}

	// Convert to sirius.Host slice
	siriusHosts := make([]sirius.Host, 0, len(hostsWithRelations))
	for _, hwr := range hostsWithRelations {
		siriusHosts = append(siriusHosts, convertHostWithRelationsToSiriusHost(&hwr))
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
// Legacy function - uses repository pattern with "legacy" source for backward compatibility
func AddHost(host sirius.Host) error {
	slog.Info("Adding or updating host in database (legacy mode)", "ip", host.IP)

	// Use legacy source for backward compatibility
	legacySource := models.ScanSource{
		Name:    "legacy",
		Version: "unknown",
		Config:  "backward_compatibility",
	}

	// Use source-aware function which now uses repository pattern
	return AddHostWithSource(host, legacySource)
}

// DeleteHost handles the POST /host/delete route
// DeleteHost Chain: SDK Consumer (e.g. Sirius REST API) -> SDK go-api sirius/host (Here)
func DeleteHost(ip string) error {
	// fmt.Printf("Deleting host %s from database\n", ip)

	db := postgres.GetDB()

	// Start a transaction with proper cleanup
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r) // Re-panic after rollback
		}
	}()

	// Delete Host
	if err := tx.Where("ip = ?", ip).Delete(&models.Host{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

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

// convertHostWithRelationsToSiriusHost converts HostWithRelations to sirius.Host
// This function is used by the repository pattern to build responses without circular references
func convertHostWithRelationsToSiriusHost(hwr *HostWithRelations) sirius.Host {
	// Convert ports
	var siriusPorts []sirius.Port
	for _, pr := range hwr.Ports {
		siriusPorts = append(siriusPorts, sirius.Port{
			Number:   pr.Port.Number,
			Protocol: pr.Port.Protocol,
			State:    pr.Port.State,
		})
	}

	// Convert vulnerabilities
	var siriusVulnerabilities []sirius.Vulnerability
	for _, vr := range hwr.Vulnerabilities {
		siriusVulnerabilities = append(siriusVulnerabilities, sirius.Vulnerability{
			VID:         vr.Vulnerability.VID,
			Title:       vr.Vulnerability.Title,
			Description: vr.Vulnerability.Description,
			RiskScore:   vr.Vulnerability.RiskScore,
		})
	}

	// Convert services (if any exist in the host model)
	var siriusServices []sirius.Service
	for _, svc := range hwr.Host.Services {
		siriusServices = append(siriusServices, sirius.Service{
			Port:    int(svc.ID), // Using ID as placeholder for port if needed
			Product: svc.Name,
		})
	}

	return sirius.Host{
		HID:             hwr.Host.HID,
		OS:              hwr.Host.OS,
		OSVersion:       hwr.Host.OSVersion,
		IP:              hwr.Host.IP,
		Hostname:        hwr.Host.Hostname,
		Ports:           siriusPorts,
		Services:        siriusServices,
		Vulnerabilities: siriusVulnerabilities,
	}
}

// REMOVED: MapDBHostToSiriusHost
// This function has been replaced by convertHostWithRelationsToSiriusHost() which uses the repository pattern.
// The old function tried to access models.Host.Ports and models.Host.Vulnerabilities which no longer exist.
// Use HostRepository.GetHostWithRelations() and convertHostWithRelationsToSiriusHost() instead.

// REMOVED: MapSiriusHostToDBHost
// This function has been replaced by the repository pattern:
// - Use HostRepository.UpsertHost() for host entity
// - Use HostRepository.UpsertPort() and LinkHostPort() for ports
// - Use HostRepository.UpsertVulnerability() and LinkHostVulnerability() for vulnerabilities
// The old function tried to access models.Host.Ports and models.Host.Vulnerabilities which no longer exist

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

// GetHostWithEnhancedData retrieves host information including JSONB fields using repository pattern
func GetHostWithEnhancedData(ip string, includeFields []string) (*EnhancedHostData, error) {
	repo := NewHostRepository()

	// Get host with relations using repository
	hostWithRelations, err := repo.GetHostWithRelations(ip)
	if err != nil {
		return nil, err
	}

	// Convert to sirius.Host
	host := convertHostWithRelationsToSiriusHost(hostWithRelations)

	// Create enhanced data structure
	enhancedData := &EnhancedHostData{
		Host: host,
	}

	// Include JSONB fields based on request
	if len(includeFields) == 0 || stringSliceContains(includeFields, "software_inventory") || stringSliceContains(includeFields, "packages") {
		if len(hostWithRelations.Host.SoftwareInventory) > 0 {
			enhancedData.SoftwareInventory = hostWithRelations.Host.SoftwareInventory
		}
	}

	if len(includeFields) == 0 || stringSliceContains(includeFields, "system_fingerprint") || stringSliceContains(includeFields, "fingerprint") {
		if len(hostWithRelations.Host.SystemFingerprint) > 0 {
			enhancedData.SystemFingerprint = hostWithRelations.Host.SystemFingerprint
		}
	}

	if len(includeFields) == 0 || stringSliceContains(includeFields, "agent_metadata") || stringSliceContains(includeFields, "metadata") {
		if len(hostWithRelations.Host.AgentMetadata) > 0 {
			enhancedData.AgentMetadata = hostWithRelations.Host.AgentMetadata
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
