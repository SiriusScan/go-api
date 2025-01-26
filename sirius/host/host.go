package host

import (
	"log"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func GetHost(ip string) (sirius.Host, error) {
	// fmt.Printf("Adding or updating host %s in database\n", ip)

	db := postgres.GetDB()

	dbHost, err := postgres.GetHost(db, ip)
	if err != nil {
		return sirius.Host{}, err
	}

	return MapDBHostToSiriusHost(dbHost), nil
	// mockHost := sirius.Host{}
	// return mockHost, nil
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
	// fmt.Printf("Adding or updating host %s in database\n", host.IP)

	dbHost := MapSiriusHostToDBHost(host)
	db := postgres.GetDB()

	// Create a separate host for the Where clause
	whereHost := models.Host{IP: dbHost.IP}

	// Find the first host with a matching IP
	var existingHost models.Host
	result := db.Where(&whereHost).First(&existingHost)

	// If a record was found, update it
	if result.RowsAffected > 0 {
		err := db.Model(&existingHost).Updates(&dbHost).Error
		if err != nil {
			return err
		}
		// Update many-to-many relationship
		err = db.Model(&existingHost).Association("Vulnerabilities").Replace(dbHost.Vulnerabilities)
		if err != nil {
			return err
		}
	} else {
		// If no record was found, create a new one
		err := db.Create(&dbHost).Error
		if err != nil {
			return err
		}
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
	db := postgres.GetDB()

	// Map Ports
	var dbPorts []models.Port
	for _, port := range siriusHost.Ports {
		dbPort := models.Port{
			ID: port.ID,
		}
		dbPorts = append(dbPorts, dbPort)
	}

	// Map Services (assuming Service has a Name field)
	var dbServices []models.Service
	// ! Address dbServices later

	// Map sirius.Vulnerabilities to models.Host.Vulnerabilities
	var dbVulnerabilities []models.Vulnerability
	for _, vulnerability := range siriusHost.Vulnerabilities {
		var existingVuln models.Vulnerability
		// Find each vulnerability by VID
		if err := db.Where("v_id = ?", vulnerability.VID).First(&existingVuln).Error; err != nil {
			log.Printf("Warning: [MapSiriusHostToDBHost] Vulnerability with VID '%s' not found in database, skipping...\n", vulnerability.VID)
			continue // Skip this vulnerability
		}
		dbVulnerabilities = append(dbVulnerabilities, existingVuln)
	}

	return models.Host{
		OS:              siriusHost.OS,
		OSVersion:       siriusHost.OSVersion,
		IP:              siriusHost.IP,
		Hostname:        siriusHost.Hostname,
		Ports:           dbPorts,
		Services:        dbServices,
		Vulnerabilities: dbVulnerabilities,
	}
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
