package host

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"gorm.io/gorm"
)

// generateHostID creates a unique host identifier for scan-discovered hosts
// Format: scan-<random-hex> to distinguish from agent-generated HIDs
func generateHostID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return "scan-" + hex.EncodeToString(bytes)
}

// HostRepository provides explicit database operations for hosts without circular references
type HostRepository struct {
	db *gorm.DB
}

// NewHostRepository creates a new HostRepository instance
func NewHostRepository() *HostRepository {
	return &HostRepository{
		db: postgres.GetDB(),
	}
}

// HostWithRelations represents a host with its ports and vulnerabilities loaded via explicit JOINs
type HostWithRelations struct {
	Host            models.Host
	Ports           []PortRelation
	Vulnerabilities []VulnerabilityRelation
}

// PortRelation represents a port with source attribution
type PortRelation struct {
	Port          models.Port
	Source        string
	SourceVersion string
	FirstSeen     time.Time
	LastSeen      time.Time
	Status        string
	Notes         string
}

// VulnerabilityRelation represents a vulnerability with source attribution
type VulnerabilityRelation struct {
	Vulnerability models.Vulnerability
	Source        string
	SourceVersion string
	FirstSeen     time.Time
	LastSeen      time.Time
	Status        string
	Confidence    float64
	Port          *int
	ServiceInfo   string
	Notes         string
}

// UpsertHost creates or updates a host and returns its ID
func (r *HostRepository) UpsertHost(ip, hostname, os, osVersion, hid string) (hostID uint, err error) {
	if r.db == nil {
		return 0, fmt.Errorf("database connection not available")
	}

	var host models.Host
	result := r.db.Select("id, h_id, os, os_version, ip, hostname, agent_id, created_at, updated_at, deleted_at").
		Where("ip = ?", ip).
		First(&host)

	if result.Error == nil {
		// Host exists - update it
		// Only update non-empty values to preserve existing data from earlier scans
		updates := map[string]interface{}{
			"updated_at": time.Now(),
		}
		// Only update hostname if non-empty (don't overwrite with empty)
		if hostname != "" {
			updates["hostname"] = hostname
		}
		// Only update OS fields if non-empty (preserve fingerprint data from ping++)
		if os != "" {
			updates["os"] = os
		}
		if osVersion != "" {
			updates["os_version"] = osVersion
		}
		if hid != "" {
			updates["h_id"] = hid
		}

		err = r.db.Model(&host).Updates(updates).Error
		if err != nil {
			return 0, fmt.Errorf("failed to update host: %w", err)
		}
		return host.ID, nil
	}

	// Host doesn't exist - create it
	// Generate a unique HID if not provided to satisfy uniqueIndex constraint
	hostHID := hid
	if hostHID == "" {
		hostHID = generateHostID()
		log.Printf("Generated HID %s for scan-discovered host %s", hostHID, ip)
	}

	newHost := models.Host{
		HID:       hostHID,
		IP:        ip,
		Hostname:  hostname,
		OS:        os,
		OSVersion: osVersion,
	}

	err = r.db.Create(&newHost).Error
	if err != nil {
		return 0, fmt.Errorf("failed to create host: %w", err)
	}

	return newHost.ID, nil
}

// UpdateHostJSONB updates JSONB fields for a host
func (r *HostRepository) UpdateHostJSONB(hostID uint, softwareInventory, systemFingerprint, agentMetadata map[string]interface{}) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

	updates := make(map[string]interface{})
	if len(softwareInventory) > 0 {
		updates["software_inventory"] = models.JSONB(softwareInventory)
	}
	if len(systemFingerprint) > 0 {
		updates["system_fingerprint"] = models.JSONB(systemFingerprint)
	}
	if len(agentMetadata) > 0 {
		updates["agent_metadata"] = models.JSONB(agentMetadata)
	}

	if len(updates) == 0 {
		return nil
	}

	updates["updated_at"] = time.Now()
	return r.db.Model(&models.Host{}).Where("id = ?", hostID).Updates(updates).Error
}

// UpsertPort creates or finds a port by number and protocol, returns its ID
func (r *HostRepository) UpsertPort(number int, protocol, state string) (portID uint, err error) {
	if r.db == nil {
		return 0, fmt.Errorf("database connection not available")
	}

	// Set defaults
	if protocol == "" {
		protocol = "tcp"
	}
	if state == "" {
		state = "open"
	}

	var port models.Port
	result := r.db.Where("number = ? AND protocol = ?", number, protocol).
		Attrs(models.Port{State: state}).
		Assign(models.Port{State: state}).
		FirstOrCreate(&port, models.Port{Number: number, Protocol: protocol})

	if result.Error != nil {
		return 0, fmt.Errorf("failed to upsert port %d/%s: %w", number, protocol, result.Error)
	}

	return port.ID, nil
}

// UpsertVulnerability creates or finds a vulnerability by VID, returns its ID
func (r *HostRepository) UpsertVulnerability(vid, title, desc string, score float64) (vulnID uint, err error) {
	if r.db == nil {
		return 0, fmt.Errorf("database connection not available")
	}

	var vuln models.Vulnerability
	result := r.db.Select("id, v_id, description, title, risk_score, created_at, updated_at, deleted_at").
		Where("v_id = ?", vid).
		First(&vuln)

	if result.Error == nil {
		// Vulnerability exists - update if needed
		updates := map[string]interface{}{
			"updated_at": time.Now(),
		}
		if title != "" && vuln.Title != title {
			updates["title"] = title
		}
		if desc != "" && vuln.Description != desc {
			updates["description"] = desc
		}
		if score > 0 && vuln.RiskScore != score {
			updates["risk_score"] = score
		}

		if len(updates) > 1 { // More than just updated_at
			err = r.db.Model(&vuln).Updates(updates).Error
			if err != nil {
				return 0, fmt.Errorf("failed to update vulnerability: %w", err)
			}
		}
		return vuln.ID, nil
	}

	// Vulnerability doesn't exist - create it
	newVuln := models.Vulnerability{
		VID:         vid,
		Title:       title,
		Description: desc,
		RiskScore:   score,
	}

	err = r.db.Create(&newVuln).Error
	if err != nil {
		return 0, fmt.Errorf("failed to create vulnerability: %w", err)
	}

	return newVuln.ID, nil
}

// LinkHostPort creates or updates a host-port relationship with source attribution
func (r *HostRepository) LinkHostPort(hostID, portID uint, source models.ScanSource) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

	now := time.Now()

	// Check if this host-port-source combination already exists
	var hostPort models.HostPort
	err := r.db.Where("host_id = ? AND port_id = ? AND source = ?", hostID, portID, source.Name).
		First(&hostPort).Error

	if err == nil {
		// Update existing relationship
		err = r.db.Model(&models.HostPort{}).
			Where("host_id = ? AND port_id = ? AND source = ?", hostID, portID, source.Name).
			Updates(map[string]interface{}{
				"last_seen":      now,
				"source_version": source.Version,
				"status":         "active",
				"notes":          source.Config,
			}).Error
		if err != nil {
			return fmt.Errorf("failed to update host-port relationship: %w", err)
		}
		return nil
	}

	// Create new relationship
	hostPort = models.HostPort{
		HostID:        hostID,
		PortID:        portID,
		Source:        source.Name,
		SourceVersion: source.Version,
		FirstSeen:     now,
		LastSeen:      now,
		Status:        "active",
		Notes:         source.Config,
	}

	err = r.db.Create(&hostPort).Error
	if err != nil {
		return fmt.Errorf("failed to create host-port relationship: %w", err)
	}

	return nil
}

// LinkHostVulnerability creates or updates a host-vulnerability relationship with source attribution
func (r *HostRepository) LinkHostVulnerability(hostID, vulnID uint, source models.ScanSource) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}

	now := time.Now()

	// Check if this host-vulnerability-source combination already exists
	var hostVuln models.HostVulnerability
	err := r.db.Where("host_id = ? AND vulnerability_id = ? AND source = ?", hostID, vulnID, source.Name).
		First(&hostVuln).Error

	if err == nil {
		// Update existing relationship
		err = r.db.Model(&models.HostVulnerability{}).
			Where("host_id = ? AND vulnerability_id = ? AND source = ?", hostID, vulnID, source.Name).
			Updates(map[string]interface{}{
				"last_seen":      now,
				"source_version": source.Version,
				"status":         "active",
				"notes":          source.Config,
			}).Error
		if err != nil {
			return fmt.Errorf("failed to update host-vulnerability relationship: %w", err)
		}
		return nil
	}

	// Create new relationship
	hostVuln = models.HostVulnerability{
		HostID:          hostID,
		VulnerabilityID: vulnID,
		Source:          source.Name,
		SourceVersion:   source.Version,
		FirstSeen:       now,
		LastSeen:        now,
		Status:          "active",
		Confidence:      1.0,
		Notes:           source.Config,
	}

	err = r.db.Create(&hostVuln).Error
	if err != nil {
		return fmt.Errorf("failed to create host-vulnerability relationship: %w", err)
	}

	return nil
}

// GetHostWithRelations retrieves a host with ports and vulnerabilities using explicit JOINs
func (r *HostRepository) GetHostWithRelations(ip string) (*HostWithRelations, error) {
	if r.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// First, get the host basic info
	var host models.Host
	err := r.db.Select("id, h_id, os, os_version, ip, hostname, agent_id, software_inventory, system_fingerprint, agent_metadata, created_at, updated_at, deleted_at").
		Where("ip = ?", ip).
		First(&host).Error
	if err != nil {
		return nil, fmt.Errorf("host not found: %w", err)
	}

	result := &HostWithRelations{
		Host:            host,
		Ports:           []PortRelation{},
		Vulnerabilities: []VulnerabilityRelation{},
	}

	// Get ports with source attribution
	portQuery := `
		SELECT 
			p.id, p.number, p.protocol, p.state, p.created_at, p.updated_at, p.deleted_at,
			hp.source, hp.source_version, hp.first_seen, hp.last_seen, hp.status, hp.notes
		FROM host_ports hp
		JOIN ports p ON hp.port_id = p.id
		WHERE hp.host_id = ? AND hp.status = 'active'
		ORDER BY p.number, p.protocol
	`

	portRows, err := r.db.Raw(portQuery, host.ID).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to query ports: %w", err)
	}
	defer portRows.Close()

	portMap := make(map[uint]*PortRelation)
	for portRows.Next() {
		var port models.Port
		var pr PortRelation
		var firstSeen, lastSeen sql.NullTime

		err := portRows.Scan(
			&port.ID, &port.Number, &port.Protocol, &port.State,
			&port.CreatedAt, &port.UpdatedAt, &port.DeletedAt,
			&pr.Source, &pr.SourceVersion, &firstSeen, &lastSeen,
			&pr.Status, &pr.Notes,
		)
		if err != nil {
			log.Printf("Error scanning port row: %v", err)
			continue
		}

		if firstSeen.Valid {
			pr.FirstSeen = firstSeen.Time
		}
		if lastSeen.Valid {
			pr.LastSeen = lastSeen.Time
		}

		pr.Port = port

		// Deduplicate ports (same port can have multiple sources)
		// Keep the one with the most recent last_seen
		if existing, exists := portMap[port.ID]; !exists || pr.LastSeen.After(existing.LastSeen) {
			portMap[port.ID] = &pr
		}
	}

	// Convert map to slice
	for _, pr := range portMap {
		result.Ports = append(result.Ports, *pr)
	}

	// Get vulnerabilities with source attribution
	vulnQuery := `
		SELECT 
			v.id, v.v_id, v.title, v.description, v.risk_score, v.created_at, v.updated_at, v.deleted_at,
			hv.source, hv.source_version, hv.first_seen, hv.last_seen, hv.status, hv.confidence,
			hv.port, hv.service_info, hv.notes
		FROM host_vulnerabilities hv
		JOIN vulnerabilities v ON hv.vulnerability_id = v.id
		WHERE hv.host_id = ? AND hv.status = 'active'
		ORDER BY v.risk_score DESC, v.v_id
	`

	vulnRows, err := r.db.Raw(vulnQuery, host.ID).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer vulnRows.Close()

	vulnMap := make(map[uint]*VulnerabilityRelation)
	for vulnRows.Next() {
		var vuln models.Vulnerability
		var vr VulnerabilityRelation
		var firstSeen, lastSeen sql.NullTime
		var port sql.NullInt64

		err := vulnRows.Scan(
			&vuln.ID, &vuln.VID, &vuln.Title, &vuln.Description, &vuln.RiskScore,
			&vuln.CreatedAt, &vuln.UpdatedAt, &vuln.DeletedAt,
			&vr.Source, &vr.SourceVersion, &firstSeen, &lastSeen,
			&vr.Status, &vr.Confidence, &port, &vr.ServiceInfo, &vr.Notes,
		)
		if err != nil {
			log.Printf("Error scanning vulnerability row: %v", err)
			continue
		}

		if firstSeen.Valid {
			vr.FirstSeen = firstSeen.Time
		}
		if lastSeen.Valid {
			vr.LastSeen = lastSeen.Time
		}
		if port.Valid {
			portInt := int(port.Int64)
			vr.Port = &portInt
		}

		vr.Vulnerability = vuln

		// Deduplicate vulnerabilities (same vuln can have multiple sources)
		// Keep the one with the highest confidence or most recent
		if existing, exists := vulnMap[vuln.ID]; !exists || vr.Confidence > existing.Confidence || vr.LastSeen.After(existing.LastSeen) {
			vulnMap[vuln.ID] = &vr
		}
	}

	// Convert map to slice
	for _, vr := range vulnMap {
		result.Vulnerabilities = append(result.Vulnerabilities, *vr)
	}

	return result, nil
}

// GetAllHostsWithRelations retrieves all hosts with their ports and vulnerabilities
func (r *HostRepository) GetAllHostsWithRelations() ([]HostWithRelations, error) {
	if r.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// Get all hosts
	var hosts []models.Host
	err := r.db.Select("id, h_id, os, os_version, ip, hostname, agent_id, software_inventory, system_fingerprint, agent_metadata, created_at, updated_at, deleted_at").
		Find(&hosts).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query hosts: %w", err)
	}

	results := make([]HostWithRelations, 0, len(hosts))
	for _, host := range hosts {
		hostWithRelations, err := r.GetHostWithRelations(host.IP)
		if err != nil {
			log.Printf("Warning: Failed to get relations for host %s: %v", host.IP, err)
			// Still include the host but without relations
			results = append(results, HostWithRelations{
				Host:            host,
				Ports:           []PortRelation{},
				Vulnerabilities: []VulnerabilityRelation{},
			})
			continue
		}
		results = append(results, *hostWithRelations)
	}

	return results, nil
}
