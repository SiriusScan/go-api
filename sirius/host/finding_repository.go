package host

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UpsertHostVulnerability stores a complete observation on the host/source
// junction, not in the shared vulnerability catalog. Catalog fields remain for
// legacy consumers; changing another host's catalog cannot change this snapshot.
func (r *HostRepository) UpsertHostVulnerability(hostID uint, finding sirius.Vulnerability, source models.ScanSource) error {
	return r.upsertHostVulnerability(hostID, finding, source, true)
}

// upsertHostVulnerability stores private observations on the host junction.
// Scoped reports must not publish their contents into the shared catalog.
func (r *HostRepository) upsertHostVulnerability(hostID uint, finding sirius.Vulnerability, source models.ScanSource, updateCatalog bool) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}
	if strings.TrimSpace(finding.VID) == "" {
		return fmt.Errorf("vulnerability VID is required")
	}
	if math.IsNaN(finding.Confidence) || math.IsInf(finding.Confidence, 0) || finding.Confidence < 0 || finding.Confidence > 1 {
		return fmt.Errorf("vulnerability confidence must be between 0 and 1")
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("encode vulnerability finding: %w", err)
	}
	snapshot := models.FindingJSON(encoded)
	return r.db.Transaction(func(tx *gorm.DB) error {
		// The catalog's existing unique VID index remains authoritative. Serialize
		// cooperating writers for this VID before the legacy lookup/create path.
		// A failure in either write rolls back both catalog and observation.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "sirius-finding:"+finding.VID).Error; err != nil {
			return err
		}
		tr := &HostRepository{db: tx}
		var owner string
		if err := tx.Model(&models.Host{}).Select("owner_subject_id").Where("id = ?", hostID).Scan(&owner).Error; err != nil {
			return fmt.Errorf("lookup finding host scope: %w", err)
		}
		if owner != "" {
			updateCatalog = false
		}
		title, description, score := finding.Title, finding.Description, finding.RiskScore
		if !updateCatalog {
			title, description, score = "", "", 0
		}
		id, err := tr.UpsertVulnerability(finding.VID, title, description, score)
		if err != nil {
			return err
		}
		return tr.writeVulnerabilityObservation(hostID, id, source, snapshot, finding.Confidence)
	})
}

// LinkHostVulnerability is the compatibility API for callers without a complete
// finding. It must not erase evidence/confidence from an existing modern report.
func (r *HostRepository) LinkHostVulnerability(hostID, vulnID uint, source models.ScanSource) error {
	return r.writeVulnerabilityObservation(hostID, vulnID, source, nil, 1)
}

func (r *HostRepository) writeVulnerabilityObservation(hostID, vulnID uint, source models.ScanSource, finding models.FindingJSON, confidence float64) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}
	if strings.TrimSpace(source.Name) == "" {
		source.Name = "unknown"
	}
	now := time.Now()
	// A map bypasses GORM's default:1.0 substitution for a valid zero confidence.
	row := map[string]interface{}{
		"host_id": hostID, "vulnerability_id": vulnID, "source": source.Name,
		"source_version": source.Version, "first_seen": now, "last_seen": now,
		"status": "active", "notes": source.Config, "confidence": confidence,
	}
	columns := []string{"source_version", "last_seen", "status", "notes"}
	if finding != nil {
		row["finding"] = finding
		columns = append(columns, "finding", "confidence")
	}
	return r.db.Table("host_vulnerabilities").Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "host_id"}, {Name: "vulnerability_id"}, {Name: "source"}},
		DoUpdates: clause.AssignmentColumns(columns),
	}).Create(row).Error
}

func vulnerabilityFromRelation(vr VulnerabilityRelation) sirius.Vulnerability {
	if vr.Finding != nil {
		return *vr.Finding
	}
	return sirius.Vulnerability{
		VID: vr.Vulnerability.VID, Title: vr.Vulnerability.Title,
		Description: vr.Vulnerability.Description, RiskScore: vr.Vulnerability.RiskScore,
		Confidence: vr.Confidence,
	}
}

// All evidence remains available through the source-aware endpoint. The legacy
// canonical list selects one complete observation, never mixed source fields.
func (r *HostRepository) getVulnerabilityRelations(hostID uint) ([]VulnerabilityRelation, error) {
	observations, err := r.getVulnerabilityObservations(hostID, true)
	if err != nil {
		return nil, err
	}
	byID := make(map[uint]VulnerabilityRelation)
	for _, vr := range observations {
		old, ok := byID[vr.Vulnerability.ID]
		if !ok || preferVulnerabilityObservation(vr, old) {
			byID[vr.Vulnerability.ID] = vr
		}
	}
	result := make([]VulnerabilityRelation, 0, len(byID))
	for _, vr := range byID {
		result = append(result, vr)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := vulnerabilityFromRelation(result[i]), vulnerabilityFromRelation(result[j])
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if a.VID != b.VID {
			return a.VID < b.VID
		}
		return result[i].Vulnerability.ID < result[j].Vulnerability.ID
	})
	return result, nil
}

func preferVulnerabilityObservation(a, b VulnerabilityRelation) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if !a.LastSeen.Equal(b.LastSeen) {
		return a.LastSeen.After(b.LastSeen)
	}
	return a.Source < b.Source
}

func (r *HostRepository) getVulnerabilitySources(hostID uint) ([]models.VulnerabilityWithSource, error) {
	observations, err := r.getVulnerabilityObservations(hostID, false)
	if err != nil {
		return nil, err
	}
	result := make([]models.VulnerabilityWithSource, 0, len(observations))
	for _, vr := range observations {
		result = append(result, models.VulnerabilityWithSource{
			Vulnerability: vr.Vulnerability,
			SourceAttribution: models.SourceAttribution{Source: vr.Source, SourceVersion: vr.SourceVersion,
				FirstSeen: vr.FirstSeen, LastSeen: vr.LastSeen, Status: vr.Status, Confidence: vr.Confidence, Notes: vr.Notes},
			Port: vr.Port, ServiceInfo: vr.ServiceInfo, Finding: vr.Finding,
		})
	}
	return result, nil
}

func (r *HostRepository) getVulnerabilityObservations(hostID uint, activeOnly bool) ([]VulnerabilityRelation, error) {
	query := `SELECT v.id, v.v_id, COALESCE(v.title,''), COALESCE(v.description,''), COALESCE(v.risk_score,0),
        v.created_at, v.updated_at, v.deleted_at,
        COALESCE(hv.source,''), COALESCE(hv.source_version,''), hv.first_seen, hv.last_seen,
        COALESCE(hv.status,''), COALESCE(hv.confidence,0), hv.port, COALESCE(hv.service_info,''), COALESCE(hv.notes,''), hv.finding
        FROM host_vulnerabilities hv JOIN vulnerabilities v ON hv.vulnerability_id = v.id
        WHERE hv.host_id = ? AND v.deleted_at IS NULL`
	if activeOnly {
		query += " AND hv.status = 'active'"
	}
	query += " ORDER BY v.v_id, hv.source"
	rows, err := r.db.Raw(query, hostID).Rows()
	if err != nil {
		return nil, fmt.Errorf("query vulnerability observations: %w", err)
	}
	defer rows.Close()
	result := []VulnerabilityRelation{}
	for rows.Next() {
		var vr VulnerabilityRelation
		v := &vr.Vulnerability
		var created, updated, first, last *time.Time
		var snapshot models.FindingJSON
		if err := rows.Scan(&v.ID, &v.VID, &v.Title, &v.Description, &v.RiskScore,
			&created, &updated, &v.DeletedAt, &vr.Source, &vr.SourceVersion, &first, &last,
			&vr.Status, &vr.Confidence, &vr.Port, &vr.ServiceInfo, &vr.Notes, &snapshot); err != nil {
			return nil, fmt.Errorf("read vulnerability observation: %w", err)
		}
		if created != nil {
			v.CreatedAt = *created
		}
		if updated != nil {
			v.UpdatedAt = *updated
		}
		if first != nil {
			vr.FirstSeen = *first
		}
		if last != nil {
			vr.LastSeen = *last
		}
		if len(snapshot) != 0 {
			var finding sirius.Vulnerability
			decoder := json.NewDecoder(bytes.NewReader(snapshot))
			decoder.UseNumber()
			if err := decoder.Decode(&finding); err != nil {
				return nil, fmt.Errorf("decode vulnerability finding: %w", err)
			}
			if finding.VID != v.VID {
				return nil, fmt.Errorf("vulnerability finding identity mismatch")
			}
			// The attribution column is authoritative for confidence and analytics.
			finding.Confidence = vr.Confidence
			vr.Finding = &finding
			// Keep the existing basic-field projections source-specific too.
			v.Title, v.Description, v.RiskScore = finding.Title, finding.Description, finding.RiskScore
		}
		result = append(result, vr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read vulnerability observations: %w", err)
	}
	return result, nil
}
