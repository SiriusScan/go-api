package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/SiriusScan/go-api/sirius/scope"
	"gorm.io/gorm"
)

// ErrInvalidReport identifies invalid input before any report writes occur.
var ErrInvalidReport = errors.New("invalid host report")

// Report is one ingestion unit. Catalog contains optional enriched catalog
// entries for its findings; original scanner evidence in Host is never replaced.
// Perform external enrichment before AddReport, not while holding a transaction.
type Report struct {
	Host              sirius.Host
	Source            models.ScanSource
	SoftwareInventory map[string]interface{}
	SystemFingerprint map[string]interface{}
	AgentMetadata     map[string]interface{}
	Catalog           []sirius.Vulnerability
}

// ValidateReport validates every finding and JSON document before persistence.
// It is also safe to call at the HTTP boundary before expensive enrichment.
func ValidateReport(report Report) error {
	for i, port := range report.Host.Ports {
		if port.Number < 0 || port.Number > 65535 {
			return fmt.Errorf("%w: ports[%d].number must be between 0 and 65535", ErrInvalidReport, i)
		}
	}
	ids := make(map[string]bool, len(report.Host.Vulnerabilities))
	for i, finding := range report.Host.Vulnerabilities {
		if strings.TrimSpace(finding.VID) == "" {
			return fmt.Errorf("%w: vulnerabilities[%d].vid is required", ErrInvalidReport, i)
		}
		if math.IsNaN(finding.Confidence) || math.IsInf(finding.Confidence, 0) || finding.Confidence < 0 || finding.Confidence > 1 {
			return fmt.Errorf("%w: vulnerabilities[%d].confidence must be between 0 and 1", ErrInvalidReport, i)
		}
		ids[finding.VID] = true
	}
	for _, entry := range report.Catalog {
		if !ids[entry.VID] {
			return fmt.Errorf("%w: catalog entry %q has no report finding", ErrInvalidReport, entry.VID)
		}
	}
	// This catches unsupported metadata, non-finite numbers and cyclic maps,
	// including enhanced JSONB data supplied by direct SDK callers.
	if _, err := json.Marshal(report); err != nil {
		return fmt.Errorf("%w: encode report: %v", ErrInvalidReport, err)
	}
	return nil
}

// AddReport commits host, JSONB, shared identities, observations and scan history
// together. Any validation, statement or commit failure leaves no partial report.
func AddReport(report Report) error {
	// Validate before even initializing the default database connection.
	if err := ValidateReport(report); err != nil {
		return err
	}
	return NewHostRepository().addReport(report)
}

// AddReportScoped persists a report under a scope authorized by the caller.
func AddReportScoped(resourceScope scope.ResourceScope, report Report) error {
	return NewHostRepository().addReportScoped(resourceScope, report)
}

func (r *HostRepository) addReport(report Report) error {
	return r.addReportScoped(scope.Global(), report)
}

func (r *HostRepository) addReportScoped(resourceScope scope.ResourceScope, report Report) error {
	if err := ValidateReport(report); err != nil {
		return err
	}
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}
	if strings.TrimSpace(report.Source.Name) == "" {
		report.Source.Name = "unknown"
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		repo := &HostRepository{db: tx}
		// The legacy host lookup has no unique IP constraint. Serialize report
		// writers for one host, including retries, without changing that schema.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "sirius-report-host:"+report.Host.IP).Error; err != nil {
			return err
		}
		// Acquire shared catalog locks in a stable order so overlapping reports
		// cannot deadlock just because they list their findings in reverse order.
		ids := make(map[string]bool, len(report.Host.Vulnerabilities))
		for _, finding := range report.Host.Vulnerabilities {
			ids[finding.VID] = true
		}
		ordered := make([]string, 0, len(ids))
		for id := range ids {
			ordered = append(ordered, id)
		}
		sort.Strings(ordered)
		for _, id := range ordered {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", "sirius-finding:"+id).Error; err != nil {
				return err
			}
		}
		hostID, err := repo.UpsertHostScoped(resourceScope, report.Host.IP, report.Host.Hostname, report.Host.OS, report.Host.OSVersion, report.Host.HID)
		if err != nil {
			return fmt.Errorf("upsert report host: %w", err)
		}
		if err := repo.UpdateHostJSONB(hostID, report.SoftwareInventory, report.SystemFingerprint, report.AgentMetadata); err != nil {
			return fmt.Errorf("update report JSONB: %w", err)
		}
		// Shared port identity inserts can also block one another. Use a stable
		// order while preserving the last occurrence of duplicate observations.
		ports := append([]sirius.Port(nil), report.Host.Ports...)
		for i := range ports {
			if ports[i].Protocol == "" {
				ports[i].Protocol = "tcp"
			}
		}
		sort.SliceStable(ports, func(i, j int) bool {
			if ports[i].Number != ports[j].Number {
				return ports[i].Number < ports[j].Number
			}
			return ports[i].Protocol < ports[j].Protocol
		})
		for _, port := range ports {
			if err := repo.UpsertHostPort(hostID, port.Number, port.Protocol, port.State, report.Source); err != nil {
				return fmt.Errorf("upsert report port %d/%s: %w", port.Number, port.Protocol, err)
			}
		}
		for _, finding := range report.Host.Vulnerabilities {
			if err := repo.UpsertHostVulnerability(hostID, finding, report.Source); err != nil {
				return fmt.Errorf("upsert report finding %s: %w", finding.VID, err)
			}
		}
		for _, entry := range report.Catalog {
			if _, err := repo.UpsertVulnerability(entry.VID, entry.Title, entry.Description, entry.RiskScore); err != nil {
				return fmt.Errorf("enrich report catalog %s: %w", entry.VID, err)
			}
		}
		count := len(report.Host.Ports) + len(report.Host.Vulnerabilities)
		if len(report.SoftwareInventory) > 0 {
			count++
		}
		if len(report.SystemFingerprint) > 0 {
			count++
		}
		entry := models.ScanHistoryEntry{HostID: hostID, Source: report.Source.Name, SourceVersion: report.Source.Version,
			ScanTime: time.Now(), FindingsCount: count, ScanConfig: report.Source.Config}
		if err := tx.Create(&entry).Error; err != nil {
			return fmt.Errorf("record report scan history: %w", err)
		}
		return nil
	})
}
