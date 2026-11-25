package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/SiriusScan/go-api/sirius/scope"
	"gorm.io/gorm"
)

const (
	// DefaultAcceptedReportLimit is the page size for callers with no preference.
	DefaultAcceptedReportLimit = 20
	// MaxAcceptedReportLimit bounds the number of entries returned per page.
	MaxAcceptedReportLimit = 100

	maxAcceptedReportCursorLength = 256
)

// ErrInvalidAcceptedReportPage identifies an invalid page limit or cursor.
var ErrInvalidAcceptedReportPage = errors.New("invalid accepted report page")

// AcceptedReport identifies an accepted submission. A zero SubmittedItemCount
// is a recorded value, and a nil count means the historical value is unknown.
type AcceptedReport struct {
	ID                 uint       `json:"id"`
	Source             string     `json:"source"`
	SourceVersion      string     `json:"source_version"`
	AcceptedAt         *time.Time `json:"accepted_at"`
	SubmittedItemCount *int       `json:"submitted_item_count"`
	AssessmentCoverage string     `json:"assessment_coverage"`
}

// AcceptedReportHistoryPage includes host discovery metadata without loading
// ports, findings, inventory or other host relationships.
type AcceptedReportHistoryPage struct {
	HostID        uint             `json:"host_id"`
	HostIP        string           `json:"host_ip"`
	HostCreatedAt *time.Time       `json:"host_created_at"`
	Reports       []AcceptedReport `json:"reports"`
	NextCursor    string           `json:"next_cursor,omitempty"`
}

type acceptedReportCursor struct {
	HostID     uint       `json:"host"`
	ReportID   uint       `json:"id"`
	AcceptedAt *time.Time `json:"at"`
}

type acceptedReportHistoryRow struct {
	HostID             uint
	HostIP             string
	HostCreatedAt      *time.Time
	ReportID           *uint
	Source             string
	SourceVersion      string
	AcceptedAt         *time.Time
	SubmittedItemCount *int
}

func hostByScopedIP(db *gorm.DB, resourceScope scope.ResourceScope, ip string) *gorm.DB {
	return db.Model(&models.Host{}).
		Where("hosts.ip = ? AND hosts.owner_subject_id = ?", ip, resourceScope.OwnerSubjectID)
}

func decodeAcceptedReportCursor(value string) (*acceptedReportCursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > maxAcceptedReportCursorLength {
		return nil, fmt.Errorf("%w: malformed cursor", ErrInvalidAcceptedReportPage)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed cursor", ErrInvalidAcceptedReportPage)
	}
	var cursor acceptedReportCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.HostID == 0 || cursor.ReportID == 0 {
		return nil, fmt.Errorf("%w: malformed cursor", ErrInvalidAcceptedReportPage)
	}
	return &cursor, nil
}

// ListAcceptedReportHistory reads the accepted-report journal for the host
// identified by ip in the supplied, caller-authorized scope. Empty history
// returns an empty Reports slice. A missing or out-of-scope host returns
// gorm.ErrRecordNotFound. Report acceptance leaves assessment coverage unknown.
func (r *HostRepository) ListAcceptedReportHistory(
	ctx context.Context,
	resourceScope scope.ResourceScope,
	ip string,
	limit int,
	cursor string,
) (AcceptedReportHistoryPage, error) {
	if limit < 1 || limit > MaxAcceptedReportLimit {
		return AcceptedReportHistoryPage{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidAcceptedReportPage, MaxAcceptedReportLimit)
	}
	position, err := decodeAcceptedReportCursor(cursor)
	if err != nil {
		return AcceptedReportHistoryPage{}, err
	}
	if err := ctx.Err(); err != nil {
		return AcceptedReportHistoryPage{}, err
	}
	if r.db == nil {
		return AcceptedReportHistoryPage{}, errors.New("database connection not available")
	}

	var rows []acceptedReportHistoryRow
	if err := acceptedReportHistoryQuery(r.db.WithContext(ctx), resourceScope, ip, limit, position).Find(&rows).Error; err != nil {
		return AcceptedReportHistoryPage{}, fmt.Errorf("read accepted report history: %w", err)
	}
	return projectAcceptedReportHistory(rows, limit, position)
}

func acceptedReportHistoryQuery(
	db *gorm.DB,
	resourceScope scope.ResourceScope,
	ip string,
	limit int,
	position *acceptedReportCursor,
) *gorm.DB {
	target := hostByScopedIP(db, resourceScope, ip).
		Select("hosts.id, hosts.ip, hosts.created_at").
		Order("hosts.id ASC").
		Limit(1)
	journal := db.Table("scan_history_entries AS entry").
		Select("entry.id AS report_id, entry.source, entry.source_version, entry.scan_time AS accepted_at, entry.findings_count AS submitted_item_count").
		Where("entry.host_id = target_host.id AND entry.deleted_at IS NULL").
		Order("entry.scan_time DESC NULLS LAST, entry.id DESC").
		Limit(limit + 1)
	if position != nil {
		if position.AcceptedAt == nil {
			journal = journal.Where("entry.scan_time IS NULL AND entry.id < ?", position.ReportID)
		} else {
			journal = journal.Where("((entry.scan_time, entry.id) < (?, ?) OR entry.scan_time IS NULL)", *position.AcceptedAt, position.ReportID)
		}
	}

	// The left lateral join preserves hosts with no rows and resolves scope
	// and journal visibility in the same database snapshot.
	return db.Table("(?) AS target_host", target).
		Select("target_host.id AS host_id, target_host.ip AS host_ip, target_host.created_at AS host_created_at, journal.report_id, journal.source, journal.source_version, journal.accepted_at, journal.submitted_item_count").
		Joins("LEFT JOIN LATERAL (?) AS journal ON TRUE", journal).
		Order("journal.accepted_at DESC NULLS LAST, journal.report_id DESC")
}

func projectAcceptedReportHistory(
	rows []acceptedReportHistoryRow,
	limit int,
	position *acceptedReportCursor,
) (AcceptedReportHistoryPage, error) {
	if len(rows) == 0 {
		return AcceptedReportHistoryPage{}, gorm.ErrRecordNotFound
	}
	host := rows[0]
	if position != nil && position.HostID != host.HostID {
		return AcceptedReportHistoryPage{}, fmt.Errorf("%w: cursor belongs to a different host", ErrInvalidAcceptedReportPage)
	}

	page := AcceptedReportHistoryPage{
		HostID:        host.HostID,
		HostIP:        host.HostIP,
		HostCreatedAt: knownReportTime(host.HostCreatedAt),
		Reports:       make([]AcceptedReport, 0, min(len(rows), limit)),
	}
	for _, row := range rows[:min(len(rows), limit)] {
		if row.ReportID == nil {
			continue
		}
		page.Reports = append(page.Reports, AcceptedReport{
			ID:                 *row.ReportID,
			Source:             row.Source,
			SourceVersion:      row.SourceVersion,
			AcceptedAt:         knownReportTime(row.AcceptedAt),
			SubmittedItemCount: row.SubmittedItemCount,
			AssessmentCoverage: "unknown",
		})
	}
	if len(rows) > limit {
		last := rows[limit-1]
		payload, err := json.Marshal(acceptedReportCursor{
			HostID:     host.HostID,
			ReportID:   *last.ReportID,
			AcceptedAt: last.AcceptedAt,
		})
		if err != nil {
			return AcceptedReportHistoryPage{}, fmt.Errorf("encode accepted report cursor: %w", err)
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(payload)
	}
	return page, nil
}

func knownReportTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}
