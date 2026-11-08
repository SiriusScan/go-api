package host

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrPortIdentityDeleted means an observation targets a retired shared identity.
// Automatic resurrection would expose other hosts' retired relationships.
var ErrPortIdentityDeleted = errors.New("port identity is soft-deleted; restore or reconcile it explicitly before recording observations")

// UpsertPort finds or creates a shared (number, protocol) identity. It never
// writes observation state to the global catalog.
// Deprecated: state is ignored; use UpsertHostPort to save a host observation.
func (r *HostRepository) UpsertPort(number int, protocol, state string) (uint, error) {
	if r.db == nil {
		return 0, fmt.Errorf("database connection not available")
	}
	if protocol == "" {
		protocol = "tcp"
	}
	port := models.Port{Number: number, Protocol: protocol}
	// The unique identity index plus ON CONFLICT makes concurrent observations
	// converge on the same identity without modifying another host's state.
	if err := r.db.Omit("State", "HostPorts").Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "number"}, {Name: "protocol"}},
		DoNothing: true,
	}).Create(&port).Error; err != nil {
		return 0, fmt.Errorf("failed to create port identity %d/%s: %w", number, protocol, err)
	}
	if err := r.db.Unscoped().Where("number = ? AND protocol = ?", number, protocol).First(&port).Error; err != nil {
		return 0, fmt.Errorf("failed to find port identity %d/%s: %w", number, protocol, err)
	}
	if port.DeletedAt.Valid {
		return 0, fmt.Errorf("port %d/%s: %w", number, protocol, ErrPortIdentityDeleted)
	}
	return port.ID, nil
}

// UpsertHostPort atomically saves an observation scoped to host and source.
// An omitted scanner state retains the historical default of open.
func (r *HostRepository) UpsertHostPort(hostID uint, number int, protocol, state string, source models.ScanSource) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}
	if state == "" {
		state = "open"
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		repo := &HostRepository{db: tx}
		portID, err := repo.UpsertPort(number, protocol, "")
		if err != nil {
			return err
		}
		return repo.LinkHostPortWithState(hostID, portID, source, state)
	})
}

// LinkHostPort refreshes a relationship without inventing observation state.
// Existing state is preserved; a new relationship has unknown state.
// Deprecated: use UpsertHostPort or LinkHostPortWithState for observations.
func (r *HostRepository) LinkHostPort(hostID, portID uint, source models.ScanSource) error {
	return r.linkHostPort(hostID, portID, source, nil)
}

// LinkHostPortWithState updates only the specified host/port/source observation.
func (r *HostRepository) LinkHostPortWithState(hostID, portID uint, source models.ScanSource, state string) error {
	if state == "" {
		state = "unknown"
	}
	return r.linkHostPort(hostID, portID, source, &state)
}

func (r *HostRepository) linkHostPort(hostID, portID uint, source models.ScanSource, state *string) error {
	if r.db == nil {
		return fmt.Errorf("database connection not available")
	}
	if strings.TrimSpace(source.Name) == "" {
		source.Name = "unknown"
	}
	now := time.Now()
	observation := models.HostPort{
		HostID: hostID, PortID: portID, Source: source.Name,
		SourceVersion: source.Version, FirstSeen: now, LastSeen: now,
		State: "unknown", Status: "active", Notes: source.Config,
	}
	updates := []string{"source_version", "last_seen", "status", "notes"}
	if state != nil {
		observation.State = *state
		updates = append(updates, "state")
	}
	if err := r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "host_id"}, {Name: "port_id"}, {Name: "source"}},
		DoUpdates: clause.AssignmentColumns(updates),
	}).Create(&observation).Error; err != nil {
		return fmt.Errorf("failed to save host-port observation: %w", err)
	}
	return nil
}

func (r *HostRepository) getPortSources(hostID uint) ([]models.PortWithSource, error) {
	var result []models.PortWithSource
	err := r.db.Table("host_ports hp").
		Select(`p.id, p.number, p.protocol, p.created_at, p.updated_at, p.deleted_at,
			COALESCE(NULLIF(hp.state, ''), 'unknown') AS state,
			hp.source, hp.source_version, hp.first_seen, hp.last_seen, hp.status, hp.notes`).
		Joins("JOIN ports p ON hp.port_id = p.id").
		Where("hp.host_id = ? AND p.deleted_at IS NULL", hostID).
		Order("p.number, p.protocol, hp.source").Scan(&result).Error
	return result, err
}
