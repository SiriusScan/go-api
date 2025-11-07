// File: event.go
package models

import (
	"time"
)

// Event represents a security or system event stored in PostgreSQL
type Event struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	EventID      string    `gorm:"uniqueIndex;not null;size:255" json:"event_id"`
	Timestamp    time.Time `gorm:"not null;default:NOW();index:idx_events_timestamp,sort:desc" json:"timestamp"`
	Service      string    `gorm:"not null;size:100;index:idx_events_service" json:"service"`
	Subcomponent string    `gorm:"size:100" json:"subcomponent,omitempty"`
	EventType    string    `gorm:"not null;size:50;index:idx_events_type" json:"event_type"`
	Severity     string    `gorm:"not null;size:20;index:idx_events_severity" json:"severity"`
	Title        string    `gorm:"not null;size:255" json:"title"`
	Description  string    `gorm:"type:text" json:"description,omitempty"`
	Metadata     JSONB     `gorm:"type:jsonb" json:"metadata,omitempty"`
	EntityType   string    `gorm:"size:50;index:idx_events_entity,priority:1" json:"entity_type,omitempty"`
	EntityID     string    `gorm:"size:255;index:idx_events_entity,priority:2" json:"entity_id,omitempty"`
	CreatedAt    time.Time `gorm:"not null;default:NOW()" json:"created_at"`
}

// TableName specifies the table name for the Event model
func (Event) TableName() string {
	return "events"
}

// EventSeverity constants for event severity levels
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

// EventType constants for common event types
const (
	EventTypeScanStarted          = "scan_started"
	EventTypeScanCompleted        = "scan_completed"
	EventTypeScanFailed           = "scan_failed"
	EventTypeScanPaused           = "scan_paused"
	EventTypeScanResumed          = "scan_resumed"
	EventTypeHostDiscovered       = "host_discovered"
	EventTypePortsDiscovered      = "ports_discovered"
	EventTypeVulnerabilitiesFound = "vulnerabilities_found"
	EventTypeHostCreated          = "host_created"
	EventTypeHostUpdated          = "host_updated"
	EventTypeHostDeleted          = "host_deleted"
	EventTypeVulnerabilityCreated = "vulnerability_created"
	EventTypeVulnerabilityUpdated = "vulnerability_updated"
)

// EntityType constants for event entity types
const (
	EntityTypeScan          = "scan"
	EntityTypeHost          = "host"
	EntityTypeVulnerability = "vulnerability"
	EntityTypePort          = "port"
	EntityTypeService       = "service"
)

// IsValidSeverity checks if a severity level is valid
func IsValidSeverity(severity string) bool {
	switch severity {
	case SeverityInfo, SeverityWarning, SeverityError, SeverityCritical:
		return true
	default:
		return false
	}
}

// IsValidEventType checks if an event type is valid
func IsValidEventType(eventType string) bool {
	switch eventType {
	case EventTypeScanStarted, EventTypeScanCompleted, EventTypeScanFailed,
		EventTypeScanPaused, EventTypeScanResumed, EventTypeHostDiscovered,
		EventTypePortsDiscovered, EventTypeVulnerabilitiesFound,
		EventTypeHostCreated, EventTypeHostUpdated, EventTypeHostDeleted,
		EventTypeVulnerabilityCreated, EventTypeVulnerabilityUpdated:
		return true
	default:
		return true // Allow custom event types
	}
}

// IsValidEntityType checks if an entity type is valid
func IsValidEntityType(entityType string) bool {
	if entityType == "" {
		return true // Entity type is optional
	}
	switch entityType {
	case EntityTypeScan, EntityTypeHost, EntityTypeVulnerability,
		EntityTypePort, EntityTypeService:
		return true
	default:
		return true // Allow custom entity types
	}
}

