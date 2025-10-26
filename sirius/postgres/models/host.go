// File: host.go
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// JSONB represents a JSONB field that can properly scan from PostgreSQL
type JSONB map[string]interface{}

// Value implements the driver.Valuer interface for database writes
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface for database reads
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = make(map[string]interface{})
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into JSONB", value)
	}

	if len(data) == 0 {
		*j = make(map[string]interface{})
		return nil
	}

	return json.Unmarshal(data, j)
}

type Host struct {
	gorm.Model
	HID                 string
	OS                  string
	OSVersion           string
	IP                  string `gorm:"uniqueIndex"`
	Hostname            string
	Ports               []Port `gorm:"many2many:host_ports"`
	Services            []Service
	Vulnerabilities     []Vulnerability     `gorm:"many2many:host_vulnerabilities"`
	HostVulnerabilities []HostVulnerability `gorm:"foreignKey:HostID"`
	HostPorts           []HostPort          `gorm:"foreignKey:HostID"`
	CPEs                []CPE
	Users               []User
	Notes               []Note
	AgentID             uint

	// SBOM and Fingerprinting JSONB fields (Migration 004) - Fixed with custom JSONB type
	SoftwareInventory JSONB `gorm:"type:jsonb;column:software_inventory;default:'{}'" json:"software_inventory,omitempty"`
	SystemFingerprint JSONB `gorm:"type:jsonb;column:system_fingerprint;default:'{}'" json:"system_fingerprint,omitempty"`
	AgentMetadata     JSONB `gorm:"type:jsonb;column:agent_metadata;default:'{}'" json:"agent_metadata,omitempty"`
}

type Port struct {
	gorm.Model
	Number    int    `gorm:"not null"`  // Port number (22, 80, 443, etc.)
	Protocol  string `gorm:"not null"`
	State     string
	Hosts     []Host     `gorm:"many2many:host_ports"`
	HostPorts []HostPort `gorm:"foreignKey:PortID"`
}

// TableName ensures GORM uses the correct table name
func (Port) TableName() string {
	return "ports"
}

// Enhanced HostPort junction table with source attribution
type HostPort struct {
	HostID        uint      `json:"host_id" gorm:"primaryKey"`
	PortID        uint      `json:"port_id" gorm:"primaryKey"`
	Source        string    `json:"source"`                       // "nmap", "agent", "manual", "rustscan"
	SourceVersion string    `json:"source_version"`               // Scanner version/build
	FirstSeen     time.Time `json:"first_seen"`                   // When first detected
	LastSeen      time.Time `json:"last_seen"`                    // When last confirmed
	Status        string    `json:"status" gorm:"default:active"` // "active", "resolved", "false_positive"
	Notes         string    `json:"notes,omitempty"`              // Additional context
}

type Service struct {
	gorm.Model
	Name   string
	HostID uint
}

// Enhanced HostVulnerability junction table with source attribution
type HostVulnerability struct {
	HostID          uint      `json:"host_id" gorm:"primaryKey"`
	VulnerabilityID uint      `json:"vulnerability_id" gorm:"primaryKey"` // Foreign Key to Vulnerability from models/vulnerability
	Source          string    `json:"source" gorm:"primaryKey"`           // "nmap", "agent", "manual", "rustscan"
	SourceVersion   string    `json:"source_version"`                     // Scanner version/build
	FirstSeen       time.Time `json:"first_seen"`                         // When first detected
	LastSeen        time.Time `json:"last_seen"`                          // When last confirmed
	Status          string    `json:"status" gorm:"default:active"`       // "active", "resolved", "false_positive"
	Confidence      float64   `json:"confidence" gorm:"default:1.0"`      // 0.0-1.0 confidence score
	Port            *int      `json:"port,omitempty"`                     // Specific port if applicable
	ServiceInfo     string    `json:"service_info,omitempty"`             // Service details
	Notes           string    `json:"notes,omitempty"`                    // Additional context
}

type Agent struct {
	gorm.Model
	Name string
	// ... other fields
}

type User struct {
	gorm.Model
	Name   string
	HostID uint
}

type Note struct {
	gorm.Model
	Content string
	HostID  uint
}

type CPE struct {
	gorm.Model
	Name   string
	HostID uint
}
