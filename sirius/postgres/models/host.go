// File: host.go
package models

import (
	"gorm.io/gorm"
)

type Host struct {
	gorm.Model
	HID             string
	OS              string
	OSVersion       string
	IP              string `gorm:"uniqueIndex"`
	Hostname        string
	Ports           []Port `gorm:"many2many:host_ports"`
	Services        []Service
	Vulnerabilities []Vulnerability `gorm:"many2many:host_vulnerabilities"`
	CPEs            []CPE
	Users           []User
	Notes           []Note
	AgentID         uint
}

type Port struct {
	gorm.Model
	ID       int
	Protocol string
	State    string
	Hosts    []Host `gorm:"many2many:host_ports"`
}

type HostPort struct {
	gorm.Model
	HostID uint
	PortID uint
}

type Service struct {
	gorm.Model
	Name   string
	HostID uint
}

type HostVulnerability struct {
	gorm.Model
	HostID uint
	// Foreign Key to Vulnerability from models/vulnerability
	VulnerabilityID uint
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
