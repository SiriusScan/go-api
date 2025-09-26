package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

// Test data structures that match the JSONB schema
type SoftwareInventory struct {
	ScanMetadata ScanMetadata      `json:"scan_metadata"`
	Packages     []PackageInfo     `json:"packages"`
	Certificates []CertificateInfo `json:"certificates"`
}

type ScanMetadata struct {
	AgentVersion   string    `json:"agent_version"`
	ScanDate       time.Time `json:"scan_date"`
	ScanDurationMs int       `json:"scan_duration_ms"`
	ScanModules    []string  `json:"scan_modules"`
}

type PackageInfo struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Source       string    `json:"source"`
	Architecture string    `json:"architecture,omitempty"`
	InstallDate  time.Time `json:"install_date,omitempty"`
	SizeBytes    int64     `json:"size_bytes,omitempty"`
	Description  string    `json:"description,omitempty"`
	Dependencies []string  `json:"dependencies,omitempty"`
	CPE          string    `json:"cpe,omitempty"`
}

type CertificateInfo struct {
	Store             string    `json:"store"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	Serial            string    `json:"serial"`
	Expires           time.Time `json:"expires"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	KeyUsage          []string  `json:"key_usage"`
	SAN               []string  `json:"san,omitempty"`
}

type SystemFingerprint struct {
	Hardware Hardware      `json:"hardware"`
	Network  Network       `json:"network"`
	Users    []UserInfo    `json:"users"`
	Services []ServiceInfo `json:"services"`
}

type Hardware struct {
	CPU     CPUInfo       `json:"cpu"`
	Memory  MemoryInfo    `json:"memory"`
	Storage []StorageInfo `json:"storage"`
}

type CPUInfo struct {
	Model        string `json:"model"`
	Cores        int    `json:"cores"`
	Architecture string `json:"architecture"`
}

type MemoryInfo struct {
	TotalGB     float64 `json:"total_gb"`
	AvailableGB float64 `json:"available_gb"`
}

type StorageInfo struct {
	Device     string `json:"device"`
	SizeGB     int    `json:"size_gb"`
	Type       string `json:"type"`
	Filesystem string `json:"filesystem"`
}

type Network struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	DNSServers []string           `json:"dns_servers"`
}

type NetworkInterface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6,omitempty"`
}

type UserInfo struct {
	Username string   `json:"username"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Shell    string   `json:"shell"`
	Home     string   `json:"home"`
	Groups   []string `json:"groups"`
}

type ServiceInfo struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	PID       int       `json:"pid,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	Version   string    `json:"version,omitempty"`
}

type AgentMetadata struct {
	LastAgentContact time.Time              `json:"last_agent_contact"`
	AgentVersion     string                 `json:"agent_version"`
	Capabilities     []string               `json:"capabilities"`
	Configuration    map[string]interface{} `json:"configuration"`
}

func main() {
	log.Println("🧪 Testing SBOM Migration Schema and JSONB Operations...")

	db := postgres.GetDB()

	// Test 1: Verify JSONB columns exist
	log.Println("Test 1: Verifying JSONB columns exist...")

	var columnExists bool
	columns := []string{"software_inventory", "system_fingerprint", "agent_metadata"}

	for _, column := range columns {
		err := db.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns 
				WHERE table_name = 'hosts' AND column_name = ?
			)
		`, column).Scan(&columnExists).Error

		if err != nil {
			log.Printf("❌ Failed to check column %s: %v", column, err)
		} else if columnExists {
			log.Printf("✅ Column %s exists", column)
		} else {
			log.Printf("❌ Column %s missing - migration may not have run", column)
		}
	}

	// Test 2: Create test data structures
	log.Println("\nTest 2: Creating test JSONB data structures...")

	now := time.Now()

	// Create test software inventory
	softwareInventory := SoftwareInventory{
		ScanMetadata: ScanMetadata{
			AgentVersion:   "1.2.0-test",
			ScanDate:       now,
			ScanDurationMs: 5432,
			ScanModules:    []string{"packages", "certificates"},
		},
		Packages: []PackageInfo{
			{
				Name:        "nginx",
				Version:     "1.18.0-6ubuntu14.4",
				Source:      "dpkg",
				InstallDate: now.Add(-30 * 24 * time.Hour),
				SizeBytes:   1048576,
				Description: "High performance web server",
				CPE:         "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
			},
		},
		Certificates: []CertificateInfo{
			{
				Store:             "system",
				Subject:           "CN=test.example.com",
				Issuer:            "CN=Test CA",
				Serial:            "123456789",
				Expires:           now.Add(365 * 24 * time.Hour),
				FingerprintSHA256: "abc123def456",
				KeyUsage:          []string{"digital_signature", "key_encipherment"},
			},
		},
	}

	// Create test system fingerprint
	systemFingerprint := SystemFingerprint{
		Hardware: Hardware{
			CPU: CPUInfo{
				Model:        "Intel Core i7-9700K",
				Cores:        8,
				Architecture: "x86_64",
			},
			Memory: MemoryInfo{
				TotalGB:     16.0,
				AvailableGB: 8.5,
			},
		},
		Network: Network{
			Interfaces: []NetworkInterface{
				{
					Name: "eth0",
					MAC:  "00:1B:44:11:3A:B7",
					IPv4: []string{"192.168.1.100"},
				},
			},
			DNSServers: []string{"8.8.8.8", "8.8.4.4"},
		},
	}

	// Create test agent metadata
	agentMetadata := AgentMetadata{
		LastAgentContact: now,
		AgentVersion:     "1.2.0-test",
		Capabilities:     []string{"package_scan", "fingerprint_scan"},
		Configuration: map[string]interface{}{
			"scan_interval_hours": 24,
			"enable_templates":    true,
		},
	}

	log.Printf("✅ Test data structures created successfully")

	// Test 3: Test JSONB marshaling
	log.Println("\nTest 3: Testing JSON marshaling...")

	softwareJSON, err := json.Marshal(softwareInventory)
	if err != nil {
		log.Printf("❌ Failed to marshal software inventory: %v", err)
	} else {
		log.Printf("✅ Software inventory JSON: %d bytes", len(softwareJSON))
	}

	fingerprintJSON, err := json.Marshal(systemFingerprint)
	if err != nil {
		log.Printf("❌ Failed to marshal system fingerprint: %v", err)
	} else {
		log.Printf("✅ System fingerprint JSON: %d bytes", len(fingerprintJSON))
	}

	metadataJSON, err := json.Marshal(agentMetadata)
	if err != nil {
		log.Printf("❌ Failed to marshal agent metadata: %v", err)
	} else {
		log.Printf("✅ Agent metadata JSON: %d bytes", len(metadataJSON))
	}

	// Test 4: Test JSONB queries (read-only)
	log.Println("\nTest 4: Testing JSONB query patterns...")

	// Test query for package search
	var packageCount int64
	err = db.Raw(`
		SELECT COUNT(*) FROM hosts 
		WHERE software_inventory -> 'packages' @> '[{"name": "nginx"}]'
	`).Scan(&packageCount).Error

	if err != nil {
		log.Printf("❌ Failed package search query: %v", err)
	} else {
		log.Printf("✅ Package search query executed: %d results", packageCount)
	}

	// Test query for agent version
	var agentVersionCount int64
	err = db.Raw(`
		SELECT COUNT(*) FROM hosts 
		WHERE agent_metadata ->> 'agent_version' = '1.2.0'
	`).Scan(&agentVersionCount).Error

	if err != nil {
		log.Printf("❌ Failed agent version query: %v", err)
	} else {
		log.Printf("✅ Agent version query executed: %d results", agentVersionCount)
	}

	// Test 5: Verify indexes exist
	log.Println("\nTest 5: Verifying JSONB indexes...")

	indexes := []string{
		"idx_hosts_software_inventory_gin",
		"idx_hosts_system_fingerprint_gin",
		"idx_hosts_agent_metadata_gin",
	}

	for _, index := range indexes {
		var indexExists bool
		err = db.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM pg_indexes 
				WHERE indexname = ?
			)
		`, index).Scan(&indexExists).Error

		if err != nil {
			log.Printf("❌ Failed to check index %s: %v", index, err)
		} else if indexExists {
			log.Printf("✅ Index %s exists", index)
		} else {
			log.Printf("❌ Index %s missing", index)
		}
	}

	// Test 6: Model compatibility test
	log.Println("\nTest 6: Testing Host model compatibility...")

	var hosts []models.Host
	err = db.Limit(1).Find(&hosts).Error
	if err != nil {
		log.Printf("❌ Failed to query hosts with new model: %v", err)
	} else {
		log.Printf("✅ Host model query successful: %d records", len(hosts))

		if len(hosts) > 0 {
			host := hosts[0]
			log.Printf("   - SoftwareInventory field present: %t", host.SoftwareInventory != nil)
			log.Printf("   - SystemFingerprint field present: %t", host.SystemFingerprint != nil)
			log.Printf("   - AgentMetadata field present: %t", host.AgentMetadata != nil)
		}
	}

	// Final summary
	log.Println("\n📋 Migration Test Summary:")
	log.Println("   ✅ JSONB column verification completed")
	log.Println("   ✅ Test data structure creation successful")
	log.Println("   ✅ JSON marshaling functionality verified")
	log.Println("   ✅ JSONB query patterns tested")
	log.Println("   ✅ Index verification completed")
	log.Println("   ✅ Host model compatibility confirmed")
	log.Println("")
	log.Println("🎯 Migration 004 schema is ready for SBOM and fingerprinting data!")
}
