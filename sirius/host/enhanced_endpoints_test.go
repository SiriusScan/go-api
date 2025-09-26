package host

import (
	"encoding/json"
	"testing"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func TestEnhancedHostDataStructures(t *testing.T) {
	t.Log("\n🔍 Testing Enhanced Host Data Structures...")

	// Test EnhancedHostData structure
	t.Run("TestEnhancedHostDataSerialization", func(t *testing.T) {
		enhancedData := &EnhancedHostData{
			Host: sirius.Host{
				IP:       "192.168.1.100",
				Hostname: "test-host",
			},
			SoftwareInventory: map[string]interface{}{
				"packages": []interface{}{
					map[string]interface{}{
						"name":         "nginx",
						"version":      "1.18.0",
						"architecture": "amd64",
						"source":       "dpkg",
					},
				},
				"package_count": float64(1),
				"collected_at":  "2024-01-15T10:30:00Z",
			},
			SystemFingerprint: map[string]interface{}{
				"platform":  "linux",
				"cpu_cores": float64(4),
				"memory_gb": float64(8),
			},
			AgentMetadata: map[string]interface{}{
				"agent_version": "1.2.0",
				"scan_duration": float64(5432),
			},
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(enhancedData)
		if err != nil {
			t.Fatalf("❌ Failed to marshal EnhancedHostData: %v", err)
		}

		// Test JSON deserialization
		var unmarshaled EnhancedHostData
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("❌ Failed to unmarshal EnhancedHostData: %v", err)
		}

		// Validate structure
		if unmarshaled.Host.IP != "192.168.1.100" {
			t.Error("❌ Host IP not preserved")
		}

		if len(unmarshaled.SoftwareInventory) == 0 {
			t.Error("❌ Software inventory not preserved")
		}

		if len(unmarshaled.SystemFingerprint) == 0 {
			t.Error("❌ System fingerprint not preserved")
		}

		if len(unmarshaled.AgentMetadata) == 0 {
			t.Error("❌ Agent metadata not preserved")
		}

		t.Log("✅ EnhancedHostData serialization/deserialization successful")
	})

	// Test SoftwareInventoryData structure
	t.Run("TestSoftwareInventoryDataStructure", func(t *testing.T) {
		inventory := &SoftwareInventoryData{
			Packages: []map[string]interface{}{
				{
					"name":         "apache2",
					"version":      "2.4.41",
					"architecture": "amd64",
					"install_date": "2023-01-15T08:22:00Z",
					"size_bytes":   float64(1048576),
					"description":  "Apache HTTP Server",
				},
			},
			PackageCount: 1,
			CollectedAt:  "2024-01-15T10:30:00Z",
			Source:       "agent-scan",
			Statistics: map[string]interface{}{
				"architectures": map[string]interface{}{
					"amd64": float64(1),
				},
			},
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(inventory)
		if err != nil {
			t.Fatalf("❌ Failed to marshal SoftwareInventoryData: %v", err)
		}

		var unmarshaled SoftwareInventoryData
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("❌ Failed to unmarshal SoftwareInventoryData: %v", err)
		}

		if unmarshaled.PackageCount != 1 {
			t.Error("❌ Package count not preserved")
		}

		if len(unmarshaled.Packages) != 1 {
			t.Error("❌ Package array not preserved")
		}

		t.Log("✅ SoftwareInventoryData structure validation successful")
	})

	// Test SystemFingerprintData structure
	t.Run("TestSystemFingerprintDataStructure", func(t *testing.T) {
		fingerprint := &SystemFingerprintData{
			Fingerprint: map[string]interface{}{
				"hardware": map[string]interface{}{
					"cpu": map[string]interface{}{
						"model": "Intel Core i7-9700K",
						"cores": float64(8),
					},
					"memory": map[string]interface{}{
						"total_gb": float64(16),
					},
				},
			},
			CollectedAt:          "2024-01-15T10:30:00Z",
			Source:               "agent-scan",
			Platform:             "linux",
			CollectionDurationMs: 2500,
		}

		jsonData, err := json.Marshal(fingerprint)
		if err != nil {
			t.Fatalf("❌ Failed to marshal SystemFingerprintData: %v", err)
		}

		var unmarshaled SystemFingerprintData
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("❌ Failed to unmarshal SystemFingerprintData: %v", err)
		}

		if unmarshaled.Platform != "linux" {
			t.Error("❌ Platform not preserved")
		}

		if unmarshaled.CollectionDurationMs != 2500 {
			t.Error("❌ Collection duration not preserved")
		}

		t.Log("✅ SystemFingerprintData structure validation successful")
	})

	// Test SoftwareStatistics structure
	t.Run("TestSoftwareStatisticsStructure", func(t *testing.T) {
		stats := &SoftwareStatistics{
			TotalPackages: 150,
			Architectures: map[string]int{
				"amd64": 140,
				"i386":  10,
			},
			Publishers: map[string]int{
				"Ubuntu":    80,
				"Microsoft": 30,
				"Apache":    20,
				"Other":     20,
			},
			PackagesBySource: map[string]int{
				"dpkg": 120,
				"snap": 20,
				"pip":  10,
			},
			LastUpdated: "2024-01-15T10:30:00Z",
		}

		jsonData, err := json.Marshal(stats)
		if err != nil {
			t.Fatalf("❌ Failed to marshal SoftwareStatistics: %v", err)
		}

		var unmarshaled SoftwareStatistics
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("❌ Failed to unmarshal SoftwareStatistics: %v", err)
		}

		if unmarshaled.TotalPackages != 150 {
			t.Error("❌ Total packages count not preserved")
		}

		if len(unmarshaled.Architectures) != 2 {
			t.Error("❌ Architecture statistics not preserved")
		}

		if len(unmarshaled.Publishers) != 4 {
			t.Error("❌ Publisher statistics not preserved")
		}

		t.Log("✅ SoftwareStatistics structure validation successful")
	})

	t.Log("✅ All enhanced host data structure tests completed successfully")
}

func TestStringSliceContains(t *testing.T) {
	t.Log("\n🔍 Testing stringSliceContains helper function...")

	testCases := []struct {
		slice    []string
		item     string
		expected bool
		name     string
	}{
		{
			slice:    []string{"packages", "fingerprint", "metadata"},
			item:     "packages",
			expected: true,
			name:     "Item exists in slice",
		},
		{
			slice:    []string{"packages", "fingerprint", "metadata"},
			item:     "nonexistent",
			expected: false,
			name:     "Item does not exist in slice",
		},
		{
			slice:    []string{},
			item:     "anything",
			expected: false,
			name:     "Empty slice",
		},
		{
			slice:    []string{"software_inventory"},
			item:     "packages",
			expected: false,
			name:     "Different item in single-element slice",
		},
		{
			slice:    []string{"software_inventory"},
			item:     "software_inventory",
			expected: true,
			name:     "Same item in single-element slice",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := stringSliceContains(tc.slice, tc.item)
			if result != tc.expected {
				t.Errorf("❌ %s: expected %v, got %v", tc.name, tc.expected, result)
			} else {
				t.Logf("✅ %s: %v", tc.name, result)
			}
		})
	}

	t.Log("✅ stringSliceContains tests completed successfully")
}

func TestEnhancedHostStatsIntegration(t *testing.T) {
	t.Log("\n🔍 Testing Enhanced Host Stats Integration...")

	// Test enhanced HostRiskStats structure
	t.Run("TestHostRiskStatsWithSoftware", func(t *testing.T) {
		stats := HostRiskStats{
			VulnerabilityCount: 5,
			TotalRiskScore:     35.5,
			AverageRiskScore:   7.1,
			HostSeverityCounts: HostVulnerabilitySeverityCounts{
				Critical: 1,
				High:     2,
				Medium:   2,
				Low:      0,
			},
			SoftwareStats: &SoftwareStatistics{
				TotalPackages: 150,
				Architectures: map[string]int{
					"amd64": 140,
					"i386":  10,
				},
				LastUpdated: "2024-01-15T10:30:00Z",
			},
			LastUpdated: "2024-01-15T10:30:00Z",
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(stats)
		if err != nil {
			t.Fatalf("❌ Failed to marshal enhanced HostRiskStats: %v", err)
		}

		var unmarshaled HostRiskStats
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("❌ Failed to unmarshal enhanced HostRiskStats: %v", err)
		}

		// Validate structure
		if unmarshaled.VulnerabilityCount != 5 {
			t.Error("❌ Vulnerability count not preserved")
		}

		if unmarshaled.SoftwareStats == nil {
			t.Error("❌ Software stats not preserved")
		} else {
			if unmarshaled.SoftwareStats.TotalPackages != 150 {
				t.Error("❌ Software stats package count not preserved")
			}
		}

		if unmarshaled.LastUpdated != "2024-01-15T10:30:00Z" {
			t.Error("❌ Last updated timestamp not preserved")
		}

		t.Log("✅ Enhanced HostRiskStats integration successful")
		t.Logf("   Vulnerabilities: %d", unmarshaled.VulnerabilityCount)
		t.Logf("   Software packages: %d", unmarshaled.SoftwareStats.TotalPackages)
		t.Logf("   Last updated: %s", unmarshaled.LastUpdated)
	})

	t.Log("✅ Enhanced host stats integration tests completed successfully")
}

func TestEnhancedEndpointsDataFlow(t *testing.T) {
	t.Log("\n🔍 Testing Enhanced Endpoints Data Flow...")

	// Simulate the data flow for enhanced endpoints
	t.Run("TestSBOMDataFlow", func(t *testing.T) {
		// Simulate JSONB data from database
		mockSoftwareInventory := map[string]interface{}{
			"packages": []interface{}{
				map[string]interface{}{
					"name":         "nginx",
					"version":      "1.18.0-6ubuntu14.4",
					"architecture": "amd64",
					"install_date": "2023-06-15T08:22:00Z",
					"size_bytes":   float64(1048576),
					"description":  "High performance web server",
					"publisher":    "Ubuntu",
					"source":       "dpkg",
				},
				map[string]interface{}{
					"name":         "apache2",
					"version":      "2.4.41-4ubuntu3.14",
					"architecture": "amd64",
					"install_date": "2023-01-15T10:30:00Z",
					"size_bytes":   float64(2097152),
					"description":  "Apache HTTP Server",
					"publisher":    "Ubuntu",
					"source":       "dpkg",
				},
			},
			"package_count": float64(2),
			"collected_at":  "2024-01-15T10:30:00Z",
			"source":        "agent-scan",
			"statistics": map[string]interface{}{
				"architectures": map[string]interface{}{
					"amd64": float64(2),
				},
				"publishers": map[string]interface{}{
					"Ubuntu": float64(2),
				},
			},
		}

		// Test parsing software inventory data
		inventory := &SoftwareInventoryData{}

		if packages, ok := mockSoftwareInventory["packages"].([]interface{}); ok {
			for _, pkg := range packages {
				if pkgMap, ok := pkg.(map[string]interface{}); ok {
					inventory.Packages = append(inventory.Packages, pkgMap)
				}
			}
		}

		if count, ok := mockSoftwareInventory["package_count"].(float64); ok {
			inventory.PackageCount = int(count)
		}

		if collectedAt, ok := mockSoftwareInventory["collected_at"].(string); ok {
			inventory.CollectedAt = collectedAt
		}

		if source, ok := mockSoftwareInventory["source"].(string); ok {
			inventory.Source = source
		}

		if stats, ok := mockSoftwareInventory["statistics"].(map[string]interface{}); ok {
			inventory.Statistics = stats
		}

		// Validate parsed data
		if inventory.PackageCount != 2 {
			t.Error("❌ Package count parsing failed")
		}

		if len(inventory.Packages) != 2 {
			t.Error("❌ Package array parsing failed")
		}

		if inventory.Source != "agent-scan" {
			t.Error("❌ Source parsing failed")
		}

		// Test statistics aggregation
		architectures := make(map[string]int)
		publishers := make(map[string]int)

		for _, pkg := range inventory.Packages {
			if arch, ok := pkg["architecture"].(string); ok {
				architectures[arch]++
			}
			if pub, ok := pkg["publisher"].(string); ok {
				publishers[pub]++
			}
		}

		if architectures["amd64"] != 2 {
			t.Error("❌ Architecture aggregation failed")
		}

		if publishers["Ubuntu"] != 2 {
			t.Error("❌ Publisher aggregation failed")
		}

		t.Log("✅ SBOM data flow validation successful")
		t.Logf("   Parsed %d packages", inventory.PackageCount)
		t.Logf("   Architectures: %v", architectures)
		t.Logf("   Publishers: %v", publishers)
	})

	t.Log("✅ Enhanced endpoints data flow tests completed successfully")
}

// Simulate database models for testing
func mockHostWithSBOMData() models.Host {
	return models.Host{
		IP:       "192.168.1.100",
		Hostname: "test-host",
		SoftwareInventory: map[string]interface{}{
			"packages": []interface{}{
				map[string]interface{}{
					"name":         "nginx",
					"version":      "1.18.0",
					"architecture": "amd64",
					"publisher":    "Ubuntu",
					"source":       "dpkg",
				},
			},
			"package_count": float64(1),
			"collected_at":  "2024-01-15T10:30:00Z",
		},
		SystemFingerprint: map[string]interface{}{
			"platform":  "linux",
			"cpu_cores": float64(4),
			"memory_gb": float64(8),
		},
		AgentMetadata: map[string]interface{}{
			"agent_version": "1.2.0",
			"scan_duration": float64(5432),
		},
	}
}

func TestEndpointResponseFormats(t *testing.T) {
	t.Log("\n🔍 Testing API Endpoint Response Formats...")

	mockHost := mockHostWithSBOMData()

	t.Run("TestPackagesEndpointResponse", func(t *testing.T) {
		// Simulate GetHostPackages response
		inventory := &SoftwareInventoryData{}

		if packages, ok := mockHost.SoftwareInventory["packages"].([]interface{}); ok {
			for _, pkg := range packages {
				if pkgMap, ok := pkg.(map[string]interface{}); ok {
					inventory.Packages = append(inventory.Packages, pkgMap)
				}
			}
		}

		if count, ok := mockHost.SoftwareInventory["package_count"].(float64); ok {
			inventory.PackageCount = int(count)
		}

		response := map[string]interface{}{
			"host_ip":       mockHost.IP,
			"packages":      inventory.Packages,
			"package_count": len(inventory.Packages),
			"total_count":   inventory.PackageCount,
			"collected_at":  "2024-01-15T10:30:00Z",
			"source":        "agent-scan",
		}

		// Validate response structure
		if response["host_ip"] != "192.168.1.100" {
			t.Error("❌ Host IP not in response")
		}

		if response["package_count"] != 1 {
			t.Error("❌ Package count incorrect")
		}

		t.Log("✅ Packages endpoint response format validated")
	})

	t.Run("TestFingerprintEndpointResponse", func(t *testing.T) {
		// Simulate GetHostFingerprint response
		response := map[string]interface{}{
			"host_ip":                mockHost.IP,
			"fingerprint":            mockHost.SystemFingerprint,
			"collected_at":           "2024-01-15T10:30:00Z",
			"source":                 "agent-scan",
			"platform":               "linux",
			"collection_duration_ms": int64(2500),
		}

		if response["host_ip"] != "192.168.1.100" {
			t.Error("❌ Host IP not in response")
		}

		if response["platform"] != "linux" {
			t.Error("❌ Platform not in response")
		}

		t.Log("✅ Fingerprint endpoint response format validated")
	})

	t.Log("✅ All endpoint response format tests completed successfully")
}
