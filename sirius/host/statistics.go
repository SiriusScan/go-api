package host

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/store"
)

// HostVulnerabilityStats represents vulnerability statistics for a single host
type HostVulnerabilityStats struct {
	HostID               string                          `json:"hostId" gorm:"column:host_id"`
	HostIP               string                          `json:"hostIp" gorm:"column:host_ip"`
	Hostname             string                          `json:"hostname,omitempty" gorm:"column:hostname"`
	TotalVulnerabilities int                             `json:"totalVulnerabilities" gorm:"column:total_vulnerabilities"`
	WeightedRiskScore    float64                         `json:"weightedRiskScore" gorm:"column:weighted_risk_score"`
	SeverityCounts       HostVulnerabilitySeverityCounts `json:"severityCounts" gorm:"-"`
	LastUpdated          string                          `json:"lastUpdated" gorm:"column:last_updated"`
}

// VulnerableHostsResponse is the complete response structure for the API
type VulnerableHostsResponse struct {
	Hosts      []HostVulnerabilityStats `json:"hosts"`
	TotalHosts int                      `json:"totalHosts"`
	Cached     bool                     `json:"cached"`
	CachedAt   *string                  `json:"cachedAt,omitempty"`
	TTL        int                      `json:"ttl"`
}

const (
	// CacheKeyMostVulnerable is the base key for caching vulnerable hosts data
	CacheKeyMostVulnerable = "dashboard:most_vulnerable_hosts"
	// CacheTTL is the cache time-to-live in seconds (5 minutes)
	CacheTTL = 300
)

// GetMostVulnerableHosts returns hosts ranked by weighted vulnerability score
// The weighted risk score is the sum of all risk_scores for vulnerabilities on that host
func GetMostVulnerableHosts(limit int) ([]HostVulnerabilityStats, error) {
	db := postgres.GetDB()

	// Check if database is available
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// SQL query using optimized indexes
	// This query joins hosts, host_vulnerabilities, and vulnerabilities to calculate:
	// 1. Total count of distinct vulnerabilities per host
	// 2. Sum of risk scores (weighted risk score)
	// 3. Orders by weighted risk score descending, then by vulnerability count
	// Using h.ip as host_id since it's guaranteed to exist and is unique
	query := `
		SELECT 
			h.ip as host_id,
			h.ip as host_ip,
			h.hostname,
			COUNT(DISTINCT hv.vulnerability_id) as total_vulnerabilities,
			COALESCE(SUM(v.risk_score), 0) as weighted_risk_score,
			h.updated_at as last_updated
		FROM hosts h
		INNER JOIN host_vulnerabilities hv ON hv.host_id = h.id
		INNER JOIN vulnerabilities v ON v.id = hv.vulnerability_id
		GROUP BY h.id, h.ip, h.hostname, h.updated_at
		HAVING COUNT(DISTINCT hv.vulnerability_id) > 0
		ORDER BY weighted_risk_score DESC, total_vulnerabilities DESC
		LIMIT ?
	`

	var results []HostVulnerabilityStats
	err := db.Raw(query, limit).Scan(&results).Error
	if err != nil {
		fmt.Printf("GetMostVulnerableHosts: SQL Error: %v\n", err)
		fmt.Printf("GetMostVulnerableHosts: Query was: %s\n", query)
		return nil, fmt.Errorf("failed to query most vulnerable hosts: %w", err)
	}
	fmt.Printf("GetMostVulnerableHosts: Query executed successfully, got %d results\n", len(results))

	// Debug logging
	if len(results) == 0 {
		fmt.Printf("GetMostVulnerableHosts: Query returned 0 results (limit=%d)\n", limit)
	} else {
		fmt.Printf("GetMostVulnerableHosts: Query returned %d results\n", len(results))
	}

	// For each host, get severity counts using existing function
	for i := range results {
		counts, err := GetHostVulnerabilitySeverityCounts(results[i].HostIP)
		if err == nil {
			results[i].SeverityCounts = counts
		} else {
			// If severity counts fail, initialize with zeros to prevent null values
			results[i].SeverityCounts = HostVulnerabilitySeverityCounts{
				Critical:      0,
				High:          0,
				Medium:        0,
				Low:           0,
				Informational: 0,
			}
		}

		// Format timestamp for JSON
		if results[i].LastUpdated != "" {
			// Parse and reformat to RFC3339 if needed
			if t, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", results[i].LastUpdated); err == nil {
				results[i].LastUpdated = t.UTC().Format(time.RFC3339)
			}
		}
	}

	return results, nil
}

// GetMostVulnerableHostsCached returns cached data or calculates fresh statistics
// This function implements a caching layer with Valkey to reduce database load
func GetMostVulnerableHostsCached(limit int) (VulnerableHostsResponse, error) {
	ctx := context.Background()
	valkeyStore, err := store.NewValkeyStore()
	if err != nil {
		// If Valkey is unavailable, fall back to direct calculation
		fmt.Printf("GetMostVulnerableHostsCached: Valkey unavailable, calculating fresh\n")
		return calculateFreshStats(limit)
	}
	defer valkeyStore.Close()

	cacheKey := fmt.Sprintf("%s:%d", CacheKeyMostVulnerable, limit)

	// Try cache first
	cached, err := valkeyStore.GetValue(ctx, cacheKey)
	if err == nil {
		// Cache hit - unmarshal and return
		var response VulnerableHostsResponse
		if err := json.Unmarshal([]byte(cached.Message.Value), &response); err == nil {
			fmt.Printf("GetMostVulnerableHostsCached: Cache hit, returning %d hosts\n", len(response.Hosts))
			response.Cached = true
			return response, nil
		}
		fmt.Printf("GetMostVulnerableHostsCached: Cache unmarshal failed, recalculating\n")
		// If unmarshal fails, fall through to recalculate
	} else {
		fmt.Printf("GetMostVulnerableHostsCached: Cache miss, calculating fresh\n")
	}

	// Cache miss or stale - calculate fresh and cache
	return calculateAndCacheFreshStats(limit, valkeyStore, cacheKey)
}

// calculateFreshStats is a helper to calculate statistics without caching
func calculateFreshStats(limit int) (VulnerableHostsResponse, error) {
	hosts, err := GetMostVulnerableHosts(limit)
	if err != nil {
		return VulnerableHostsResponse{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	response := VulnerableHostsResponse{
		Hosts:      hosts,
		TotalHosts: len(hosts),
		Cached:     false,
		CachedAt:   &now,
		TTL:        CacheTTL,
	}

	return response, nil
}

// calculateAndCacheFreshStats calculates fresh statistics and stores in cache
func calculateAndCacheFreshStats(limit int, valkeyStore store.KVStore, cacheKey string) (VulnerableHostsResponse, error) {
	hosts, err := GetMostVulnerableHosts(limit)
	if err != nil {
		return VulnerableHostsResponse{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	response := VulnerableHostsResponse{
		Hosts:      hosts,
		TotalHosts: len(hosts),
		Cached:     false,
		CachedAt:   &now,
		TTL:        CacheTTL,
	}

	// Cache for next request (best effort - don't fail if caching fails)
	data, err := json.Marshal(response)
	if err == nil {
		_ = valkeyStore.SetValue(context.Background(), cacheKey, string(data))
	}

	return response, nil
}

// InvalidateMostVulnerableHostsCache clears all cached vulnerable hosts data
// This should be called when:
// - A scan completes and adds new vulnerabilities
// - Vulnerabilities are bulk updated or imported
// - Host vulnerability status changes significantly
func InvalidateMostVulnerableHostsCache() error {
	ctx := context.Background()
	valkeyStore, err := store.NewValkeyStore()
	if err != nil {
		// If Valkey is unavailable, this is not a critical error
		// Just return nil as cache invalidation is best-effort
		return nil
	}
	defer valkeyStore.Close()

	// Delete all cached variants (different limits)
	// Using pattern matching to find all keys with the base prefix
	keys, err := valkeyStore.ListKeys(ctx, CacheKeyMostVulnerable+":*")
	if err != nil {
		// Not critical if listing fails
		return nil
	}

	// Delete each cached key
	for _, key := range keys {
		_ = valkeyStore.DeleteValue(ctx, key)
	}

	return nil
}
