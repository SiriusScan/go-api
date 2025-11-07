package events

import (
	"fmt"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"gorm.io/gorm"
)

// EventFilters represents filters for querying events
type EventFilters struct {
	Limit      int
	Offset     int
	Service    string
	Severity   string
	EventType  string
	StartTime  *time.Time
	EndTime    *time.Time
	EntityType string
	EntityID   string
}

// EventStats represents aggregated event statistics
type EventStats struct {
	TotalEvents  int                `json:"total_events"`
	BySeverity   map[string]int     `json:"by_severity"`
	ByService    map[string]int     `json:"by_service"`
	ByType       map[string]int     `json:"by_type"`
	RecentEvents []models.Event     `json:"recent_events"`
}

// GetEvents retrieves events from PostgreSQL with filters
func GetEvents(filters EventFilters) ([]models.Event, int, error) {
	db := postgres.GetDB()
	if db == nil {
		return nil, 0, fmt.Errorf("database connection not available")
	}

	// Build query with filters
	query := db.Model(&models.Event{})

	// Apply filters
	if filters.Service != "" {
		query = query.Where("service = ?", filters.Service)
	}
	if filters.Severity != "" {
		query = query.Where("severity = ?", filters.Severity)
	}
	if filters.EventType != "" {
		query = query.Where("event_type = ?", filters.EventType)
	}
	if filters.EntityType != "" {
		query = query.Where("entity_type = ?", filters.EntityType)
	}
	if filters.EntityID != "" {
		query = query.Where("entity_id = ?", filters.EntityID)
	}
	if filters.StartTime != nil {
		query = query.Where("timestamp >= ?", filters.StartTime)
	}
	if filters.EndTime != nil {
		query = query.Where("timestamp <= ?", filters.EndTime)
	}

	// Get total count before pagination
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count events: %w", err)
	}

	// Apply pagination and ordering
	if filters.Limit <= 0 {
		filters.Limit = 50
	}
	if filters.Limit > 500 {
		filters.Limit = 500
	}
	if filters.Offset < 0 {
		filters.Offset = 0
	}

	var events []models.Event
	err := query.
		Order("timestamp DESC").
		Limit(filters.Limit).
		Offset(filters.Offset).
		Find(&events).Error

	if err != nil {
		return nil, 0, fmt.Errorf("failed to query events: %w", err)
	}

	return events, int(total), nil
}

// GetEvent retrieves a single event by event_id
func GetEvent(eventID string) (*models.Event, error) {
	db := postgres.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	var event models.Event
	err := db.Where("event_id = ?", eventID).First(&event).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("event not found: %s", eventID)
		}
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	return &event, nil
}

// GetEventStatistics returns aggregated event statistics
func GetEventStatistics() (*EventStats, error) {
	db := postgres.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	stats := &EventStats{
		BySeverity: make(map[string]int),
		ByService:  make(map[string]int),
		ByType:     make(map[string]int),
	}

	// Get total count
	var total int64
	if err := db.Model(&models.Event{}).Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count events: %w", err)
	}
	stats.TotalEvents = int(total)

	// Group by severity
	var severityCounts []struct {
		Severity string
		Count    int
	}
	if err := db.Model(&models.Event{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityCounts).Error; err != nil {
		return nil, fmt.Errorf("failed to count by severity: %w", err)
	}
	for _, item := range severityCounts {
		stats.BySeverity[item.Severity] = item.Count
	}

	// Group by service
	var serviceCounts []struct {
		Service string
		Count   int
	}
	if err := db.Model(&models.Event{}).
		Select("service, COUNT(*) as count").
		Group("service").
		Scan(&serviceCounts).Error; err != nil {
		return nil, fmt.Errorf("failed to count by service: %w", err)
	}
	for _, item := range serviceCounts {
		stats.ByService[item.Service] = item.Count
	}

	// Group by event type
	var typeCounts []struct {
		EventType string
		Count     int
	}
	if err := db.Model(&models.Event{}).
		Select("event_type, COUNT(*) as count").
		Group("event_type").
		Scan(&typeCounts).Error; err != nil {
		return nil, fmt.Errorf("failed to count by type: %w", err)
	}
	for _, item := range typeCounts {
		stats.ByType[item.EventType] = item.Count
	}

	// Get recent events (last 10)
	var recentEvents []models.Event
	if err := db.Model(&models.Event{}).
		Order("timestamp DESC").
		Limit(10).
		Find(&recentEvents).Error; err != nil {
		return nil, fmt.Errorf("failed to get recent events: %w", err)
	}
	stats.RecentEvents = recentEvents

	return stats, nil
}

// DeleteOldEvents deletes events older than the specified duration
// This can be used for data retention policies
func DeleteOldEvents(olderThan time.Duration) (int64, error) {
	db := postgres.GetDB()
	if db == nil {
		return 0, fmt.Errorf("database connection not available")
	}

	cutoffTime := time.Now().Add(-olderThan)
	result := db.Where("timestamp < ?", cutoffTime).Delete(&models.Event{})
	if result.Error != nil {
		return 0, fmt.Errorf("failed to delete old events: %w", result.Error)
	}

	return result.RowsAffected, nil
}

// GetEventsByEntity retrieves all events for a specific entity
func GetEventsByEntity(entityType, entityID string, limit int) ([]models.Event, error) {
	db := postgres.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	if limit <= 0 {
		limit = 50
	}

	var events []models.Event
	err := db.Where("entity_type = ? AND entity_id = ?", entityType, entityID).
		Order("timestamp DESC").
		Limit(limit).
		Find(&events).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get events by entity: %w", err)
	}

	return events, nil
}

// GetRecentEventsBySeverity retrieves recent events filtered by severity
func GetRecentEventsBySeverity(severity string, limit int) ([]models.Event, error) {
	db := postgres.GetDB()
	if db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	if limit <= 0 {
		limit = 50
	}

	var events []models.Event
	err := db.Where("severity = ?", severity).
		Order("timestamp DESC").
		Limit(limit).
		Find(&events).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get events by severity: %w", err)
	}

	return events, nil
}

