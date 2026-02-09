package logging

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"gorm.io/gorm"
)

// EventPersistence handles PostgreSQL persistence for events
type EventPersistence struct {
	db            *gorm.DB
	buffer        []models.Event
	mutex         sync.Mutex
	stopChan      chan bool
	flushInterval time.Duration
	bufferSize    int
}

// NewEventPersistence creates a new EventPersistence instance
func NewEventPersistence(flushInterval time.Duration, bufferSize int) *EventPersistence {
	ep := &EventPersistence{
		db:            postgres.GetDB(),
		buffer:        make([]models.Event, 0, bufferSize),
		stopChan:      make(chan bool),
		flushInterval: flushInterval,
		bufferSize:    bufferSize,
	}

	// Start flush routine
	go ep.flushRoutine()

	return ep
}

// StoreEvent buffers an event for batch insertion
func (ep *EventPersistence) StoreEvent(entry LogEntry) error {
	if ep.db == nil {
		return fmt.Errorf("database connection not available")
	}

	// Convert LogEntry to models.Event
	event := ep.convertToEvent(entry)

	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	// Add to buffer
	ep.buffer = append(ep.buffer, event)

	// Flush if buffer is full
	if len(ep.buffer) >= ep.bufferSize {
		return ep.flushBufferUnsafe()
	}

	return nil
}

// convertToEvent converts a LogEntry to a models.Event
func (ep *EventPersistence) convertToEvent(entry LogEntry) models.Event {
	// Generate event_id if not provided
	eventID := entry.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("evt_%s_%d", time.Now().Format("20060102_150405"), time.Now().UnixNano()%1000000)
	}

	// Convert metadata to JSONB
	metadata := models.JSONB{}
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			metadata[k] = v
		}
	}

	// Add context to metadata if present
	if entry.Context != nil {
		if len(metadata) == 0 {
			metadata = models.JSONB{}
		}
		metadata["context"] = entry.Context
	}

	// Determine severity from level if not provided
	severity := entry.Severity
	if severity == "" {
		severity = ep.levelToSeverity(entry.Level)
	}

	// Use title or message as title
	title := entry.Title
	if title == "" {
		title = entry.Message
		if len(title) > 255 {
			title = title[:252] + "..."
		}
	}

	// Use description or empty
	description := entry.Description
	if description == "" && entry.Title != "" {
		// If we have a title, use the full message as description
		description = entry.Message
	}

	return models.Event{
		EventID:      eventID,
		Timestamp:    entry.Timestamp,
		Service:      entry.Service,
		Subcomponent: entry.Subcomponent,
		EventType:    entry.EventType,
		Severity:     severity,
		Title:        title,
		Description:  description,
		Metadata:     metadata,
		EntityType:   entry.EntityType,
		EntityID:     entry.EntityID,
		CreatedAt:    time.Now(),
	}
}

// levelToSeverity converts LogLevel to severity string
func (ep *EventPersistence) levelToSeverity(level LogLevel) string {
	switch level {
	case LogLevelError:
		return models.SeverityError
	case LogLevelWarn:
		return models.SeverityWarning
	case LogLevelInfo:
		return models.SeverityInfo
	case LogLevelDebug:
		return models.SeverityInfo
	default:
		return models.SeverityInfo
	}
}

// FlushEvents flushes all buffered events to PostgreSQL
func (ep *EventPersistence) FlushEvents() error {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	return ep.flushBufferUnsafe()
}

// flushBufferUnsafe flushes the buffer without acquiring the mutex
// Caller must hold the mutex
func (ep *EventPersistence) flushBufferUnsafe() error {
	if len(ep.buffer) == 0 {
		return nil
	}

	if ep.db == nil {
		return fmt.Errorf("database connection not available")
	}

	// Batch insert events
	err := ep.db.CreateInBatches(ep.buffer, len(ep.buffer)).Error
	if err != nil {
		slog.Error("Failed to flush events to PostgreSQL", "error", err)
		// Don't return error - we don't want to stop the logging client
		// Events will be retried on next flush
		return err
	}

	slog.Debug("Flushed events to PostgreSQL", "count", len(ep.buffer))

	// Clear buffer
	ep.buffer = ep.buffer[:0]

	return nil
}

// flushRoutine periodically flushes the buffer
func (ep *EventPersistence) flushRoutine() {
	ticker := time.NewTicker(ep.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ep.mutex.Lock()
			if len(ep.buffer) > 0 {
				err := ep.flushBufferUnsafe()
				if err != nil {
					slog.Error("Periodic flush failed", "error", err)
				}
			}
			ep.mutex.Unlock()
		case <-ep.stopChan:
			// Final flush before stopping
			ep.mutex.Lock()
			if len(ep.buffer) > 0 {
				ep.flushBufferUnsafe()
			}
			ep.mutex.Unlock()
			return
		}
	}
}

// Close stops the flush routine and flushes remaining events
func (ep *EventPersistence) Close() error {
	close(ep.stopChan)

	// Give it a moment to flush
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Helper function to convert LogEntry to JSON for debugging
func (ep *EventPersistence) logEntryToJSON(entry LogEntry) string {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Sprintf("Error marshaling LogEntry: %v", err)
	}
	return string(data)
}
