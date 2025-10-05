package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/logging"
	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	MAX_LOGS   = 1000 // Maximum number of logs to keep (focused on meaningful events)
	LOG_PREFIX = "logs"
)

// LogSubmissionRequest represents a request to submit a log entry
type LogSubmissionRequest struct {
	Service      string                 `json:"service"`
	Subcomponent string                 `json:"subcomponent,omitempty"`
	Level        string                 `json:"level"`
	Message      string                 `json:"message"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// LogRetrievalRequest represents a request to retrieve logs
type LogRetrievalRequest struct {
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
	Service   string `json:"service,omitempty"`
	Level     string `json:"level,omitempty"`
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`
	Search    string `json:"search,omitempty"`
}

// LogRetrievalResponse represents the response for log retrieval
type LogRetrievalResponse struct {
	Logs  []logging.LogEntry `json:"logs"`
	Total int                `json:"total"`
	Limit int                `json:"limit"`
	Offset int               `json:"offset"`
}

// LogStatsResponse represents statistics about logs
type LogStatsResponse struct {
	TotalLogs    int                    `json:"total_logs"`
	ServiceStats map[string]int         `json:"service_stats"`
	LevelStats   map[string]int         `json:"level_stats"`
	RecentLogs   []logging.LogEntry     `json:"recent_logs"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// LogUpdateRequest represents a request to update a log entry
type LogUpdateRequest struct {
	Message  string                 `json:"message,omitempty"`
	Level    string                 `json:"level,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// LogSubmissionHandler handles log submission
func LogSubmissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LogSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Service == "" || req.Level == "" || req.Message == "" {
		http.Error(w, "Missing required fields: service, level, message", http.StatusBadRequest)
		return
	}

	// Validate log level
	if !logging.IsValidLogLevel(req.Level) {
		http.Error(w, fmt.Sprintf("Invalid log level: %s", req.Level), http.StatusBadRequest)
		return
	}

	// Create log entry
	entry := logging.LogEntry{
		ID:           generateLogID(),
		Timestamp:    time.Now(),
		Service:      req.Service,
		Subcomponent: req.Subcomponent,
		Level:        logging.GetLogLevelFromString(req.Level),
		Message:      req.Message,
		Metadata:     req.Metadata,
		Context:      req.Context,
	}

	// Store in Valkey
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Valkey: %v", err), http.StatusInternalServerError)
		return
	}
	defer kvStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Serialize and store
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize log entry: %v", err), http.StatusInternalServerError)
		return
	}

	key := fmt.Sprintf("%s:%s", LOG_PREFIX, entry.ID)
	if err := kvStore.SetValue(ctx, key, string(entryJSON)); err != nil {
		http.Error(w, fmt.Sprintf("Failed to store log entry: %v", err), http.StatusInternalServerError)
		return
	}

	// Maintain log count and cleanup old logs (only occasionally to avoid performance impact)
	// Only run maintenance every 10th log entry to reduce overhead
	if time.Now().Unix()%10 == 0 {
		if err := maintainLogCount(ctx, kvStore); err != nil {
			// Log the error but don't fail the request
			fmt.Printf("Warning: Failed to maintain log count: %v\n", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"log_id":  entry.ID,
		"message": "Log entry stored successfully",
	})
}

// LogRetrievalHandler handles log retrieval
func LogRetrievalHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	service := r.URL.Query().Get("service")
	level := r.URL.Query().Get("level")
	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")
	search := r.URL.Query().Get("search")

	// Set defaults
	limit := 100
	offset := 0

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Connect to Valkey
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Valkey: %v", err), http.StatusInternalServerError)
		return
	}
	defer kvStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get all log keys
	keys, err := kvStore.ListKeys(ctx, LOG_PREFIX+":*")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list log keys: %v", err), http.StatusInternalServerError)
		return
	}

	// Limit the number of keys to process for performance
	maxKeysToProcess := 1000
	if len(keys) > maxKeysToProcess {
		keys = keys[:maxKeysToProcess]
	}

	// Retrieve and filter logs
	var logs []logging.LogEntry
	for _, key := range keys {
		value, err := kvStore.GetValue(ctx, key)
		if err != nil {
			continue // Skip failed retrievals
		}

		var entry logging.LogEntry
		if err := json.Unmarshal([]byte(value.Message.Value), &entry); err != nil {
			continue // Skip invalid entries
		}

		// Apply filters
		if service != "" && entry.Service != service {
			continue
		}
		if level != "" && string(entry.Level) != level {
			continue
		}
		if startTime != "" {
			if start, err := time.Parse(time.RFC3339, startTime); err == nil {
				if entry.Timestamp.Before(start) {
					continue
				}
			}
		}
		if endTime != "" {
			if end, err := time.Parse(time.RFC3339, endTime); err == nil {
				if entry.Timestamp.After(end) {
					continue
				}
			}
		}
		if search != "" {
			if !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(search)) &&
			   !strings.Contains(strings.ToLower(entry.Service), strings.ToLower(search)) {
				continue
			}
		}

		logs = append(logs, entry)
	}

	// Sort by timestamp (newest first)
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp.After(logs[j].Timestamp)
	})

	total := len(logs)

	// Apply pagination
	if offset >= len(logs) {
		logs = []logging.LogEntry{}
	} else {
		end := offset + limit
		if end > len(logs) {
			end = len(logs)
		}
		logs = logs[offset:end]
	}

	response := LogRetrievalResponse{
		Logs:   logs,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// LogStatsHandler handles log statistics
func LogStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Connect to Valkey
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Valkey: %v", err), http.StatusInternalServerError)
		return
	}
	defer kvStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get all log keys
	keys, err := kvStore.ListKeys(ctx, LOG_PREFIX+":*")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list log keys: %v", err), http.StatusInternalServerError)
		return
	}

	// Limit the number of keys to process for performance
	maxKeysToProcess := 1000
	if len(keys) > maxKeysToProcess {
		keys = keys[:maxKeysToProcess]
	}

	// Calculate statistics
	serviceStats := make(map[string]int)
	levelStats := make(map[string]int)
	var recentLogs []logging.LogEntry

	for _, key := range keys {
		value, err := kvStore.GetValue(ctx, key)
		if err != nil {
			continue
		}

		var entry logging.LogEntry
		if err := json.Unmarshal([]byte(value.Message.Value), &entry); err != nil {
			continue
		}

		// Count services
		serviceStats[entry.Service]++

		// Count levels
		levelStats[string(entry.Level)]++

		// Collect recent logs (last 10)
		if len(recentLogs) < 10 {
			recentLogs = append(recentLogs, entry)
		}
	}

	// Sort recent logs by timestamp
	sort.Slice(recentLogs, func(i, j int) bool {
		return recentLogs[i].Timestamp.After(recentLogs[j].Timestamp)
	})

	response := LogStatsResponse{
		TotalLogs:    len(keys),
		ServiceStats: serviceStats,
		LevelStats:   levelStats,
		RecentLogs:   recentLogs,
		Metadata: map[string]interface{}{
			"max_logs":        MAX_LOGS,
			"keys_processed":  len(keys),
			"generated_at":    time.Now().Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// LogUpdateHandler handles log updates
func LogUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract log ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "Log ID required", http.StatusBadRequest)
		return
	}
	logID := pathParts[len(pathParts)-1]

	var req LogUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Connect to Valkey
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Valkey: %v", err), http.StatusInternalServerError)
		return
	}
	defer kvStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get existing log entry
	key := fmt.Sprintf("%s:%s", LOG_PREFIX, logID)
	value, err := kvStore.GetValue(ctx, key)
	if err != nil {
		http.Error(w, "Log entry not found", http.StatusNotFound)
		return
	}

	var entry logging.LogEntry
	if err := json.Unmarshal([]byte(value.Message.Value), &entry); err != nil {
		http.Error(w, "Invalid log entry format", http.StatusInternalServerError)
		return
	}

	// Update fields if provided
	if req.Message != "" {
		entry.Message = req.Message
	}
	if req.Level != "" && logging.IsValidLogLevel(req.Level) {
		entry.Level = logging.GetLogLevelFromString(req.Level)
	}
	if req.Metadata != nil {
		entry.Metadata = req.Metadata
	}
	if req.Context != nil {
		entry.Context = req.Context
	}

	// Store updated entry
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize log entry: %v", err), http.StatusInternalServerError)
		return
	}

	if err := kvStore.SetValue(ctx, key, string(entryJSON)); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update log entry: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Log entry updated successfully",
		"log_id":  logID,
	})
}

// LogDeleteHandler handles log deletion
func LogDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract log ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "Log ID required", http.StatusBadRequest)
		return
	}
	logID := pathParts[len(pathParts)-1]

	// Connect to Valkey
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Valkey: %v", err), http.StatusInternalServerError)
		return
	}
	defer kvStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete log entry
	key := fmt.Sprintf("%s:%s", LOG_PREFIX, logID)
	if err := kvStore.DeleteValue(ctx, key); err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete log entry: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Log entry deleted successfully",
		"log_id":  logID,
	})
}

// LogClearHandler handles clearing all logs
func LogClearHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Connect to Valkey
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Valkey: %v", err), http.StatusInternalServerError)
		return
	}
	defer kvStore.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get all log keys
	keys, err := kvStore.ListKeys(ctx, LOG_PREFIX+":*")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list log keys: %v", err), http.StatusInternalServerError)
		return
	}

	// Delete all log keys
	deletedCount := 0
	for _, key := range keys {
		if err := kvStore.DeleteValue(ctx, key); err == nil {
			deletedCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "Logs cleared successfully",
		"deleted_count": deletedCount,
	})
}

// Helper functions

func generateLogID() string {
	return fmt.Sprintf("log_%s_%d", time.Now().Format("20060102_150405"), time.Now().UnixNano()%1000000)
}

// maintainLogCount ensures we don't exceed MAX_LOGS
func maintainLogCount(ctx context.Context, kvStore store.KVStore) error {
	// Use a longer timeout for log maintenance
	maintenanceCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Get all log keys
	keys, err := kvStore.ListKeys(maintenanceCtx, LOG_PREFIX+":*")
	if err != nil {
		return err
	}

	if len(keys) <= MAX_LOGS {
		return nil // No cleanup needed
	}

	// Sort keys by timestamp (oldest first) - assuming log ID contains timestamp
	sort.Strings(keys)

	// Delete oldest logs
	logsToDelete := len(keys) - MAX_LOGS
	for i := 0; i < logsToDelete; i++ {
		if err := kvStore.DeleteValue(maintenanceCtx, keys[i]); err != nil {
			// Continue with other deletions even if one fails
			continue
		}
	}

	return nil
}
