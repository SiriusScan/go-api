package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"
)

// LoggingClient provides a centralized way to send structured logs to the API
type LoggingClient struct {
	config           *LogConfig
	httpClient       *http.Client
	buffer           []LogEntry
	bufferMux        sync.Mutex
	stopChan         chan struct{}
	wg               sync.WaitGroup
	eventPersistence *EventPersistence
}

// NewLoggingClient creates a new LoggingClient instance with default configuration
func NewLoggingClient() *LoggingClient {
	config := DefaultLogConfig()

	// Override with environment variables if present
	if apiURL := os.Getenv("SIRIUS_LOG_API_URL"); apiURL != "" {
		config.APIBaseURL = apiURL
	}
	if timeout := os.Getenv("SIRIUS_LOG_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Timeout = d
		}
	}

	return NewLoggingClientWithConfig(config)
}

// NewLoggingClientWithConfig creates a new LoggingClient instance with custom configuration
func NewLoggingClientWithConfig(config *LogConfig) *LoggingClient {
	client := &LoggingClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		buffer:   make([]LogEntry, 0, config.BufferSize),
		stopChan: make(chan struct{}),
	}

	// Initialize PostgreSQL event persistence if enabled
	if config.EnablePostgresEvents {
		client.eventPersistence = NewEventPersistence(config.FlushInterval, config.BufferSize)
	}

	// Start background flush routine if async is enabled
	if config.Async {
		client.wg.Add(1)
		go client.flushRoutine()
	}

	return client
}

// Log sends a generic log entry to the API
func (lc *LoggingClient) Log(service, subcomponent string, level LogLevel, message string, metadata map[string]interface{}, context map[string]interface{}) {
	entry := LogEntry{
		ID:           lc.generateID(),
		Timestamp:    time.Now(),
		Service:      service,
		Subcomponent: subcomponent,
		Level:        level,
		Message:      message,
		Metadata:     metadata,
		Context:      context,
	}

	if lc.config.Async {
		lc.bufferLog(entry)
	} else {
		lc.submitLog(entry)
	}
}

// LogBusinessEvent logs a structured business event
func (lc *LoggingClient) LogBusinessEvent(service, subcomponent string, event BusinessEvent, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add business event data to metadata
	metadata["business_event"] = event

	context := map[string]interface{}{
		"type": "business_event",
	}

	lc.Log(service, subcomponent, LogLevelInfo, fmt.Sprintf("Business event: %s", event.EventType), metadata, context)
}

// LogPerformanceMetric logs a performance metric
func (lc *LoggingClient) LogPerformanceMetric(service, subcomponent string, metric PerformanceMetric, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add performance data to metadata
	metadata["performance"] = metric

	context := map[string]interface{}{
		"type": "performance_metric",
	}

	lc.Log(service, subcomponent, LogLevelInfo, fmt.Sprintf("Performance metric: %v", metric.Duration), metadata, context)
}

// LogError logs an error with detailed information
func (lc *LoggingClient) LogError(service, subcomponent string, err error, details ErrorDetails, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Add error details to metadata
	metadata["error_details"] = details

	context := map[string]interface{}{
		"type": "error",
	}

	lc.Log(service, subcomponent, LogLevelError, err.Error(), metadata, context)
}

// LogScanEvent logs a scan-related event (convenience method for App Scanner)
func (lc *LoggingClient) LogScanEvent(scanID, eventType, message string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["scan_id"] = scanID
	metadata["event_type"] = eventType

	event := BusinessEvent{
		EventType:  eventType,
		EntityID:   scanID,
		EntityType: "scan",
		Action:     eventType,
		Metadata:   metadata,
	}

	lc.LogBusinessEvent("sirius-scanner", "scan-manager", event, metadata)
}

// LogScanError logs a scan-related error (convenience method for App Scanner)
func (lc *LoggingClient) LogScanError(scanID, target, errorCode, message string, err error) {
	metadata := map[string]interface{}{
		"scan_id":    scanID,
		"target":     target,
		"error_code": errorCode,
	}

	details := ErrorDetails{
		ErrorCode:    errorCode,
		ErrorMessage: message,
		Source:       "scan-manager",
		Metadata:     metadata,
	}

	lc.LogError("sirius-scanner", "scan-manager", err, details, metadata)
}

// LogToolExecution logs tool execution metrics (convenience method for App Scanner)
func (lc *LoggingClient) LogToolExecution(scanID, target, tool string, duration time.Duration, success bool, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["scan_id"] = scanID
	metadata["target"] = target
	metadata["tool"] = tool
	metadata["success"] = success

	metric := PerformanceMetric{
		Duration: duration,
		Metadata: metadata,
	}

	lc.LogPerformanceMetric("sirius-scanner", "tool-execution", metric, metadata)
}

// LogHostDiscovery logs host discovery events (convenience method for App Scanner)
func (lc *LoggingClient) LogHostDiscovery(scanID, hostIP string, ports []int, toolUsed string) {
	metadata := map[string]interface{}{
		"scan_id":     scanID,
		"host_ip":     hostIP,
		"ports_found": len(ports),
		"ports":       ports,
		"tool_used":   toolUsed,
	}

	event := BusinessEvent{
		EventType:  "host_discovery",
		EntityID:   hostIP,
		EntityType: "host",
		Action:     "discovered",
		Result:     "success",
		Metadata:   metadata,
	}

	lc.LogBusinessEvent("sirius-scanner", "host-discovery", event, metadata)
}

// LogVulnerabilityScan logs vulnerability scan results (convenience method for App Scanner)
func (lc *LoggingClient) LogVulnerabilityScan(scanID, hostIP string, vulnerabilities []map[string]interface{}, toolUsed string) {
	metadata := map[string]interface{}{
		"scan_id":               scanID,
		"host_ip":               hostIP,
		"vulnerabilities_found": len(vulnerabilities),
		"vulnerabilities":       vulnerabilities,
		"tool_used":             toolUsed,
	}

	event := BusinessEvent{
		EventType:  "vulnerability_scan",
		EntityID:   hostIP,
		EntityType: "host",
		Action:     "vulnerability_scan",
		Result:     "completed",
		Metadata:   metadata,
	}

	lc.LogBusinessEvent("sirius-scanner", "vulnerability-scan", event, metadata)
}

// LogScanCompletion logs scan completion (convenience method for App Scanner)
func (lc *LoggingClient) LogScanCompletion(scanID, target string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["scan_id"] = scanID
	metadata["target"] = target

	event := BusinessEvent{
		EventType:  "scan_completion",
		EntityID:   scanID,
		EntityType: "scan",
		Action:     "completed",
		Result:     "success",
		Metadata:   metadata,
	}

	lc.LogBusinessEvent("sirius-scanner", "scan-manager", event, metadata)
}

// LogEvent logs a structured event with all event fields
func (lc *LoggingClient) LogEvent(service, subcomponent, eventType, severity, title, description string, entityType, entityID string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	context := map[string]interface{}{
		"type": "event",
	}

	// Generate event ID
	eventID := fmt.Sprintf("evt_%s_%d", time.Now().Format("20060102_150405"), time.Now().UnixNano()%1000000)

	entry := LogEntry{
		ID:           lc.generateID(),
		EventID:      eventID,
		Timestamp:    time.Now(),
		Service:      service,
		Subcomponent: subcomponent,
		Level:        lc.severityToLevel(severity),
		EventType:    eventType,
		Severity:     severity,
		Title:        title,
		Message:      title, // Use title as message for backward compatibility
		Description:  description,
		Metadata:     metadata,
		Context:      context,
		EntityType:   entityType,
		EntityID:     entityID,
	}

	if lc.config.Async {
		lc.bufferLog(entry)
	} else {
		lc.submitLog(entry)
	}
}

// severityToLevel converts severity string to LogLevel
func (lc *LoggingClient) severityToLevel(severity string) LogLevel {
	switch severity {
	case "critical", "error":
		return LogLevelError
	case "warning":
		return LogLevelWarn
	case "info":
		return LogLevelInfo
	default:
		return LogLevelInfo
	}
}

// LogScanStarted logs when a scan starts
func (lc *LoggingClient) LogScanStarted(scanID string, targets []string, options map[string]interface{}) {
	metadata := make(map[string]interface{})
	for k, v := range options {
		metadata[k] = v
	}
	metadata["scan_id"] = scanID
	metadata["targets"] = targets
	metadata["target_count"] = len(targets)

	lc.LogEvent(
		"sirius-scanner",
		"scan-manager",
		"scan_started",
		"info",
		fmt.Sprintf("Scan %s started", scanID),
		fmt.Sprintf("Started scan with %d targets", len(targets)),
		"scan",
		scanID,
		metadata,
	)
}

// LogScanCompleted logs when a scan completes successfully
func (lc *LoggingClient) LogScanCompleted(scanID string, stats map[string]interface{}) {
	metadata := make(map[string]interface{})
	for k, v := range stats {
		metadata[k] = v
	}
	metadata["scan_id"] = scanID

	lc.LogEvent(
		"sirius-scanner",
		"scan-manager",
		"scan_completed",
		"info",
		fmt.Sprintf("Scan %s completed", scanID),
		"Scan completed successfully",
		"scan",
		scanID,
		metadata,
	)
}

// LogHostDiscovered logs when a new host is discovered
func (lc *LoggingClient) LogHostDiscovered(hostIP, scanID string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["scan_id"] = scanID
	metadata["host_ip"] = hostIP

	lc.LogEvent(
		"sirius-scanner",
		"host-discovery",
		"host_discovered",
		"info",
		fmt.Sprintf("Host %s discovered", hostIP),
		fmt.Sprintf("New host discovered during scan %s", scanID),
		"host",
		hostIP,
		metadata,
	)
}

// LogVulnerabilityFound logs when vulnerabilities are found
func (lc *LoggingClient) LogVulnerabilityFound(vulnID, hostIP, severity string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["vulnerability_id"] = vulnID
	metadata["host_ip"] = hostIP

	// Determine event severity based on vulnerability severity
	eventSeverity := "info"
	if severity == "critical" || severity == "high" {
		eventSeverity = "warning"
	}

	lc.LogEvent(
		"sirius-scanner",
		"vulnerability-scan",
		"vulnerabilities_found",
		eventSeverity,
		fmt.Sprintf("Vulnerability %s found on %s", vulnID, hostIP),
		fmt.Sprintf("Vulnerability with severity %s detected", severity),
		"vulnerability",
		vulnID,
		metadata,
	)
}

// Close gracefully shuts down the logging client
func (lc *LoggingClient) Close() error {
	if lc.config.Async {
		close(lc.stopChan)
		lc.wg.Wait()

		// Flush any remaining logs
		lc.bufferMux.Lock()
		if len(lc.buffer) > 0 {
			lc.flushBuffer()
		}
		lc.bufferMux.Unlock()
	}

	// Close PostgreSQL event persistence if enabled
	if lc.eventPersistence != nil {
		if err := lc.eventPersistence.Close(); err != nil {
			return fmt.Errorf("failed to close event persistence: %w", err)
		}
	}

	return nil
}

// Private methods

func (lc *LoggingClient) generateID() string {
	return fmt.Sprintf("log_%s_%d", time.Now().Format("20060102_150405"), time.Now().UnixNano()%1000000)
}

func (lc *LoggingClient) bufferLog(entry LogEntry) {
	lc.bufferMux.Lock()
	defer lc.bufferMux.Unlock()

	lc.buffer = append(lc.buffer, entry)

	// Flush if buffer is full
	if len(lc.buffer) >= lc.config.BufferSize {
		lc.flushBuffer()
	}
}

func (lc *LoggingClient) flushRoutine() {
	defer lc.wg.Done()

	ticker := time.NewTicker(lc.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lc.bufferMux.Lock()
			if len(lc.buffer) > 0 {
				lc.flushBuffer()
			}
			lc.bufferMux.Unlock()
		case <-lc.stopChan:
			return
		}
	}
}

func (lc *LoggingClient) flushBuffer() {
	if len(lc.buffer) == 0 {
		return
	}

	// Submit all buffered logs
	for _, entry := range lc.buffer {
		lc.submitLog(entry)
	}

	// Clear buffer
	lc.buffer = lc.buffer[:0]
}

func (lc *LoggingClient) submitLog(entry LogEntry) {
	// Sanitize metadata to prevent circular references
	sanitizedEntry := entry
	sanitizedEntry.Metadata = sanitizeMetadata(entry.Metadata)
	sanitizedEntry.Context = sanitizeMetadata(entry.Context)

	// Dual-write: Store in PostgreSQL if enabled
	if lc.config.EnablePostgresEvents && lc.eventPersistence != nil {
		if err := lc.eventPersistence.StoreEvent(sanitizedEntry); err != nil {
			// Log error but don't fail - continue with HTTP submission
			fmt.Printf("⚠️  Failed to store event in PostgreSQL: %v\n", err)
		}
	}

	// Serialize the log entry for HTTP submission to Valkey
	body, err := json.Marshal(sanitizedEntry)
	if err != nil {
		fmt.Printf("Failed to marshal log entry: %v\n", err)
		return
	}

	// Submit to Valkey via HTTP (legacy behavior)
	lc.submitWithRetry(body)
}

// sanitizeMetadata removes circular references and converts complex objects to safe representations
func sanitizeMetadata(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	visited := make(map[uintptr]bool)

	for key, value := range metadata {
		sanitized[key] = sanitizeValue(value, visited)
	}

	return sanitized
}

// sanitizeValue recursively sanitizes a value to prevent circular references
func sanitizeValue(value interface{}, visited map[uintptr]bool) interface{} {
	if value == nil {
		return nil
	}

	// Use reflection to get the pointer address for circular reference detection
	val := reflect.ValueOf(value)
	var ptr uintptr

	// Get pointer address based on type
	switch val.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface:
		if val.IsValid() && !val.IsNil() {
			ptr = val.Pointer()
		}
	default:
		// For non-pointer types, create a pointer to detect cycles
		if val.CanAddr() {
			ptr = val.Addr().Pointer()
		}
	}

	// Check for circular reference
	if ptr != 0 && visited[ptr] {
		return "[circular reference]"
	}

	// Handle primitive types directly
	switch v := value.(type) {
	case string, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		return v
	case time.Time:
		return v.Format(time.RFC3339)
	case time.Duration:
		return v.String()
	case error:
		return v.Error()
	}

	// Handle maps
	if m, ok := value.(map[string]interface{}); ok {
		if ptr != 0 {
			visited[ptr] = true
			defer delete(visited, ptr)
		}

		sanitized := make(map[string]interface{})
		for k, v := range m {
			sanitized[k] = sanitizeValue(v, visited)
		}
		return sanitized
	}

	// Handle slices/arrays
	if s, ok := value.([]interface{}); ok {
		if ptr != 0 {
			visited[ptr] = true
			defer delete(visited, ptr)
		}

		sanitized := make([]interface{}, len(s))
		for i, v := range s {
			sanitized[i] = sanitizeValue(v, visited)
		}
		return sanitized
	}

	// Handle arrays of specific types (safe to return as-is)
	if arr, ok := value.([]int); ok {
		return arr
	}
	if arr, ok := value.([]string); ok {
		return arr
	}
	if arr, ok := value.([]float64); ok {
		return arr
	}

	// For complex types, return type information instead of trying to serialize
	// This prevents stack overflow from circular references in fmt.Sprintf
	if t := reflect.TypeOf(value); t != nil {
		return fmt.Sprintf("[%s]", t.String())
	}
	return "[unknown type]"
}

func (lc *LoggingClient) submitWithRetry(body []byte) {
	for attempt := 0; attempt <= lc.config.MaxRetries; attempt++ {
		req, err := http.NewRequest("POST", lc.config.APIBaseURL, bytes.NewBuffer(body))
		if err != nil {
			fmt.Printf("Failed to create log request: %v\n", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := lc.httpClient.Do(req)
		if err != nil {
			if attempt < lc.config.MaxRetries {
				time.Sleep(lc.config.RetryDelay * time.Duration(attempt+1))
				continue
			}
			// Silently fail on final attempt to avoid log spam
			return
		}
		defer resp.Body.Close()

		// Success or non-retryable error
		if resp.StatusCode < 500 || attempt == lc.config.MaxRetries {
			return
		}

		// Retry on server errors
		time.Sleep(lc.config.RetryDelay * time.Duration(attempt+1))
	}
}
