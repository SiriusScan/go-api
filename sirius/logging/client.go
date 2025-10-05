package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// LoggingClient provides a centralized way to send structured logs to the API
type LoggingClient struct {
	config     *LogConfig
	httpClient *http.Client
	buffer     []LogEntry
	bufferMux  sync.Mutex
	stopChan   chan struct{}
	wg         sync.WaitGroup
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
		EventType: eventType,
		EntityID:  scanID,
		EntityType: "scan",
		Action:    eventType,
		Metadata:  metadata,
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
		"scan_id":             scanID,
		"host_ip":             hostIP,
		"vulnerabilities_found": len(vulnerabilities),
		"vulnerabilities":     vulnerabilities,
		"tool_used":           toolUsed,
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
	// Serialize the log entry
	body, err := json.Marshal(entry)
	if err != nil {
		fmt.Printf("Failed to marshal log entry: %v\n", err)
		return
	}
	
	// Create request with retry logic
	lc.submitWithRetry(body)
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
