package logging

import (
	"context"
	"sync"
	"time"
)

// Global logging client instance
var (
	globalClient *LoggingClient
	clientMux    sync.RWMutex
)

// Init initializes the global logging client with default configuration
func Init() {
	clientMux.Lock()
	defer clientMux.Unlock()
	
	if globalClient == nil {
		globalClient = NewLoggingClient()
	}
}

// InitWithConfig initializes the global logging client with custom configuration
func InitWithConfig(config *LogConfig) {
	clientMux.Lock()
	defer clientMux.Unlock()
	
	globalClient = NewLoggingClientWithConfig(config)
}

// GetClient returns the global logging client, initializing it if necessary
func GetClient() *LoggingClient {
	clientMux.RLock()
	if globalClient != nil {
		clientMux.RUnlock()
		return globalClient
	}
	clientMux.RUnlock()
	
	// Initialize if not already done
	Init()
	
	clientMux.RLock()
	defer clientMux.RUnlock()
	return globalClient
}

// Close closes the global logging client
func Close() error {
	clientMux.Lock()
	defer clientMux.Unlock()
	
	if globalClient != nil {
		err := globalClient.Close()
		globalClient = nil
		return err
	}
	return nil
}

// Convenience functions that use the global client

// Log sends a log entry using the global client
func Log(service, subcomponent string, level LogLevel, message string, metadata map[string]interface{}, context map[string]interface{}) {
	GetClient().Log(service, subcomponent, level, message, metadata, context)
}

// LogBusinessEvent logs a business event using the global client
func LogBusinessEvent(service, subcomponent string, event BusinessEvent, metadata map[string]interface{}) {
	GetClient().LogBusinessEvent(service, subcomponent, event, metadata)
}

// LogPerformanceMetric logs a performance metric using the global client
func LogPerformanceMetric(service, subcomponent string, metric PerformanceMetric, metadata map[string]interface{}) {
	GetClient().LogPerformanceMetric(service, subcomponent, metric, metadata)
}

// LogError logs an error using the global client
func LogError(service, subcomponent string, err error, details ErrorDetails, metadata map[string]interface{}) {
	GetClient().LogError(service, subcomponent, err, details, metadata)
}

// LogScanEvent logs a scan event using the global client
func LogScanEvent(scanID, eventType, message string, metadata map[string]interface{}) {
	GetClient().LogScanEvent(scanID, eventType, message, metadata)
}

// LogScanError logs a scan error using the global client
func LogScanError(scanID, target, errorCode, message string, err error) {
	GetClient().LogScanError(scanID, target, errorCode, message, err)
}

// LogToolExecution logs tool execution using the global client
func LogToolExecution(scanID, target, tool string, duration time.Duration, success bool, metadata map[string]interface{}) {
	GetClient().LogToolExecution(scanID, target, tool, duration, success, metadata)
}

// LogHostDiscovery logs host discovery using the global client
func LogHostDiscovery(scanID, hostIP string, ports []int, toolUsed string) {
	GetClient().LogHostDiscovery(scanID, hostIP, ports, toolUsed)
}

// LogVulnerabilityScan logs vulnerability scan using the global client
func LogVulnerabilityScan(scanID, hostIP string, vulnerabilities []map[string]interface{}, toolUsed string) {
	GetClient().LogVulnerabilityScan(scanID, hostIP, vulnerabilities, toolUsed)
}

// LogScanCompletion logs scan completion using the global client
func LogScanCompletion(scanID, target string, metadata map[string]interface{}) {
	GetClient().LogScanCompletion(scanID, target, metadata)
}

// Context-aware logging functions

// WithContext creates a context-aware logger
func WithContext(ctx context.Context) *ContextLogger {
	return &ContextLogger{
		client: GetClient(),
		ctx:    ctx,
	}
}

// ContextLogger provides context-aware logging
type ContextLogger struct {
	client *LoggingClient
	ctx    context.Context
}

// Log sends a log entry with context
func (cl *ContextLogger) Log(service, subcomponent string, level LogLevel, message string, metadata map[string]interface{}, context map[string]interface{}) {
	// Add context information to metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	
	// Add request ID if available
	if requestID := cl.ctx.Value("request_id"); requestID != nil {
		metadata["request_id"] = requestID
	}
	
	// Add user ID if available
	if userID := cl.ctx.Value("user_id"); userID != nil {
		metadata["user_id"] = userID
	}
	
	cl.client.Log(service, subcomponent, level, message, metadata, context)
}

// LogBusinessEvent logs a business event with context
func (cl *ContextLogger) LogBusinessEvent(service, subcomponent string, event BusinessEvent, metadata map[string]interface{}) {
	cl.client.LogBusinessEvent(service, subcomponent, event, metadata)
}

// LogError logs an error with context
func (cl *ContextLogger) LogError(service, subcomponent string, err error, details ErrorDetails, metadata map[string]interface{}) {
	cl.client.LogError(service, subcomponent, err, details, metadata)
}
