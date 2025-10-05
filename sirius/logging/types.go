package logging

import "time"

// LogLevel represents the severity level of a log entry
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Service      string                 `json:"service"`
	Subcomponent string                 `json:"subcomponent,omitempty"`
	Level        LogLevel               `json:"level"`
	Message      string                 `json:"message"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// LogConfig represents configuration for the logging client
type LogConfig struct {
	APIBaseURL    string        `json:"api_base_url"`
	Timeout       time.Duration `json:"timeout"`
	MaxRetries    int           `json:"max_retries"`
	RetryDelay    time.Duration `json:"retry_delay"`
	Async         bool          `json:"async"`
	BufferSize    int           `json:"buffer_size"`
	FlushInterval time.Duration `json:"flush_interval"`
}

// DefaultLogConfig returns a default configuration for logging
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		APIBaseURL:    "http://localhost:9001/api/v1/logs",
		Timeout:       2 * time.Second,
		MaxRetries:    3,
		RetryDelay:    100 * time.Millisecond,
		Async:         true,
		BufferSize:    100,
		FlushInterval: 5 * time.Second,
	}
}

// LogContext represents additional context for log entries
type LogContext struct {
	Type        string                 `json:"type,omitempty"`
	Endpoint    string                 `json:"endpoint,omitempty"`
	Method      string                 `json:"method,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Custom      map[string]interface{} `json:"custom,omitempty"`
}

// BusinessEvent represents a structured business event for logging
type BusinessEvent struct {
	EventType string                 `json:"event_type"`
	EntityID  string                 `json:"entity_id,omitempty"`
	EntityType string                `json:"entity_type,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Result    string                 `json:"result,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// PerformanceMetric represents performance data for logging
type PerformanceMetric struct {
	Duration    time.Duration         `json:"duration"`
	MemoryUsage int64                 `json:"memory_usage,omitempty"`
	CPUUsage    float64               `json:"cpu_usage,omitempty"`
	Throughput  float64               `json:"throughput,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ErrorDetails represents detailed error information for logging
type ErrorDetails struct {
	ErrorCode    string                 `json:"error_code,omitempty"`
	ErrorMessage string                 `json:"error_message"`
	StackTrace   string                 `json:"stack_trace,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}
