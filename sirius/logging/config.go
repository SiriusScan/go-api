package logging

import (
	"os"
	"strconv"
	"time"
)

// LoadConfigFromEnv loads logging configuration from environment variables
func LoadConfigFromEnv() *LogConfig {
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
	
	if maxRetries := os.Getenv("SIRIUS_LOG_MAX_RETRIES"); maxRetries != "" {
		if r, err := strconv.Atoi(maxRetries); err == nil {
			config.MaxRetries = r
		}
	}
	
	if retryDelay := os.Getenv("SIRIUS_LOG_RETRY_DELAY"); retryDelay != "" {
		if d, err := time.ParseDuration(retryDelay); err == nil {
			config.RetryDelay = d
		}
	}
	
	if async := os.Getenv("SIRIUS_LOG_ASYNC"); async != "" {
		if a, err := strconv.ParseBool(async); err == nil {
			config.Async = a
		}
	}
	
	if bufferSize := os.Getenv("SIRIUS_LOG_BUFFER_SIZE"); bufferSize != "" {
		if s, err := strconv.Atoi(bufferSize); err == nil {
			config.BufferSize = s
		}
	}
	
	if flushInterval := os.Getenv("SIRIUS_LOG_FLUSH_INTERVAL"); flushInterval != "" {
		if d, err := time.ParseDuration(flushInterval); err == nil {
			config.FlushInterval = d
		}
	}
	
	return config
}

// GetLogLevelFromString converts a string to LogLevel
func GetLogLevelFromString(level string) LogLevel {
	switch level {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// IsValidLogLevel checks if a string represents a valid log level
func IsValidLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "warning", "error":
		return true
	default:
		return false
	}
}
