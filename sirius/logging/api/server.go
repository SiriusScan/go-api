package api

import (
	"log/slog"
	"net/http"
	"time"
)

// LoggingAPIServer provides a standalone HTTP server for the logging API
type LoggingAPIServer struct {
	server *http.Server
	mux    *http.ServeMux
}

// NewLoggingAPIServer creates a new logging API server
func NewLoggingAPIServer(addr string) *LoggingAPIServer {
	mux := http.NewServeMux()

	// Setup logging routes
	SetupLoggingRoutes(mux)

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"healthy","service":"logging-api"}`)); err != nil {
			slog.Error("Failed to write health response", "error", err)
		}
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &LoggingAPIServer{
		server: server,
		mux:    mux,
	}
}

// Start starts the logging API server
func (s *LoggingAPIServer) Start() error {
	slog.Info("Starting logging API server", "addr", s.server.Addr)
	return s.server.ListenAndServe()
}

// Stop stops the logging API server
func (s *LoggingAPIServer) Stop() error {
	slog.Info("Stopping logging API server")
	return s.server.Close()
}

// GetMux returns the HTTP mux for custom route additions
func (s *LoggingAPIServer) GetMux() *http.ServeMux {
	return s.mux
}
