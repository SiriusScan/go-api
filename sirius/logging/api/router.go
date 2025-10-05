package api

import (
	"net/http"
)

// SetupLoggingRoutes sets up all logging-related HTTP routes
func SetupLoggingRoutes(mux *http.ServeMux) {
	// Log submission
	mux.HandleFunc("/api/v1/logs", LogSubmissionHandler)
	
	// Log retrieval with query parameters
	mux.HandleFunc("/api/v1/logs/", func(w http.ResponseWriter, r *http.Request) {
		// Handle different endpoints based on the path
		if r.URL.Path == "/api/v1/logs/stats" {
			LogStatsHandler(w, r)
		} else if r.URL.Path == "/api/v1/logs/clear" {
			LogClearHandler(w, r)
		} else {
			// For individual log operations (GET, PUT, DELETE)
			// Extract the log ID from the path
			LogRetrievalHandler(w, r)
		}
	})
	
	// Individual log operations
	mux.HandleFunc("/api/v1/logs/", LogUpdateHandler)
	mux.HandleFunc("/api/v1/logs/", LogDeleteHandler)
}

// SetupLoggingRoutesWithPrefix sets up logging routes with a custom prefix
func SetupLoggingRoutesWithPrefix(mux *http.ServeMux, prefix string) {
	// Log submission
	mux.HandleFunc(prefix+"/logs", LogSubmissionHandler)
	
	// Log retrieval with query parameters
	mux.HandleFunc(prefix+"/logs/", func(w http.ResponseWriter, r *http.Request) {
		// Handle different endpoints based on the path
		if r.URL.Path == prefix+"/logs/stats" {
			LogStatsHandler(w, r)
		} else if r.URL.Path == prefix+"/logs/clear" {
			LogClearHandler(w, r)
		} else {
			// For individual log operations (GET, PUT, DELETE)
			LogRetrievalHandler(w, r)
		}
	})
	
	// Individual log operations
	mux.HandleFunc(prefix+"/logs/", LogUpdateHandler)
	mux.HandleFunc(prefix+"/logs/", LogDeleteHandler)
}
