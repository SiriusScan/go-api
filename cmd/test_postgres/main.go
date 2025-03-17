package main

import (
	"fmt"
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres"
)

func main() {
	log.Println("Starting app PostgreSQL connection test...")

	// Get database connection using our application's database code
	db := postgres.GetDB()

	// Check if connection was successful
	if db == nil {
		log.Fatalf("❌ Failed to establish database connection")
	}

	// Try to execute a simple query
	var result int
	if err := db.Raw("SELECT 1").Scan(&result).Error; err != nil {
		log.Fatalf("❌ Failed to execute query: %v", err)
	}

	// Check if connection is marked as initialized
	if !postgres.IsConnected() {
		log.Fatalf("❌ Connection not marked as initialized")
	}

	// Get any connection error
	if err := postgres.GetConnectionError(); err != nil {
		log.Fatalf("❌ Connection error: %v", err)
	}

	// Success!
	fmt.Println("✅ App PostgreSQL connection test successful!")
	fmt.Println("✅ Database is properly connected and initialized")
}
