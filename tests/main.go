package main

import (
	"log"

	// sqlite "github.com/ytsruh/gorm-libsql"
	"gorm.io/gorm"

	// _ "github.com/tursodatabase/go-libsql"

	_ "github.com/tursodatabase/libsql-client-go/libsql"

	_ "github.com/SiriusScan/go-api/sirius/host"
	"github.com/SiriusScan/go-api/nvd"
)

var db *gorm.DB

func main() {
	log.Println("Entering Tests")
	
	cve, err := nvd.GetCVE("CVE-2017-0143")
	if err != nil {
		log.Fatalf("Failed test: %v", err)
	}
	log.Println(cve.Descriptions)

}

func MigrateTables(db *gorm.DB) error {
	// Use the existing database connection
	log.Println("Migrating tables")

	// Create test table
	// func GetHost(db *gorm.DB, ip string) (models.Host, error) {
		// var host models.Host
		// result := db.Preload("Ports").Preload("Vulnerabilities").Where("ip = ?", ip).First(&host)
		// if result.Error != nil {
		// 	return models.Host{}, result.Error
		// }

		// fmt.Printf("Host retrieved: \n", host.IP)
		// fmt.Printf("=====================")

		// fmt.Println(host)
		// return host, nil

	return nil

}

/*

// Configure connection pool
	db.SetConnMaxIdleTime(9 * time.Second)

	// Create Base Tables
	err = MigrateTables(db)
	if err != nil {
		log.Fatal("Could not instantiate tables.")
	}

	// Query the data
	rows, err := db.Query("SELECT * FROM test")
	if err != nil {
		fmt.Errorf("error querying data: %w", err)
	}
	defer rows.Close()

	// Print results
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			fmt.Errorf("error scanning row: %w", err)
		}
		fmt.Printf("Row: id=%d, name=%s\n", id, name)
	}
	if err := rows.Err(); err != nil {
		fmt.Errorf("error iterating rows: %w", err)
	}

	fmt.Printf("Successfully connected and executed queries on %s\n", dbUrl)

*/

/*
// Use the existing database connection
	db := postgres.GetDB()

	// Retrieve a CVEItem based on the CVE ID
	var cveItem models.CVEItem
	cveID := "CVE-2017-0143" // Replace with an actual CVE ID from your database

	err := db.Preload("DataMeta").
		Preload("ProblemType").
		Preload("References").
		Preload("Descriptions").
		Preload("Configurations").
		Preload("Impact").
		Joins("JOIN cve_data_meta ON cve_data_meta.cve_item_id = cve_items.id").
		Where("cve_data_meta.id = ?", cveID).
		First(&cveItem).Error

	if err != nil {
		log.Fatalf("Failed to retrieve CVEItem: %v", err)
	}

	fmt.Printf("Retrieved CVEItem: %+v\n", cveItem)
*/

/*

// Check if test data already exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM test WHERE id = 1)").Scan(&exists)
	if err != nil {
		fmt.Errorf("error checking existing data: %w", err)
	}

	// Insert test data only if it doesn't exist
	if !exists {
		_, err = db.Exec("INSERT INTO test (id, name) VALUES (?, ?)", 1, "remote test")
		if err != nil {
			fmt.Errorf("error inserting data: %w", err)
		}
		fmt.Println("Inserted test data")
	} else {
		fmt.Println("Test data already exists, skipping insert")
	}

*/
