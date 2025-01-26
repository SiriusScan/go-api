// File: connection.go
package postgres

import (
	"fmt"
	"log"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
	_ "github.com/SiriusScan/go-api/sirius/postgres/models"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"

	"gorm.io/gorm"
)

var db *gorm.DB

func init() {
	var err error

	var connType string
	connType = "libsql"

	if connType == "libsql" {
		dbUrl := "http://sirius-libsql:8080"

		db, err = gorm.Open(sqlite.New(sqlite.Config{
			DSN:        dbUrl,
			DriverName: "libsql",
			// isableForeignKeyConstraintWhenMigrating: true,
		}), &gorm.Config{})

		if err != nil {
			fmt.Println("Failed to connect to database")
			panic(err)
		}
	} else {
		dsn := "host=localhost user=postgres password=password dbname=sirius port=5432 sslmode=disable"
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
			// Logger: logger.Default.LogMode(logger.Info),
		})

		if err != nil {
			log.Fatalf("Error connecting to database: %v", err)
		}
	}

	err = db.AutoMigrate(
		&models.Host{},
		&models.Port{},
		&models.Service{},
		&models.Vulnerability{},
		&models.Agent{},
		&models.User{},
		&models.Note{},
		&models.CPE{},
		&models.CVEData{},
		&models.CVEItem{},
		&models.CVEDataMeta{},
		&models.ProblemType{},
		&models.ProblemTypeData{},
		&models.Reference{},
		&models.Configurations{},
		&models.Node{},
		&models.CpeMatch{},
		&models.Impact{},
		&models.BaseMetricV2{},
		&models.HostVulnerability{},
	)
	if err != nil {
		log.Fatalf("Error migrating database schema: %v", err)
	}
}

func GetDB() *gorm.DB {
	return db
}
