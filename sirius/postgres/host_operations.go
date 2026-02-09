// File: host_operations.go
package postgres

import (
	"log/slog"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"gorm.io/gorm"
)

func AddHost(db *gorm.DB, host models.Host) error {
	result := db.Create(&host)
	if result.Error != nil {
		return result.Error
	}

	slog.Info("Added host to database", "ip", host.IP)
	return nil
}

func GetHost(db *gorm.DB, ip string) (models.Host, error) {
	var host models.Host
	result := db.Preload("Ports").Preload("Vulnerabilities").Where("ip = ?", ip).First(&host)
	if result.Error != nil {
		return models.Host{}, result.Error
	}

	return host, nil
}

func GetAllHosts(db *gorm.DB) ([]models.Host, error) {
	var hosts []models.Host
	result := db.Find(&hosts)
	if result.Error != nil {
		return nil, result.Error
	}

	return hosts, nil
}

func GetCVEID(db *gorm.DB, cve string) (uint, error) {
	var vulnerability models.CVEItem
	result := db.Where("cve = ?", cve).First(&vulnerability)
	if result.Error != nil {
		return 0, result.Error
	}
	return vulnerability.ID, nil
}
