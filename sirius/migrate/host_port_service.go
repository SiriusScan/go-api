package migrate

import "gorm.io/gorm"

// apply011 adds per-host, per-source service identification columns to
// host_ports so open ports carry service detection independently of findings.
func apply011(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		return execAll(tx, []string{
			`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS service_name TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS service_product TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS service_version TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS service_extrainfo TEXT NOT NULL DEFAULT ''`,
		})
	})
}
