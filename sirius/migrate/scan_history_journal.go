package migrate

import "gorm.io/gorm"

// apply012 matches the live journal's host filter and keyset order.
// The core runner commits the index build and the ledger row together.
func apply012(db *gorm.DB) error {
	return db.Exec(`
		CREATE INDEX idx_scan_history_entries_live_host_time_id
			ON scan_history_entries USING btree (host_id, scan_time DESC NULLS LAST, id DESC)
			WHERE deleted_at IS NULL
	`).Error
}
