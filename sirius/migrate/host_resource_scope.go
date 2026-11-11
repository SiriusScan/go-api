package migrate

import "gorm.io/gorm"

// apply010 leaves all existing hosts in the global scope. Scoped IP identities
// are unique; legacy global duplicates are retained for backwards compatibility.
func apply010(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		for _, query := range []string{
			`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS owner_subject_id TEXT NOT NULL DEFAULT ''`,
			`CREATE INDEX IF NOT EXISTS idx_hosts_owner_subject_id ON hosts(owner_subject_id)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_scoped_ip ON hosts(owner_subject_id, ip) WHERE owner_subject_id <> '' AND deleted_at IS NULL`,
		} {
			if err := tx.Exec(query).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
