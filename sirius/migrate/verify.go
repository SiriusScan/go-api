package migrate

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// PendingVersionsError lists the core migrations the ledger has yet to record.
type PendingVersionsError struct {
	Versions []string
}

func (e *PendingVersionsError) Error() string {
	return "pending core schema migrations: " + strings.Join(e.Versions, ", ")
}

// VerifyContext checks for every core migration required by this version of the
// SDK using read-only queries. A missing ledger or version returns a
// *PendingVersionsError. Database failures are returned as wrapped errors.
func VerifyContext(ctx context.Context, db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}
	db = db.Session(&gorm.Session{NewDB: true, Context: ctx})

	var exists bool
	if err := db.Raw("SELECT pg_catalog.to_regclass(?) IS NOT NULL", ledgerTable).Scan(&exists).Error; err != nil {
		return fmt.Errorf("locate core migration ledger: %w", err)
	}

	var versions []string
	if exists {
		if err := db.Table(ledgerTable).Pluck("version", &versions).Error; err != nil {
			return fmt.Errorf("read core migration ledger: %w", err)
		}
	}

	applied := make(map[string]bool, len(versions))
	for _, version := range versions {
		applied[version] = true
	}
	var pending []string
	for _, migration := range Migrations() {
		if !applied[migration.Version] {
			pending = append(pending, migration.Version)
		}
	}
	if len(pending) > 0 {
		return &PendingVersionsError{Versions: pending}
	}
	return nil
}
