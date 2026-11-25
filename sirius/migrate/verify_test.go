package migrate

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"gorm.io/gorm"
)

func TestVerifyContextChecksLedgerReadOnly(t *testing.T) {
	db := migrationTestPool(t, migrationTestSchema(t))
	ctx := context.Background()
	verify := func() error {
		return db.Transaction(func(tx *gorm.DB) error {
			return VerifyContext(ctx, tx)
		}, &sql.TxOptions{ReadOnly: true})
	}

	var required []string
	for _, migration := range Migrations() {
		required = append(required, migration.Version)
	}
	checkPending := func(want []string) {
		t.Helper()
		err := verify()
		var pending *PendingVersionsError
		if !errors.As(err, &pending) || !slices.Equal(pending.Versions, want) {
			t.Fatalf("verify returned %v, want pending versions %v", err, want)
		}
	}

	checkPending(required)
	if db.Migrator().HasTable(ledgerTable) {
		t.Fatal("verification created a missing ledger")
	}

	if err := ensureLedger(db); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{required[0], "999_future"} {
		if err := recordApplied(db, version); err != nil {
			t.Fatal(err)
		}
	}
	checkPending(required[1:])

	for _, version := range required[1:] {
		if err := recordApplied(db, version); err != nil {
			t.Fatal(err)
		}
	}
	if err := verify(); err != nil {
		t.Fatalf("verify up-to-date ledger: %v", err)
	}

	if err := db.Exec("ALTER TABLE schema_migrations_core RENAME COLUMN version TO unexpected_version").Error; err != nil {
		t.Fatal(err)
	}
	var pending *PendingVersionsError
	if err := verify(); err == nil || errors.As(err, &pending) {
		t.Fatalf("verify broken ledger returned %v, want a database error", err)
	}
}
