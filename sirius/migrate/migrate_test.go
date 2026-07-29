package migrate

import (
	"testing"
)

func TestMigrationsAreOrderedAndUnique(t *testing.T) {
	ms := Migrations()
	if len(ms) < 7 {
		t.Fatalf("expected at least 7 migrations, got %d", len(ms))
	}

	seen := make(map[string]bool)
	prev := ""
	for _, m := range ms {
		if m.Version == "" {
			t.Fatal("migration version must not be empty")
		}
		if m.Apply == nil {
			t.Fatalf("migration %s has nil Apply", m.Version)
		}
		if seen[m.Version] {
			t.Fatalf("duplicate migration version %s", m.Version)
		}
		seen[m.Version] = true
		if prev != "" && m.Version < prev {
			// Lexicographic order matches our zero-padded numeric prefixes.
			t.Fatalf("migrations out of order: %s before %s", prev, m.Version)
		}
		prev = m.Version
	}

	if ms[0].Version != "001_baseline" {
		t.Fatalf("first migration must be 001_baseline, got %s", ms[0].Version)
	}
	if ms[len(ms)-1].Version != "007_add_vulnerability_stats_indexes" {
		t.Fatalf("last migration must be 007_..., got %s", ms[len(ms)-1].Version)
	}
}

func TestLedgerTableName(t *testing.T) {
	if ledgerTable != "schema_migrations_core" {
		t.Fatalf("unexpected ledger table name: %s", ledgerTable)
	}
}
