package postgres

import "testing"

func TestInitializeSchemaVerifyModeSkipsLegacyDDL(t *testing.T) {
	t.Setenv("SIRIUS_SCHEMA_MODE", " verify ")
	t.Setenv("SIRIUS_SCHEMA_AUTO_MIGRATE", "true")
	t.Setenv("SIRIUS_SCHEMA_FORCE_RESET", "true")

	// The reset path would attempt DDL on this unavailable handle.
	previous := db
	t.Cleanup(func() { db = previous })
	db = nil
	initializeSchema()
}
