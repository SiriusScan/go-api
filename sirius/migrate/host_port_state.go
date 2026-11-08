package migrate

import "gorm.io/gorm"

// apply008 preserves legacy catalog data but stops using it as live observation
// state. Backfill is a best-effort snapshot, not recovery of historical truth.
// The entire step is transactional; duplicate identities or unexpected keys fail
// safely rather than merging or deleting findings.
func apply008(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		return execAll(tx, []string{
			`LOCK TABLE ports, host_ports IN SHARE ROW EXCLUSIVE MODE`,
			`DO $$ BEGIN
			  IF EXISTS (SELECT 1 FROM ports WHERE deleted_at IS NOT NULL) THEN
			    RAISE EXCEPTION 'Soft-deleted port identities require explicit reconciliation before migration 008; refusing to resurrect host observations';
			  END IF;
			END $$`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_identity_unique ON ports(number, protocol)`,
			`ALTER TABLE host_ports ADD COLUMN IF NOT EXISTS state TEXT`,
			`UPDATE host_ports hp SET state = COALESCE(NULLIF(p.state, ''), 'unknown')
			 FROM ports p WHERE hp.port_id = p.id AND hp.state IS NULL`,
			`UPDATE host_ports SET state = 'unknown' WHERE state IS NULL`,
			`ALTER TABLE host_ports ALTER COLUMN state SET DEFAULT 'unknown'`,
			`ALTER TABLE host_ports ALTER COLUMN state SET NOT NULL`,
			`UPDATE host_ports SET source = 'unknown' WHERE source IS NULL`,
			`ALTER TABLE host_ports ALTER COLUMN source SET DEFAULT 'unknown'`,
			`ALTER TABLE host_ports ALTER COLUMN source SET NOT NULL`,
			`DO $$
			DECLARE key_name text; key_columns text[];
			BEGIN
			  SELECT c.conname, ARRAY(
			    SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, position)
			    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
			    ORDER BY k.position
			  ) INTO key_name, key_columns
			  FROM pg_constraint c WHERE c.conrelid = 'host_ports'::regclass AND c.contype = 'p';
			  IF key_columns = ARRAY['host_id', 'port_id', 'source']::text[] THEN
			    RETURN;
			  END IF;
			  IF key_name IS NOT NULL THEN
			    IF key_columns <> ARRAY['host_id', 'port_id']::text[] THEN
			      RAISE EXCEPTION 'Unexpected host_ports primary key: %', key_columns;
			    END IF;
			    EXECUTE format('ALTER TABLE host_ports DROP CONSTRAINT %I', key_name);
			  END IF;
			  ALTER TABLE host_ports ADD PRIMARY KEY (host_id, port_id, source);
			END $$`,
		})
	})
}
