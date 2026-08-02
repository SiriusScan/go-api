# Migration 008: Host owner_subject_id

Adds `owner_subject_id` so the same IP can exist as separate inventory rows per student/tenant.

## Authoritative path

Applied by the ledger migrator (`sirius/migrate` via `cmd/migrate`) as version `008_host_owner_subject`.

## SQL (idempotent)

```sql
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS owner_subject_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_hosts_owner_subject_id ON hosts(owner_subject_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_owner_ip ON hosts(owner_subject_id, ip) WHERE deleted_at IS NULL;
```

## Notes

- Empty `owner_subject_id` = legacy/admin global inventory (Community path unchanged).
- HID remains globally unique; generated HIDs embed a short owner digest when owned.
- AutoMigrate on connect (`SIRIUS_SCHEMA_AUTO_MIGRATE=true`) also picks up the GORM field; production must still run `cmd/migrate` for the unique index.
