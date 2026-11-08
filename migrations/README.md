# Database Migrations

Core schema changes are applied by the **ledger migrator** in `sirius/migrate`,
invoked via `cmd/migrate`. Applied versions are recorded in
`schema_migrations_core`.

## Production / Compose

```bash
# Preferred: one-shot service (see Sirius docker-compose.yaml sirius-migrate)
docker compose run --rm sirius-migrate

# Or run the binary directly against Postgres
DB_HOST=sirius-postgres DB_USER=postgres DB_PASSWORD=... DB_NAME=sirius \
  ./migrate
```

## Local development

```bash
# Apply all pending core migrations
go run ./cmd/migrate

# Optional: AutoMigrate on connect for throwaway local DBs only
# This does not replace the ledger migrator; 008 owns host_ports.state.
export SIRIUS_SCHEMA_AUTO_MIGRATE=true

# Tests only — destructive reset before AutoMigrate
export SIRIUS_SCHEMA_FORCE_RESET=true
export SIRIUS_SCHEMA_AUTO_MIGRATE=true
```

**Do not** use `SIRIUS_SCHEMA_FORCE_RESET` in production. Connecting to the
database no longer drops tables by default.

## Legacy per-directory scripts

The numbered directories (`002_source_attribution`, …) remain for historical
reference and one-off debugging. New deployments must use `cmd/migrate`, which
applies equivalent idempotent steps (`001_baseline` … `008_host_port_state`).

## Ledger

| Table | Purpose |
| --- | --- |
| `schema_migrations_core` | Versions applied for Community/core schema |

Pro editions use a separate `schema_migrations_pro` ledger (not in this repo).

## Host/source port state

Migration 008 requires a coordinated writer upgrade and an affected-host rescan.
Read [008 rollout and compatibility notes](008_host_port_state.md) before release.

## Source-specific vulnerability evidence

Migration 009 preserves full findings per host/source. See [009_host_vulnerability_finding.md](009_host_vulnerability_finding.md) for compatibility, preflight, rollout, and isolated tests.
