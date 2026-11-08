# 008: host- and source-scoped port state

This change is prepared in source only. Do not apply it to a live database as
part of tests. Production rollout requires a separately authorized maintenance
window and a backup.

## Data model and behavior

`ports` remains the shared `(number, protocol)` catalog. `host_ports.state`
stores the observation under `(host_id, port_id, source)`. Both normal host
responses and source-attributed responses now read that observation. Normal
responses select the active source with the latest `last_seen`; equal timestamps
use source name order as a deterministic tie breaker. Source responses retain
all source records and their independent states. The JSON port shape is unchanged.

Migration 008 adds the observation column, ensures unique port identity, and
repairs the legacy two-column host-port primary key to include source. All of
008 runs transactionally, without truncating or deleting findings. It takes
write-blocking table locks, builds a unique index, and may scan the junction
table, so size the maintenance window for the dataset.

The model excludes `HostPort.State` from GORM schema auto-migration. Migration
008 exclusively owns adding and initializing that column, including when the
ledger baseline runs on a populated legacy database. Run the ledger migrator
even for throwaway databases; AutoMigrate alone is no longer sufficient for
port observations. Subsequent AutoMigrate does not alter the observation column.

Rows lacking observation state are initialized from the legacy catalog value,
or `unknown` if no value/identity exists. This is a **best-effort snapshot**, not
proof that every host had that state. The old shared field may already have been
overwritten by another host. Historical host/source truth is unrecoverable from
that field alone. Rescan affected hosts after rollout. Already-populated
observation states are preserved if the migration is retried. A null source is
normalized to `unknown`; incompatible duplicates or unexpected key layouts fail
and roll back rather than guessing how to merge data. Investigate those cases
before retrying. Soft-deleted catalog identities also fail migration preflight:
the full identity uniqueness in existing schemas prevents safely creating a
second active identity. Runtime attempts return `ErrPortIdentityDeleted`; they
never automatically resurrect a shared identity and thereby revive another
host's retired observations. Review the intended retirement/recovery policy and
reconcile those rows explicitly before release. A dependent foreign key that prevents replacing the old primary
key also fails safely; the migration intentionally does not use `CASCADE`.

## SDK compatibility

Prefer the new atomic method:

```go
err := repo.UpsertHostPort(hostID, port.Number, port.Protocol, port.State, source)
```

Both in-tree ingestion paths use it. An omitted scanner state still defaults to
`open`, as before. External callers that already hold a catalog ID can call
`LinkHostPortWithState(hostID, portID, source, state)`.

The old `UpsertPort(number, protocol, state)` signature remains callable, but its
state argument is deprecated and ignored because it has no host/source context.
`LinkHostPort(hostID, portID, source)` preserves an existing state, or creates an
`unknown` observation. The old two-step pattern is therefore source-compatible
but **not observation-behavior-compatible**. Update external SDK users to pass
state explicitly. No request-local cache or shared state fallback is used to
simulate the old API, since those would reintroduce cross-host races.

Protocol identity spelling is preserved; this change does not normalize or merge
existing mixed-case protocol values.

The exported `models.Port.State` field and database column remain for response
and legacy schema compatibility. New repository writes do not update it. Direct
SQL/GORM consumers must switch reads and writes to `host_ports.state`.

## Rollout order and dependency audit

1. Back up and inspect duplicate or soft-deleted `(number, protocol)` identities, host-port keys,
   dependent constraints, and table sizes. Do not automatically delete duplicates.
2. Stop/pause every writer using the old SDK. Do not do a mixed-version rolling
   writer rollout: old writers continue updating the catalog and do not update
   the new observation column.
3. Run the ledger migrator containing `008_host_port_state` once, then deploy all
   API/scanner/engine binaries built against the same updated go-api version.
4. Confirm migration ledger version and host/source read behavior, then rescan
   affected hosts to replace the uncertain baseline.

Current Compose wiring invokes `/app/migrate` before API/engine startup. The dev
Compose override runs `go run ./cmd/migrate` from the mounted go-api checkout.
The production API Dockerfile clones go-api to build the migrator and the engine
Dockerfile clones its own go-api dependency. Update their pinned dependency refs
and the API's Go module version consistently when preparing a release; changing
this local checkout alone does not update those images. No Dockerfile pins,
services, binaries, or live data were changed for this fix.

The caller audit covered all checked-out Go repositories under
`sirius-workspace`, excluding dependency caches and vendor directories. The only
functional `UpsertPort`/`LinkHostPort` callers found were the two go-api ingestion
paths, now migrated. External repos and independently pinned SDK consumers still
require an audit before release.

This is a forward-only migration. Keeping old columns means an old binary can
read the schema, but rolling application code back restores stale/shared-state
behavior. Restoring the old two-column key would lose source isolation and may
fail once multiple sources exist; do not treat that as an automatic rollback.

## Isolated verification

New tests use an explicit `SIRIUS_PORT_TEST_DSN` pointing only at a disposable
Postgres instance. They use rolled-back temporary tables or a rolled-back schema
for the fresh-ledger test. Set `DB_HOST=127.0.0.1 DB_PORT=1` and both schema flags
to false to keep the package's global connection away from any real database.

```sh
DB_HOST=127.0.0.1 DB_PORT=1 \
SIRIUS_SCHEMA_AUTO_MIGRATE=false SIRIUS_SCHEMA_FORCE_RESET=false \
SIRIUS_PORT_TEST_DSN='host=127.0.0.1 port=<disposable-port> user=postgres dbname=port_state_test sslmode=disable' \
go test ./sirius/host ./sirius/migrate -run 'TestPort|TestMigrations' -count=1
```

Do not run the old repository integration tests against a shared database: some
legacy tests contain broad deletes. The new focused command excludes them.
