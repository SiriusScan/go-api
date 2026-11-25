# Migration 012 accepted report history index

`012_scan_history_journal` adds a partial B-tree on live journal rows ordered
by host, acceptance time descending with nulls last, then entry ID descending.
It runs in the core migration transaction and leaves existing rows intact.

## Rollout

Plain `CREATE INDEX` allows journal reads and blocks writes to
`scan_history_entries` while it holds the table lock. It can also wait for
prior writers. Measure build time and lock effects on a representative copy,
then schedule a rollout window and choose a `cmd/migrate -timeout` that fits
that window. A failed or canceled migration rolls back both the index and the
ledger row. Run the same migrator again after the blocker clears.

The migration requires the index name to be available. A separately created
index with that name produces an error before the ledger records 012. Check
its definition and validity and resolve the name collision before retrying.
An online build would need a separate path since PostgreSQL disallows
`CREATE INDEX CONCURRENTLY` inside the core migration transaction.

## PostgreSQL 15 acceptance

Use a disposable PostgreSQL 15 database with a role that can create schemas.
The tests create and remove their own schemas. Seeded report timestamps and
addresses are synthetic.

```sh
SIRIUS_REPORT_TEST_DSN="$DISPOSABLE_PG15_DSN" \
  go test -count=1 -v ./sirius/host -run '^TestAcceptedReportHistory'

SIRIUS_PORT_TEST_DSN="$DISPOSABLE_PG15_DSN" \
  go test -count=1 -v ./sirius/migrate -run '^Test(ScanHistoryJournalMigration|MigrationRunnerConcurrent)'
```

The host plan test loads 800,000 rows across eight hosts, with timestamp ties,
undated entries, soft deletes and a same-IP host in another scope. It logs
`EXPLAIN (ANALYZE, BUFFERS)` using default planner settings before and after
adding the index, then compares pages and cursors. Review actual row counts,
filter removals and buffer activity for the first page, the dated seek 80,000
rows into the journal, the transition to undated entries and a deep undated
seek. The before and after runs can warm different buffers. Use the plan
shape and rows scanned as the primary comparison.

The host suite also checks tenant visibility and cancels a read once
PostgreSQL reports that it is waiting on the journal relation lock. The
migration suite applies the fresh schema and separately upgrades a populated
010 schema. It cancels the upgrade while the index is waiting on a conflicting
lock, then verifies the retry and the surviving journal rows.
