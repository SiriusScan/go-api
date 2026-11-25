# Atomic host report ingestion

`host.AddReport(host.Report{...})` saves a single report as one PostgreSQL
transaction. `AddHost`, `AddHostWithSource`, and `AddHostWithSourceAndJSONB` delegate
to the same path. No database migration is required by this change.

The transaction includes:

- Host identity and basic fields.
- Software inventory, system fingerprint, and agent metadata JSONB.
- Shared port identities and source-specific port observations.
- Shared vulnerability identities and complete source-specific finding snapshots.
- Optional enriched catalog fields, kept separate from original scanner evidence.
- One scan-history event for the accepted report.

All findings and JSON documents are validated before persistence. The HTTP host
handlers return 400 for invalid reports before checking the catalog or attempting
NVD enrichment. Enrichment is computed in memory outside the transaction and
committed with the report. Statement or commit rejection rolls back the entire
report, including changes to preexisting rows. History failures are errors, not
silently ignored warnings.

Report writers serialize by host IP and acquire shared vulnerability locks in
sorted order. Port writes use sorted canonical identity order. This prevents
concurrent retries from creating duplicate host/observation rows and avoids
order-dependent deadlocks between overlapping reports. These locks coordinate
this ingestion path; unrelated legacy writers that bypass it are not covered.

Repeated successful reports update existing observations and retain first-seen
values. Each accepted report creates a new history event. This is not an
exactly-once request API: a client retry after a lost commit acknowledgment can
create another history event, but not another identity/observation.

## Reading accepted report history

`host.NewHostRepository().ListAcceptedReportHistory(ctx, resourceScope, ip, limit,
cursor)` reads the journal using a caller-authorized resource scope and a host IP.
Use `DefaultAcceptedReportLimit` for an unspecified page size. A subsequent
request uses the previous page's `next_cursor` for the same host. Reports are
ordered by accepted time and then by descending row ID, with undated entries
last. A missing or inaccessible host returns `gorm.ErrRecordNotFound`, and an
accessible host with no entries returns an empty list.

The read DTO calls the legacy `findings_count` column `submitted_item_count`.
That value counts submitted port and vulnerability entries and up to one software
inventory and fingerprint contribution each. Zero records an accepted empty
submission. A missing historical count or timestamp is `null`. Assessment
coverage is always `unknown` for these journal rows. Config and notes are
excluded from the default read.

The read applies its page limit in SQL and returns discovery metadata without
loading host relationships. It runs against the existing journal schema. A
composite index on host ID, accepted time and row ID can be added separately
if large retained journals require it.

## Regression checks

Run the offline query and projection checks with
`go test ./sirius/host -run TestAcceptedReportHistory`. Set
`SIRIUS_REPORT_TEST_DSN` to enable the accompanying history query fixture.

Use a disposable PostgreSQL instance, never an installed Sirius database:

```sh
SIRIUS_REPORT_TEST_DSN='host=127.0.0.1 port=... user=... password=... dbname=... sslmode=disable' \
  go test -short -race ./sirius/host -run TestReport -count=1
```

The tests create isolated temporary tables and one uniquely named schema for
concurrency checks. They cover invalid late findings, unsupported JSON values,
rollback after JSONB/port/finding/catalog/history failures, unchanged existing
reports, deferred commit rejection, exact retry, and concurrent reports with
reversed finding order. The temporary schema is removed after testing.
