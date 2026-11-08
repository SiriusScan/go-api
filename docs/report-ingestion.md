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

## Regression checks

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
