# Bounded NVD lookups

`GetCVEContext(ctx, id)` propagates cancellation and uses a 10-second maximum
request deadline. The shared HTTP client also has a 10-second timeout covering
connection setup, headers, and the full response body. An earlier caller deadline
wins. `GetCVE(id)` remains source-compatible and uses the same limit with a
background context. The vulnerability package similarly exposes the additive
`GetVulnerabilityContext` helper and retains `GetVulnerability`.

Consumers must bound a batch once, not renew the budget for every CVE. The scanner
and host-ingest API use a 30-second total enrichment budget per host. A metadata
timeout is best-effort: preserve detected findings and stop further lookups once
the budget expires. Scanner cancellation is distinct: return the context error
(with the detected findings) so cancellation is not reported as success.

API handlers derive their budget from Fiber `UserContext`. This respects a
middleware-supplied cancellation/deadline, but does not claim that Fiber cancels on
client disconnect. The explicit budget also covers requests without such
middleware. The budget bounds NVD work, not database operations.

## Release order

These SDK additions must be published before consumer dependency pins are moved.
The scanner's development replacement uses the local SDK. The Sirius API's pinned
SDK does not yet contain the context helpers; a temporary Go workspace is suitable
for local verification but is not a release solution. Publish the additive SDK,
update each consumer to that immutable version, verify clean builds without local
replacements/workspaces, then release consumers. Do not substitute a local replace
for the consumer release pin.

## Tests

`go test -race ./nvd` uses synthetic transports only. It covers canceled and
stalled headers/body, earlier caller deadlines, the finite legacy default, HTTP
and decode failures, and the existing empty-result contract. Scanner and API
`TestNVD*` tests cover multi-CVE budgets, cancellation, and preserving existing
findings without running scans or contacting NVD. When running consumer package
tests, isolate their unrelated database initialization using a nonexistent Unix
socket directory and disable schema auto-migration/reset.
