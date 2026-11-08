# Atomic store and authentication persistence

The SDK now supports optional `ValueCreator`, `ValueCompareAndSetter`, and
`AtomicValueUpdater` capabilities. The public `KVStore` method set is unchanged.
The Valkey implementation supports all three capabilities.

- Enrollment uses atomic create-if-absent and never overwrites an existing token.
- Token and API-key validation update timestamps only when the exact record that
  was validated is still present. Revocation or scope changes cannot be undone
  by a stale timestamp write. A request already in progress can finish with the
  metadata it read; the next validation observes revocation or replacement.
- Stores without CAS skip best-effort timestamp persistence. Stores without
  atomic creation reject enrollment rather than emulate it with GET then SET.
- `EnsureAPIKey` fails closed on read errors or malformed records, creates only
  after confirmed absence, and preserves a concurrent scoped creator.
- Missing `GetValue` keys wrap `ErrKeyNotFound`. Custom store implementations
  must return that sentinel for confirmed absence. Other errors fail closed.
- API keys may carry the additive `mcp:read` scope. Legacy keys remain
  unrestricted. Invalid explicit scope lists are rejected. Enforcement belongs
  to the API consumer, which must be upgraded before issuing scoped keys.
- Batch CAS compares exact bytes and supports absent keys, read-only guards,
  create, update and delete. All guards are checked before any mutation and
  existing TTLs are retained. A false return means conflict; an error may have
  an uncertain outcome and must not be retried as a confirmed conflict.
- Clustered stores require every key in a batch to share a hash slot.

No database schema migration is included in this change.

## Verification

Run the ordinary offline suite with `go test -race -short ./...`.
Use only a new disposable Valkey instance for the opt-in integration tests:

```
SIRIUS_TEST_VALKEY_ADDR=127.0.0.1:<port> \
SIRIUS_TEST_ATOMIC_ISOLATED_ADDR=127.0.0.1:<port> \
go test -race -short -count=20 ./sirius/store
```

Run `scripts/test-atomic-store.sh` to provision and remove a capped, loopback-only
disposable Valkey container and repeat the store suite. Automatic CI wiring is
not included in this PR because the publishing account lacks workflow access.
Coverage includes
concurrent enrollment, revocation/restriction races, exact-byte comparisons,
absence versus empty strings, TTL retention, all-or-none conflicts, type errors,
cancellation, and concurrent single winners. Do not point test switches at an
application store. This source change does not revoke existing credentials or
change live configuration.
