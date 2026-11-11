# Queue contracts v1

The envelope and scan job schemas are versioned independently. The supported
scan request type is `sirius.scan.requested`, with spec and schema version `1.0`.
`id` identifies a message, `correlation_id` an operation, `causation_id` its
immediate cause, and `idempotency_key` the logical effect across retries.
Scope is optional and must be authorized before publication. Missing scope is
global. Consumers ignore additive fields and reject unsupported versions.

Queues may redeliver. Consumers must use idempotency keys or business keys;
acknowledge only after required effects commit when manual acknowledgements are
available, retain the same idempotency key on retries, and route poison messages
to an error/dead-letter path. Delivery is not exactly once. Scope attribution is
not itself authorization.

`ReplyRouter` creates a unique correlation ID for each request and dispatches
responses by that ID. Supply a reply destination exclusive to the client, or
share a destination only when one consumer routes every delivery through the
same router. Cancel the wait if publishing fails. Duplicate, late and unknown
replies are rejected. The router is an in-process correlation helper; transport
setup, durable delivery and acknowledgements remain the caller's responsibility.

The fixture suite validates positive and negative examples against the checked-in
schemas on every `go test` run. Optional fields can be added within v1; breaking
changes require a new major version.
