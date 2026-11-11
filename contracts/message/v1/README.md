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
