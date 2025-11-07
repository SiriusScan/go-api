# Migration 006: Add Events Table

## Purpose

This migration adds the `events` table to PostgreSQL for storing security events and system activities. This replaces the temporary Valkey-based log storage with a persistent, queryable database solution.

## Changes

### New Table: `events`

Stores security events, scan activities, and system operations with:
- Unique event IDs for idempotency
- Timestamp-based ordering
- Service and subcomponent tracking
- Event type categorization (scan_started, host_discovered, etc.)
- Severity levels (info, warning, error, critical)
- JSONB metadata for flexible event data
- Entity linking (host, scan, vulnerability)

### Indexes

- `idx_events_timestamp`: Efficient time-based queries (DESC for recent-first)
- `idx_events_service`: Filter by service (sirius-scanner, sirius-api, etc.)
- `idx_events_type`: Filter by event type
- `idx_events_severity`: Filter by severity level
- `idx_events_entity`: Composite index for entity lookups

## Running the Migration

### Apply Migration

```bash
# From go-api directory
cd /Users/oz/Projects/Sirius-Project/minor-projects/go-api

# Run migration
go run migrations/006_add_events_table/main.go
```

### Rollback Migration

```bash
go run migrations/006_add_events_table/main.go --rollback
```

## Integration

After this migration:
1. The `events` table will be available for event storage
2. The go-api SDK logging package will dual-write to both Valkey and PostgreSQL
3. Dashboard can query events via new API endpoints
4. Historical event data will be retained (not limited to 1000 entries)

## Verification

```sql
-- Check table exists
\dt events

-- Check indexes
\di events*

-- View table structure
\d+ events

-- Query sample events
SELECT event_id, timestamp, service, event_type, severity, title
FROM events
ORDER BY timestamp DESC
LIMIT 10;
```

## Data Migration

This is a new table, so no data migration is required. Events will begin populating once:
1. Migration is applied
2. go-api SDK is updated with event persistence
3. Scanner and API are updated to emit events

## Performance Considerations

- Indexes optimize common query patterns (time, service, type, severity, entity)
- JSONB metadata allows flexible event data without schema changes
- Batch inserts (10 events buffered) minimize write overhead
- Consider implementing data retention policy after initial deployment

## Related Changes

This migration is part of the Event System PostgreSQL Migration project:
- Phase 1: Database Schema (this migration)
- Phase 2: SDK Logging Updates
- Phase 3: Scanner Event Emission
- Phase 4: API Event Emission
- Phase 5: REST API Endpoints
- Phase 6: Event Querying

## Rollback Plan

If issues arise:
1. Run migration with `--rollback` flag
2. SDK will continue writing to Valkey only
3. No data loss (events continue in Valkey)
4. Can re-run migration after fixes

