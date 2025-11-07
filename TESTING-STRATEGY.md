# Repository Pattern Testing Strategy

## Problem
The circular references in GORM models were causing stack overflow errors during JSON serialization. Full integration testing through the scanner takes too long and is inefficient for validating the fix.

## Solution
Comprehensive unit tests that validate the repository pattern directly without requiring full scanner integration.

## Quick Test Command

```bash
# Inside sirius-engine container
docker exec sirius-engine sh -c "cd /go-api && ./test-circular-refs.sh"

# Or run tests directly
docker exec sirius-engine sh -c "cd /go-api && go test -v ./sirius/host -run TestRepository"
```

## Test Coverage

### `TestRepositoryCircularReferences`
Comprehensive test that validates:

1. **Write Operations** - Repository methods can persist hosts with ports and vulnerabilities
2. **Read Operations** - Repository methods can retrieve complete host data
3. **JSON Serialization** - Confirms NO circular references during marshaling
4. **Direct Repository Access** - HostWithRelations can be marshaled without errors
5. **Database Model Integrity** - Models themselves don't contain circular references
6. **Batch Operations** - GetAllHosts works without circular references

### `TestRepositoryUpsertOperations`
Individual operation tests:

- `UpsertHost` - Creates/updates host entities
- `UpsertPort` - Creates/updates port entities  
- `UpsertVulnerability` - Creates/updates vulnerability entities
- `LinkHostPort` - Links hosts to ports with source attribution
- `LinkHostVulnerability` - Links hosts to vulnerabilities with source attribution

## What Gets Tested

✅ **No Circular References** - JSON marshaling succeeds without stack overflow  
✅ **Complete Data Retrieval** - Ports and vulnerabilities are properly loaded  
✅ **Repository Pattern** - All CRUD operations work through repository  
✅ **Source Attribution** - Junction tables properly track scan sources  
✅ **JSONB Fields** - Software inventory and fingerprints work correctly  

## Testing Workflow

### Before Making Changes
```bash
# Run baseline tests
docker exec sirius-engine sh -c "cd /go-api && go test ./sirius/host -run TestRepository"
```

### After Making Changes
```bash
# Validate no circular references introduced
docker exec sirius-engine sh -c "cd /go-api && ./test-circular-refs.sh"

# If tests pass, restart API to load new code
docker compose restart sirius-api

# Then test via API
curl -X POST http://localhost:9001/host/with-source \
  -H "Content-Type: application/json" \
  -d '{"host":{"ip":"test.ip","ports":[{"number":80,"protocol":"tcp","state":"open"}]},"source":{"name":"test","version":"1.0"}}'

curl http://localhost:9001/host/test.ip
```

### Integration Testing (if needed)
```bash
# Only after unit tests pass
docker exec sirius-engine sh -c "cd /app-scanner && go build -o app-scanner ."
docker exec sirius-engine sh -c "cd /app-scanner && ./app-scanner --mode=discovery --hosts=scanme.nmap.org"
```

## Benefits

1. **Fast Feedback** - Tests run in <1 second vs minutes for full scanner integration
2. **Precise Validation** - Tests exactly what we need (circular references)
3. **No Rebuild Cycle** - Volume mounts mean code changes are immediate
4. **Comprehensive Coverage** - Tests write, read, and serialization paths
5. **Easy to Run** - Single command validates everything

## Test Output Example

```
✅ Database initialized and cleaned
✅ Successfully added host using repository pattern  
✅ Successfully retrieved host: 192.168.99.99
✅ JSON marshaling successful - NO CIRCULAR REFERENCES
  JSON size: 508 bytes
  Ports in JSON: 3
  Vulnerabilities in JSON: 2
✅ HostWithRelations JSON marshaling successful
✅ Database model marshaling successful  
✅ GetAllHosts JSON marshaling successful
============================================================
✅ ALL TESTS PASSED - NO CIRCULAR REFERENCES DETECTED
============================================================
```

## When to Use Each Testing Level

| Test Level | When to Use | Time |
|------------|-------------|------|
| Unit Tests (repository_test.go) | After ANY code change to models/repository | ~1s |
| API Tests (curl commands) | After confirming unit tests pass | ~5s |
| Scanner Integration | Final validation before deployment | ~30s+ |

## Troubleshooting

### If Tests Fail

1. **Check error message** - Usually points to specific function
2. **Verify column names** - Should be `h_id` not `hid`
3. **Check model definitions** - Ensure no `Ports []Port` or `Hosts []Host` fields
4. **Validate repository queries** - All SELECT statements should use explicit JOINs

### If JSON Marshaling Fails

This indicates circular references were reintroduced:
- Check if any `Preload()` calls were added back
- Verify models don't have bidirectional many2many relationships
- Ensure repository uses explicit SQL JOINs, not GORM associations

## File Locations

- **Tests**: `/go-api/sirius/host/repository_test.go`
- **Repository**: `/go-api/sirius/host/repository.go`
- **Models**: `/go-api/sirius/postgres/models/host.go`, `vulnerability.go`
- **Quick Test Script**: `/go-api/test-circular-refs.sh`


