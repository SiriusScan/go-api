# Host Persistence Refactoring - Complete Summary

## Problem Solved

**Root Cause**: Circular references in GORM models causing stack overflow errors:
```
Failed to marshal log entry: json: unsupported value: encountered a cycle via map[string]interface {}
fatal error: stack overflow
```

This was happening because:
- `Host.Ports []Port` and `Port.Hosts []Host` created bidirectional many2many relationships
- `Host.Vulnerabilities []Vulnerability` and `Vulnerability.Hosts []Host` had the same issue
- GORM's eager loading (Preload) would attempt to load these relationships recursively
- JSON marshaling would then encounter infinite loops

## Solution Implemented

### 1. Repository Pattern
Created `sirius/host/repository.go` with centralized persistence logic:

**Core Methods:**
- `UpsertHost(ip, hostname, os, osVersion, hid)` - Create/update host entities
- `UpsertPort(number, protocol, state)` - Create/update port entities
- `UpsertVulnerability(vid, title, description, riskScore)` - Create/update vulnerability entities
- `LinkHostPort(hostID, portID, source)` - Link hosts to ports with source attribution
- `LinkHostVulnerability(hostID, vulnID, source)` - Link hosts to vulnerabilities with source attribution
- `GetHostWithRelations(ip)` - Retrieve host with explicit JOINs
- `GetAllHostsWithRelations()` - Retrieve all hosts with explicit JOINs
- `UpdateHostJSONB(hostID, softwareInventory, systemFingerprint, agentMetadata)` - Update JSONB fields

### 2. Model Changes

**Removed from `models.Host`:**
```go
// REMOVED: Ports []Port `gorm:"many2many:host_ports"` 
// REMOVED: Vulnerabilities []Vulnerability `gorm:"many2many:host_vulnerabilities"`
```

**Kept explicit junction tables:**
```go
HostVulnerabilities []HostVulnerability `gorm:"foreignKey:HostID"`
HostPorts           []HostPort          `gorm:"foreignKey:HostID"`
```

**Removed from `models.Port` and `models.Vulnerability`:**
```go
// REMOVED: Hosts []Host `gorm:"many2many:host_ports"`
// REMOVED: Hosts []Host `gorm:"many2many:host_vulnerabilities"`
```

### 3. Refactored Functions

**Write Path (`source_aware.go`):**
- `AddHostWithSource()` - Now uses repository methods instead of `MapSiriusHostToDBHost`
- `AddHostWithSourceAndJSONB()` - Uses repository with JSONB field updates

**Read Path (`host.go`):**
- `GetHost()` - Uses `repo.GetHostWithRelations()` with explicit SQL JOINs
- `GetAllHosts()` - Uses `repo.GetAllHostsWithRelations()`
- `AddHost()` - Uses repository pattern
- `GetHostWithEnhancedData()` - Uses repository pattern

**Removed Obsolete Functions:**
- `MapSiriusHostToDBHost()` - No longer needed, repository handles entity mapping
- `UpdatePortsWithSource()` - Replaced by `repo.LinkHostPort()`
- `UpdateVulnerabilitiesWithSource()` - Replaced by `repo.LinkHostVulnerability()`
- `MapDBHostToSiriusHost()` - Replaced by `convertHostWithRelationsToSiriusHost()`

## Validation Strategy

### Quick Unit Tests (< 1 second)
```bash
docker exec sirius-engine sh -c "cd /go-api && ./test-circular-refs.sh"
```

**Tests validate:**
✅ Write operations work without circular references  
✅ Read operations properly load ports and vulnerabilities  
✅ JSON marshaling succeeds (no stack overflow)  
✅ Direct repository access works correctly  
✅ Database models have no circular references  
✅ Batch operations (GetAllHosts) work correctly  

### API Testing (~ 5 seconds)
```bash
# Add host with source
curl -X POST http://localhost:9001/host/with-source \
  -H "Content-Type: application/json" \
  -d '{"host":{"ip":"test","ports":[...],"vulnerabilities":[...]},"source":{"name":"test"}}'

# Retrieve host
curl http://localhost:9001/host/test

# Check statistics
curl http://localhost:9001/statistics/most-vulnerable-hosts
```

### Scanner Integration (~ 30 seconds)
```bash
docker exec sirius-engine sh -c "cd /app-scanner && ./app-scanner --mode=discovery --hosts=target"
```

## Test Results

### ✅ Unit Tests: PASSED
```
✅ Successfully added host using repository pattern  
✅ JSON marshaling successful - NO CIRCULAR REFERENCES
✅ HostWithRelations JSON marshaling successful
✅ Database model marshaling successful  
✅ GetAllHosts JSON marshaling successful
============================================================
✅ ALL TESTS PASSED - NO CIRCULAR REFERENCES DETECTED
============================================================
```

### ✅ API Tests: PASSED
```json
{
    "ip": "192.168.1.200",
    "hostname": "quick-test",
    "ports": [
        {"number": 22, "protocol": "tcp", "state": "open"},
        {"number": 443, "protocol": "tcp", "state": "open"}
    ],
    "vulnerabilities": [
        {"vid": "CVE-2024-QUICK", "title": "Quick Test Vuln"}
    ]
}
```

### ✅ Scanner Integration: PASSED
No stack overflow errors during scanning operations.

## Files Changed

### New Files
- `sirius/host/repository.go` - Repository pattern implementation
- `sirius/host/repository_test.go` - Comprehensive unit tests
- `test-circular-refs.sh` - Quick test script
- `TESTING-STRATEGY.md` - Testing documentation
- `REFACTORING-SUMMARY.md` - This file

### Modified Files
- `sirius/postgres/models/host.go` - Removed circular associations
- `sirius/postgres/models/vulnerability.go` - Removed circular associations
- `sirius/host/source_aware.go` - Refactored to use repository pattern
- `sirius/host/host.go` - Refactored to use repository pattern

## Benefits

1. **No More Stack Overflows** - Circular references eliminated
2. **Explicit Control** - Manual JOIN queries prevent unexpected eager loading
3. **Better Performance** - Only load data that's actually needed
4. **Easier Testing** - Repository pattern allows comprehensive unit testing
5. **Maintainability** - Centralized persistence logic in one place
6. **Source Attribution** - Properly tracks which scanner found which data
7. **Fast Validation** - Unit tests provide <1s feedback cycle

## Migration Notes

### For Future Development

**✅ DO:**
- Use repository methods for all host persistence operations
- Add new methods to `HostRepository` for new features
- Run unit tests after any model or repository changes
- Use explicit JOINs when querying related data

**❌ DON'T:**
- Add `Ports []Port` or `Vulnerabilities []Vulnerability` back to `Host` model
- Add `Hosts []Host` back to `Port` or `Vulnerability` models
- Use GORM's `Preload()` for many2many relationships
- Skip unit tests when making repository changes

### Testing Workflow

1. Make code changes
2. Run quick unit tests: `docker exec sirius-engine sh -c "cd /go-api && ./test-circular-refs.sh"`
3. If tests pass, restart API: `docker compose restart sirius-api`
4. Test via API endpoints
5. Only run full scanner integration if needed

## Performance Notes

- **Unit tests**: < 1 second
- **API tests**: ~ 5 seconds  
- **Scanner integration**: ~ 30 seconds
- **Database queries**: Still use efficient JOINs and indexes

## Future Enhancements

Consider adding:
- [ ] Repository method for batch host operations
- [ ] Caching layer in repository for frequently accessed hosts
- [ ] Pagination support in `GetAllHostsWithRelations`
- [ ] Repository metrics (query counts, timing)
- [ ] Additional validation tests for edge cases

## Questions?

See:
- `TESTING-STRATEGY.md` - Detailed testing documentation
- `repository_test.go` - Test implementation examples
- `repository.go` - Repository pattern implementation

---

**Status**: ✅ Refactoring Complete and Validated  
**Date**: 2025-11-03  
**Tests**: All Passing  
**Circular References**: ELIMINATED





