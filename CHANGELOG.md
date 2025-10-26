# Changelog

All notable changes to the Sirius Go API SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.11] - 2025-10-26

### Fixed

#### 🔴 CRITICAL: Port.ID Schema Conflict
- **BREAKING CHANGE:** Renamed `Port.ID` field to `Port.Number`
  - `Port.ID int` → `Port.Number int` (stores port number: 22, 80, 443, etc.)
  - Auto-increment `ID uint` from `gorm.Model` now used as primary key
  - Resolves duplicate key violations when same port appears on multiple hosts
  - Added unique constraint on `(number, protocol)` combination
- Updated all port-related functions to use `Number` field
- Updated database schema migration (005_fix_critical_schema_issues)

#### 🔴 HIGH: Vulnerability.VID Unique Constraint
- Added unique constraint on `vulnerabilities.v_id` column
- Prevents duplicate CVE entries in database
- Includes duplicate cleanup logic in migration

#### 🔴 HIGH: CVEDataMeta.ID Conflict
- **BREAKING CHANGE:** Renamed `CVEDataMeta.ID` to `CVEDataMeta.CVEIdentifier`
  - Resolves conflict with `gorm.Model.ID`
  - Prevents database schema corruption

#### 🟡 MEDIUM: Performance Indexes
- Added index on `vulnerabilities.v_id` (primary lookup field)
- Added index on `hosts.hostname` (common filter)
- Added index on `hosts.os` (common filter)
- Added composite index on `ports(number, protocol)`
- Expected 10-100x performance improvement on large datasets

#### 🟢 LOW: Code Cleanup
- Removed redundant `ID` declaration from `ScanHistoryEntry`
- Now properly uses `gorm.Model` for auto-increment ID

### Changed

- `sirius/postgres/models/host.go`: Port struct field rename
- `sirius/host/source_aware.go`: UpdatePortsWithSource queries by `number` instead of `id`
- `sirius/host/host.go`: Mapping functions updated for Port.Number
- `sirius/postgres/models/vulnerability.go`: CVEDataMeta.ID → CVEIdentifier
- `sirius/postgres/models/scan_source.go`: ScanHistoryEntry cleanup

### Migration

Database migration `005_fix_critical_schema_issues` includes:
- Port table schema transformation (id → number, new auto-increment id)
- Vulnerability VID unique constraint
- CVEDataMeta column rename
- Performance index creation
- Data preservation and backup

**Migration is idempotent and safe to run multiple times.**

### Upgrading

Projects using this SDK must update their code:

**Before:**
```go
port := sirius.Port{
    ID:       22,
    Protocol: "tcp",
    State:    "open",
}
```

**After:**
```go
port := sirius.Port{
    Number:   22,
    Protocol: "tcp",
    State:    "open",
}
```

See `SCHEMA-FIX-SUMMARY.md` for complete details.

## [0.0.10] - 2025-10-XX

### Added
- Previous features and changes

## [0.0.9] - 2025-10-XX

### Added
- Previous features and changes

---

[Unreleased]: https://github.com/SiriusScan/go-api/compare/v0.0.11...HEAD
[0.0.11]: https://github.com/SiriusScan/go-api/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/SiriusScan/go-api/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/SiriusScan/go-api/releases/tag/v0.0.9

