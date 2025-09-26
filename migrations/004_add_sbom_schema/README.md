# Migration 004: Add SBOM and System Fingerprinting Schema

This migration extends the `hosts` table with three new JSONB columns to support comprehensive Software Bill of Materials (SBOM) and system fingerprinting capabilities.

## Changes Made

### New Columns Added

- **`software_inventory`** (JSONB): Stores package information, certificates, and scan metadata
- **`system_fingerprint`** (JSONB): Stores hardware, network, user, and service information
- **`agent_metadata`** (JSONB): Stores agent version, capabilities, and configuration

### Indexes Created

- GIN indexes on all JSONB columns for efficient querying
- Specific indexes for common query paths (packages, hardware, network, agent version)
- B-tree indexes for agent version and last contact timestamp

## JSONB Schema Documentation

### 1. software_inventory

```json
{
  "scan_metadata": {
    "agent_version": "1.2.0",
    "scan_date": "2024-01-15T10:30:00Z",
    "scan_duration_ms": 5432,
    "scan_modules": ["packages", "certificates", "services"]
  },
  "packages": [
    {
      "name": "nginx",
      "version": "1.18.0-6ubuntu14.4",
      "source": "dpkg",
      "architecture": "amd64",
      "install_date": "2023-06-15T08:22:00Z",
      "size_bytes": 1048576,
      "description": "High performance web server",
      "dependencies": ["libc6", "libssl1.1"],
      "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    }
  ],
  "certificates": [
    {
      "store": "system",
      "subject": "CN=*.example.com",
      "issuer": "CN=DigiCert SHA2 High Assurance Server CA",
      "serial": "0A1B2C3D4E5F6789",
      "expires": "2024-12-31T23:59:59Z",
      "fingerprint_sha256": "abc123def456...",
      "key_usage": ["digital_signature", "key_encipherment"],
      "san": ["example.com", "www.example.com"]
    }
  ]
}
```

### 2. system_fingerprint

```json
{
  "hardware": {
    "cpu": {
      "model": "Intel Core i7-9700K",
      "cores": 8,
      "architecture": "x86_64"
    },
    "memory": {
      "total_gb": 16,
      "available_gb": 8.5
    },
    "storage": [
      {
        "device": "/dev/sda1",
        "size_gb": 500,
        "type": "SSD",
        "filesystem": "ext4"
      }
    ]
  },
  "network": {
    "interfaces": [
      {
        "name": "eth0",
        "mac": "00:1B:44:11:3A:B7",
        "ipv4": ["192.168.1.100"],
        "ipv6": ["fe80::21b:44ff:fe11:3ab7"]
      }
    ],
    "dns_servers": ["8.8.8.8", "8.8.4.4"]
  },
  "users": [
    {
      "username": "admin",
      "uid": 1000,
      "gid": 1000,
      "shell": "/bin/bash",
      "home": "/home/admin",
      "groups": ["sudo", "docker"]
    }
  ],
  "services": [
    {
      "name": "nginx",
      "status": "running",
      "pid": 1234,
      "start_time": "2024-01-15T10:00:00Z",
      "version": "1.18.0"
    }
  ]
}
```

### 3. agent_metadata

```json
{
  "last_agent_contact": "2024-01-15T10:30:00Z",
  "agent_version": "1.2.0",
  "capabilities": [
    "package_scan",
    "fingerprint_scan",
    "template_detection",
    "script_execution"
  ],
  "configuration": {
    "scan_interval_hours": 24,
    "enable_template_detection": true,
    "enable_script_detection": false,
    "max_scan_duration_minutes": 60
  }
}
```

## Usage Instructions

### Running the Migration

```bash
# Navigate to the go-api directory
cd go-api

# Run the migration
go run migrations/004_add_sbom_schema/main.go
```

### Rolling Back the Migration

```bash
# Navigate to the go-api directory
cd go-api

# Run the rollback
go run migrations/004_add_sbom_schema/rollback/main.go
```

## Common JSONB Queries

### Query Examples

```sql
-- Find hosts with specific package installed
SELECT ip, hostname
FROM hosts
WHERE software_inventory -> 'packages' @> '[{"name": "nginx"}]';

-- Find hosts by CPU architecture
SELECT ip, hostname
FROM hosts
WHERE system_fingerprint -> 'hardware' -> 'cpu' ->> 'architecture' = 'x86_64';

-- Find hosts by agent version
SELECT ip, hostname, agent_metadata ->> 'agent_version' as agent_version
FROM hosts
WHERE agent_metadata ->> 'agent_version' = '1.2.0';

-- Find hosts with expired certificates
SELECT ip, hostname
FROM hosts,
jsonb_array_elements(software_inventory -> 'certificates') as cert
WHERE (cert ->> 'expires')::timestamp < NOW();

-- Find hosts with specific capabilities
SELECT ip, hostname
FROM hosts
WHERE agent_metadata -> 'capabilities' ? 'template_detection';
```

### Performance Considerations

- Use GIN indexes for complex JSONB queries
- Use B-tree indexes for simple key extraction (`->>` operator)
- Consider using `EXPLAIN ANALYZE` to verify query performance
- For large datasets, consider additional partial indexes on commonly queried fields

## Migration Safety

- ✅ **Backward Compatible**: Existing functionality is preserved
- ✅ **Rollback Support**: Complete rollback capability with verification
- ✅ **Data Preservation**: All existing host data is maintained
- ✅ **Index Optimization**: Efficient querying support added
- ✅ **Constraint Validation**: JSONB columns have proper constraints

## Testing

### Automated Test Suite

```bash
# Run comprehensive JSONB schema tests
cd go-api
go run migrations/004_add_sbom_schema/test/main.go
```

### Manual Testing

```bash
# Test column creation
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'hosts'
AND column_name IN ('software_inventory', 'system_fingerprint', 'agent_metadata');

# Test JSONB constraints
INSERT INTO hosts (ip, hostname, software_inventory, system_fingerprint, agent_metadata)
VALUES ('192.168.1.1', 'test', '{}', '{}', '{}');

# Test index usage
EXPLAIN ANALYZE
SELECT * FROM hosts
WHERE software_inventory -> 'packages' @> '[{"name": "test"}]';
```

## Migration Log Reference

The migration creates a `migration_004_rollback_info` table to track changes for safe rollback:

```sql
CREATE TABLE migration_004_rollback_info (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(255),
    column_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
```

This table is automatically cleaned up during rollback operations.
