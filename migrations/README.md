# Database Migration: Fixing Model Relationships

This directory contains migration scripts for updating the database schema to properly support many-to-many relationships.

## Migration: 001_fix_relationships.go

This migration addresses the following issues in our data model:

1. **Port Model**: Previously, ports had a one-to-many relationship with hosts (one host has many ports),
   which prevented ports from being shared across multiple hosts. The migration updates this to a many-to-many
   relationship through a junction table called `host_ports`.

2. **Vulnerability Model**: Previously, vulnerabilities had conflicting relationship definitions:

   - A `HostID` field creating a one-to-many relationship
   - A `Hosts` field with a many-to-many relationship annotation

   The migration removes the `HostID` field to resolve this conflict.

## Running the Migration

To run the migration in a Docker container environment:

```bash
# Access the container shell
docker-compose exec api bash

# Navigate to the migrations directory
cd migrations

# Run the migration
go run 001_fix_relationships.go
```

## Data Preservation

The migration handles data preservation by:

1. Backing up existing relationships before schema changes
2. Creating appropriate entries in the junction tables based on the backed-up data
3. Removing redundant foreign key columns only after preserving relationships

## Verifying the Migration

After running the migration, you can verify that it was successful by:

1. Checking that the `host_ports` table has been created and populated
2. Verifying that the `host_vulnerabilities` table contains all expected relationships
3. Confirming that the `host_id` columns have been removed from both the `ports` and `vulnerabilities` tables

## Rollback

This migration doesn't include automatic rollback functionality. If you need to roll back:

1. Restore from a database backup taken before running the migration
2. Or manually recreate the `host_id` columns and populate them based on the junction tables

## Model Changes

The migration fixes these specific model changes:

### Port Model

```go
// Before
type Port struct {
    gorm.Model
    ID       int
    Protocol string
    State    string
    HostID   uint // Direct relationship to Host
}

// After
type Port struct {
    gorm.Model
    ID       int
    Protocol string
    State    string
    Hosts    []Host `gorm:"many2many:host_ports"` // Many-to-many relationship
}

// New junction table
type HostPort struct {
    gorm.Model
    HostID uint
    PortID uint
}
```

### Vulnerability Model

```go
// Before
type Vulnerability struct {
    gorm.Model
    VID         string
    Description string
    Title       string
    HostID      uint                // Conflicting relationship
    Hosts       []Host `gorm:"many2many:host_vulnerabilities"` // Conflicting relationship
    RiskScore   float64
}

// After
type Vulnerability struct {
    gorm.Model
    VID         string
    Description string
    Title       string
    // HostID field removed
    Hosts       []Host `gorm:"many2many:host_vulnerabilities"` // Only many-to-many remains
    RiskScore   float64
}
```

### Host Model

```go
// Before
type Host struct {
    // ... other fields
    Ports           []Port // One-to-many relationship
    Vulnerabilities []Vulnerability `gorm:"many2many:host_vulnerabilities"` // Many-to-many relationship
    // ... other fields
}

// After
type Host struct {
    // ... other fields
    Ports           []Port `gorm:"many2many:host_ports"` // Now many-to-many
    Vulnerabilities []Vulnerability `gorm:"many2many:host_vulnerabilities"` // Many-to-many relationship unchanged
    // ... other fields
}
```
