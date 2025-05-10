# Sirius Go API Documentation

## Table of Contents

- [Overview](#overview)
- [Installation & Import](#installation--import)
- [Database](#database)
  - [Connection Management](#connection-management)
  - [Models](#models)
- [Host Management](#host-management)
- [Vulnerability Management](#vulnerability-management)
- [Queue System](#queue-system)
- [Key-Value Store](#key-value-store)
- [NVD Integration](#nvd-integration)

## Overview

The Sirius Go API provides a comprehensive backend system for vulnerability scanning and management. It integrates with various services including PostgreSQL for data persistence, RabbitMQ for message queuing, and the National Vulnerability Database (NVD) for vulnerability data.

## Installation & Import

### Installing the Package

```bash
go get github.com/SiriusScan/go-api
```

### Basic Imports

```go
// Core packages
import (
    "github.com/SiriusScan/go-api/sirius"
    "github.com/SiriusScan/go-api/sirius/postgres"
)

// Feature-specific packages
import (
    "github.com/SiriusScan/go-api/sirius/host"
    "github.com/SiriusScan/go-api/sirius/vulnerability"
    "github.com/SiriusScan/go-api/sirius/queue"
    "github.com/SiriusScan/go-api/sirius/store"
    "github.com/SiriusScan/go-api/nvd"
)
```

### Package Organization

```
go-api/
├── sirius/
│   ├── postgres/     # Database operations
│   ├── host/        # Host management
│   ├── vulnerability/ # Vulnerability operations
│   ├── queue/       # RabbitMQ integration
│   └── store/       # Key-value store
└── nvd/            # NVD API integration
```

### Basic Usage Example

```go
package main

import (
    "log"
    "github.com/SiriusScan/go-api/sirius/postgres"
    "github.com/SiriusScan/go-api/sirius/host"
)

func main() {
    // Initialize database connection
    db := postgres.GetDB()
    if db == nil {
        log.Fatal("Failed to connect to database")
    }

    // Example: Get host information
    hostInfo, err := host.GetHost("192.168.1.1")
    if err != nil {
        log.Printf("Error getting host: %v", err)
    }
}
```

## Database

### Connection Management

The database connection is managed through the `postgres` package, specifically in `connection.go`.

```go
// GetDB returns the database connection, initializing it if necessary
func GetDB() *gorm.DB

// IsConnected returns whether the database is connected
func IsConnected() bool

// GetConnectionError returns the last connection error
func GetConnectionError() error
```

Key Features:

- Automatic connection retry with exponential backoff
- Environment-aware configuration (Docker vs local)
- Automatic schema initialization and migration
- Connection pooling via GORM

### Models

The database models are defined in the `models` package and include:

- Host
- Vulnerability
- Port
- Service
- Note
- CPE
- Various CVE-related models

## Host Management

The `host` package (`host.go`) provides functionality for managing host information:

```go
// GetHost retrieves a host by IP address
func GetHost(ip string) (sirius.Host, error)

// GetAllHosts retrieves all hosts from the database
func GetAllHosts() ([]sirius.Host, error)

// AddHost adds or updates a host in the database
func AddHost(host sirius.Host) error

// DeleteHost removes a host from the database
func DeleteHost(ip string) error
```

Additional Features:

- Host vulnerability statistics
- Port and service management
- Risk scoring and metrics

## Vulnerability Management

The `vulnerability` package (`vulnerability.go`) handles vulnerability data:

```go
// GetVulnerability retrieves vulnerability information by ID
func GetVulnerability(vid string) (nvd.CveItem, error)

// CheckVulnerabilityExists checks if a vulnerability exists
func CheckVulnerabilityExists(vid string) bool

// AddVulnerability adds a new vulnerability to the database
func AddVulnerability(vuln sirius.Vulnerability) error

// DeleteVulnerability removes a vulnerability from the database
func DeleteVulnerability(vid string) error
```

## Queue System

The `queue` package (`queue.go`) provides RabbitMQ integration:

```go
// MessageProcessor is a type for functions that can process messages
type MessageProcessor func(msg string)

// Listen listens to a RabbitMQ queue and processes messages
func Listen(qName string, messageProcessor MessageProcessor)

// Send sends a message to a RabbitMQ queue
func Send(qName string, message string) error
```

Features:

- Automatic queue declaration
- Message processing in goroutines
- Error handling and logging

## Key-Value Store

The `store` package (`store.go`) provides a key-value store interface:

```go
// KVStore defines the key/value operations
type KVStore interface {
    SetValue(ctx context.Context, key, value string) error
    GetValue(ctx context.Context, key string) (ValkeyResponse, error)
    Close() error
}
```

Implementation:

- Uses Valkey as the backend store
- Supports JSON serialization
- Context-aware operations

## NVD Integration

The `nvd` package (`nvd.go`) provides integration with the National Vulnerability Database:

```go
// GetCVE retrieves CVE information from NVD
func GetCVE(vid string) (CveItem, error)
```

Supported Data Types:

- CVSS v2.0, v3.0, v3.1, and v4.0 metrics
- Vulnerability descriptions
- References and weaknesses
- Vendor comments
- CPE configurations

### CVE Data Structures

The package includes comprehensive type definitions for NVD data:

```go
type CveItem struct {
    ID              string
    SourceIdentifier string
    VulnStatus      string
    Published       string
    LastModified    string
    Descriptions    []LangString
    References      []Reference
    Metrics         Metrics
    // ... additional fields
}
```

## Advanced Usage Examples

### Scanning a Host for Vulnerabilities

```go
package main

import (
    "context"
    "log"
    "github.com/SiriusScan/go-api/sirius"
    "github.com/SiriusScan/go-api/sirius/host"
    "github.com/SiriusScan/go-api/sirius/vulnerability"
)

func scanHost() {
    // Create a new host
    newHost := sirius.Host{
        IP: "192.168.1.1",
        OS: "Linux",
        OSVersion: "Ubuntu 20.04",
    }

    // Add host to database
    if err := host.AddHost(newHost); err != nil {
        log.Fatalf("Failed to add host: %v", err)
    }

    // Get vulnerability statistics
    stats, err := host.GetHostRiskStatistics(newHost.IP)
    if err != nil {
        log.Printf("Error getting risk stats: %v", err)
    }

    log.Printf("Host vulnerability count: %d", stats.VulnerabilityCount)
}
```

### Using the Message Queue

```go
package main

import (
    "log"
    "github.com/SiriusScan/go-api/sirius/queue"
)

func processMessages() {
    // Define message processor
    processor := func(msg string) {
        log.Printf("Processing message: %s", msg)
    }

    // Start listening for messages
    queue.Listen("scan-queue", processor)

    // Send a message
    if err := queue.Send("scan-queue", "Start scan"); err != nil {
        log.Printf("Error sending message: %v", err)
    }
}
```

### Working with the Key-Value Store

```go
package main

import (
    "context"
    "log"
    "github.com/SiriusScan/go-api/sirius/store"
)

func useKeyValueStore() {
    // Create new store
    kvStore, err := store.NewValkeyStore()
    if err != nil {
        log.Fatalf("Failed to create store: %v", err)
    }
    defer kvStore.Close()

    ctx := context.Background()

    // Store a value
    if err := kvStore.SetValue(ctx, "scan-status", "running"); err != nil {
        log.Printf("Error setting value: %v", err)
    }

    // Retrieve a value
    val, err := kvStore.GetValue(ctx, "scan-status")
    if err != nil {
        log.Printf("Error getting value: %v", err)
    }
}
```

## Usage Examples

### Adding a New Host

```go
host := sirius.Host{
    IP: "192.168.1.1",
    Hostname: "example-host",
    OS: "Linux",
    OSVersion: "Ubuntu 20.04",
}
err := host.AddHost(host)
```

### Processing Queue Messages

```go
queue.Listen("scan-queue", func(msg string) {
    // Process the message
    log.Printf("Received message: %s", msg)
})
```

### Retrieving Vulnerability Data

```go
cve, err := vulnerability.GetVulnerability("CVE-2021-1234")
if err != nil {
    log.Printf("Error retrieving vulnerability: %v", err)
}
```

## Error Handling

The API uses standard Go error handling patterns:

- Functions return errors as second return values
- Database operations wrap underlying errors with context
- Queue operations use the failOnError helper for critical errors

## Configuration

The API can be configured through environment variables:

- `DB_HOST`: Database host address
- `SIRIUS_RABBITMQ`: RabbitMQ connection string
- `SIRIUS_VALKEY`: Valkey store connection string

## Best Practices

When using the API:

1. Always check error returns
2. Close resources (database connections, queues) when done
3. Use appropriate context for cancellation
4. Handle database reconnection scenarios
5. Implement proper logging and monitoring
