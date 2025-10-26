# Sirius Go API SDK

> A shared Go library for the Sirius vulnerability scanning platform, providing core data models, database operations, and service integrations.

[![Go Version](https://img.shields.io/github/go-mod/go-version/SiriusScan/go-api)](https://github.com/SiriusScan/go-api)
[![Latest Release](https://img.shields.io/github/v/release/SiriusScan/go-api)](https://github.com/SiriusScan/go-api/releases/latest)
[![License](https://img.shields.io/github/license/SiriusScan/go-api)](LICENSE)

## Overview

The **Sirius Go API SDK** provides a unified interface for:

- **Core Data Models**: Host, Port, Vulnerability, Service structures
- **Database Operations**: PostgreSQL via GORM ORM
- **Message Queue**: RabbitMQ pub/sub integration
- **Key-Value Store**: ValKey/Redis operations
- **NVD Integration**: CVE data enrichment from National Vulnerability Database
- **Source Attribution**: Track which tool found each piece of data

## Installation

```bash
go get github.com/SiriusScan/go-api@latest
```

## Quick Start

```go
package main

import (
    "github.com/SiriusScan/go-api/sirius"
    "github.com/SiriusScan/go-api/sirius/host"
    "github.com/SiriusScan/go-api/sirius/postgres"
)

func main() {
    // Initialize database connection
    if err := postgres.InitDB(); err != nil {
        panic(err)
    }

    // Create host data
    hostData := sirius.Host{
        IP:       "192.168.1.100",
        Hostname: "server.local",
        Ports: []sirius.Port{
            {Number: 22, Protocol: "tcp", State: "open"},
            {Number: 80, Protocol: "tcp", State: "open"},
        },
    }

    // Add host to database
    if err := host.AddHost(hostData); err != nil {
        panic(err)
    }

    // Retrieve host
    retrieved, err := host.GetHost("192.168.1.100")
    if err != nil {
        panic(err)
    }

    println("Found host:", retrieved.IP)
}
```

## Features

### Core Data Models

```go
type Host struct {
    HID             string
    OS              string
    OSVersion       string
    IP              string
    Hostname        string
    Ports           []Port
    Services        []Service
    Vulnerabilities []Vulnerability
    CPE             []string
    Agent           *SiriusAgent
}

type Port struct {
    Number   int    `json:"number"`   // Port number (22, 80, 443)
    Protocol string `json:"protocol"` // tcp, udp
    State    string `json:"state"`    // open, closed, filtered
}

type Vulnerability struct {
    VID         string  `json:"vid"`         // CVE ID
    Title       string  `json:"title"`
    Description string  `json:"description"`
    RiskScore   float64 `json:"risk_score"`  // CVSS score
}
```

### Database Operations

```go
import "github.com/SiriusScan/go-api/sirius/host"

// Add or update host
err := host.AddHost(hostData)

// Get host by IP
hostData, err := host.GetHost("192.168.1.100")

// Get all hosts
hosts, err := host.GetAllHosts()

// Delete host
err := host.DeleteHost("192.168.1.100")
```

### Source Attribution

Track which tool discovered each finding:

```go
import (
    "github.com/SiriusScan/go-api/sirius/host"
    "github.com/SiriusScan/go-api/sirius/postgres/models"
)

// Define scan source
source := models.ScanSource{
    Name:    "nmap",
    Version: "7.94",
    Config:  "ports:1-1000;template:quick",
}

// Add host with source attribution
err := host.AddHostWithSource(hostData, source)

// Get host with source history
hostWithSources, err := host.GetHostWithSources("192.168.1.100")
```

### Message Queue

```go
import "github.com/SiriusScan/go-api/sirius/queue"

// Publish message
err := queue.Publish("scan", scanMessage)

// Listen for messages
queue.Listen("scan", func(msg string) {
    // Process message
})
```

### Key-Value Store

```go
import "github.com/SiriusScan/go-api/sirius/store"

// Set value
err := store.SetValue(ctx, "key", "value")

// Get value
value, err := store.GetValue(ctx, "key")

// Delete value
err := store.DeleteValue(ctx, "key")
```

## Configuration

### Environment Variables

#### Database (PostgreSQL)
```bash
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_NAME=sirius
```

#### Message Queue (RabbitMQ)
```bash
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
```

#### Key-Value Store (ValKey/Redis)
```bash
VALKEY_HOST=localhost
VALKEY_PORT=6379
```

## Development

### Local Development with Replace Directive

For projects in the same repository or local development:

**go.mod:**
```go
module github.com/SiriusScan/your-project

// Use local SDK for development
replace github.com/SiriusScan/go-api => ../go-api

require (
    github.com/SiriusScan/go-api v0.0.11
)
```

**Benefits:**
- Test SDK changes immediately
- No need to publish for every change
- Easy cross-project debugging

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./sirius/postgres/...
```

### Building

```bash
# Build all packages
go build ./...

# Verify no issues
go vet ./...

# Format code
gofmt -w .
```

## Releasing New Versions

### Automatic Release (Recommended)

Push to `main` branch to trigger automatic release:

```bash
# Commit changes
git add .
git commit -m "feat: add new feature"
git push origin main

# CI/CD automatically:
# 1. Runs tests and linting
# 2. Creates new patch version (v0.0.10 → v0.0.11)
# 3. Generates GitHub release
# 4. Notifies dependent projects
```

### Manual Release

Create and push a Git tag:

```bash
# Create tag
git tag v0.1.0

# Push tag
git push origin v0.1.0

# CI/CD creates GitHub release automatically
```

### Using Automation Scripts

**Check versions across projects:**
```bash
./scripts/check-versions.sh
```

**Update all dependent projects:**
```bash
./scripts/update-dependents.sh v0.0.11
```

## Documentation

### Comprehensive Guides

- **[SDK Architecture](../../Sirius/documentation/dev/architecture/README.go-api-sdk.md)** - Design, patterns, and integration
- **[Release Process](../../Sirius/documentation/dev/operations/README.sdk-releases.md)** - How to release and update
- **[CHANGELOG](CHANGELOG.md)** - Version history and breaking changes
- **[API Documentation](docs/documentation.md)** - Detailed API reference

## Breaking Changes

### v0.0.11 (Latest)

**Port.ID → Port.Number**
- `Port.ID` field renamed to `Port.Number` to resolve database conflicts
- Migration required for existing databases
- See [CHANGELOG](CHANGELOG.md) for migration guide

**Before:**
```go
port := sirius.Port{
    ID:       22,
    Protocol: "tcp",
}
```

**After:**
```go
port := sirius.Port{
    Number:   22,
    Protocol: "tcp",
}
```

## Projects Using This SDK

- **[app-scanner](../app-scanner)** - Port scanning and service detection engine
- **[app-agent](../app-agent)** - Agent management and command execution
- **sirius-api** - REST API server (via Docker container)
- **sirius-engine** - Core scanning orchestration (via Docker container)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Guidelines:**
- Follow Go idioms and best practices
- Add tests for new features
- Update documentation
- Use [conventional commits](https://www.conventionalcommits.org/)

## Support

- **Issues**: [GitHub Issues](https://github.com/SiriusScan/go-api/issues)
- **Documentation**: [SDK Docs](../../Sirius/documentation/dev/architecture/README.go-api-sdk.md)
- **Release Process**: [Release Guide](../../Sirius/documentation/dev/operations/README.sdk-releases.md)

## License

This project is licensed under the terms specified in [LICENSE](LICENSE).

## Changelog

For a detailed list of changes, see [CHANGELOG.md](CHANGELOG.md).

---

**Current Version**: v0.0.11  
**Go Version**: 1.23+  
**Maintained by**: Sirius Team
