// Package module defines the versioned compile-time API Module contract and
// Community registration seam for Sirius API extension (ADR-004).
//
// Contracts are intentionally minimal and testable. Pro builds replace
// modules_community.go to register proprietary modules without runtime plugin
// loading. Licensing/entitlements are not implemented here; the capability
// middleware hook defaults to allow/no-op for Community.
package module

import (
	"context"

	"github.com/gofiber/fiber/v2"
)

// ContractVersion is the semantic version of this Module contract surface.
const ContractVersion = "v1"

// HealthStatus is a lightweight module health report.
type HealthStatus struct {
	Status  string            `json:"status"` // "ok", "degraded", or "error"
	Message string            `json:"message,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// JobFunc is a named background job entry point registered by a Module.
type JobFunc func(ctx context.Context) error

// JobRegistrar collects background jobs at startup. Community may use a no-op.
type JobRegistrar interface {
	RegisterJob(name string, job JobFunc) error
}

// EventHandler processes a typed event payload.
type EventHandler func(ctx context.Context, payload []byte) error

// EventRegistrar collects event handlers at startup. Community may use a no-op.
type EventRegistrar interface {
	RegisterHandler(eventType string, handler EventHandler) error
}

// Module is the versioned compile-time extension contract for API surfaces.
// Implementations must be deterministic and free of runtime plugin loading.
type Module interface {
	ID() string
	Version() string
	RegisterRoutes(app *fiber.App) error
	RegisterJobs(reg JobRegistrar) error
	RegisterEventHandlers(reg EventRegistrar) error
	RequiredCapabilities() []string
	Health(ctx context.Context) HealthStatus
}

// Base provides no-op defaults for optional Module methods so adapters stay small.
type Base struct {
	ModuleID      string
	ModuleVersion string
	Capabilities  []string
}

// ID returns the module identifier.
func (b Base) ID() string { return b.ModuleID }

// Version returns the module version string.
func (b Base) Version() string { return b.ModuleVersion }

// RegisterJobs is a no-op default.
func (b Base) RegisterJobs(JobRegistrar) error { return nil }

// RegisterEventHandlers is a no-op default.
func (b Base) RegisterEventHandlers(EventRegistrar) error { return nil }

// RequiredCapabilities returns declared capability requirements (may be empty).
func (b Base) RequiredCapabilities() []string {
	if len(b.Capabilities) == 0 {
		return nil
	}
	out := make([]string, len(b.Capabilities))
	copy(out, b.Capabilities)
	return out
}

// Health reports ok by default.
func (b Base) Health(context.Context) HealthStatus {
	return HealthStatus{Status: "ok"}
}

// NoopJobRegistrar discards job registrations.
type NoopJobRegistrar struct{}

// RegisterJob implements JobRegistrar.
func (NoopJobRegistrar) RegisterJob(string, JobFunc) error { return nil }

// NoopEventRegistrar discards event handler registrations.
type NoopEventRegistrar struct{}

// RegisterHandler implements EventRegistrar.
func (NoopEventRegistrar) RegisterHandler(string, EventHandler) error { return nil }
