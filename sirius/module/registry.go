package module

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Registry holds compile-time registered Modules and mounts them onto an app.
type Registry struct {
	modules []Module
	byID    map[string]Module
}

// NewRegistry returns an empty module registry.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]Module)}
}

// Register adds a module. Duplicate IDs are rejected.
func (r *Registry) Register(m Module) error {
	if r == nil {
		return fmt.Errorf("module: nil registry")
	}
	if m == nil {
		return fmt.Errorf("module: nil module")
	}
	id := m.ID()
	if id == "" {
		return fmt.Errorf("module: empty module ID")
	}
	if _, exists := r.byID[id]; exists {
		return fmt.Errorf("module: duplicate module ID %q", id)
	}
	r.byID[id] = m
	r.modules = append(r.modules, m)
	return nil
}

// Modules returns registered modules in registration order.
func (r *Registry) Modules() []Module {
	if r == nil {
		return nil
	}
	out := make([]Module, len(r.modules))
	copy(out, r.modules)
	return out
}

// ModuleIDs returns registered module IDs in registration order.
func (r *Registry) ModuleIDs() []string {
	mods := r.Modules()
	ids := make([]string, 0, len(mods))
	for _, m := range mods {
		ids = append(ids, m.ID())
	}
	return ids
}

// Mount registers routes, jobs, and event handlers for all modules.
// jobs/events may be nil (treated as no-op registrars).
func (r *Registry) Mount(app *fiber.App, jobs JobRegistrar, events EventRegistrar) error {
	if r == nil {
		return fmt.Errorf("module: nil registry")
	}
	if app == nil {
		return fmt.Errorf("module: nil app")
	}
	if jobs == nil {
		jobs = NoopJobRegistrar{}
	}
	if events == nil {
		events = NoopEventRegistrar{}
	}
	for _, m := range r.modules {
		if err := m.RegisterRoutes(app); err != nil {
			return fmt.Errorf("module %q RegisterRoutes: %w", m.ID(), err)
		}
		if err := m.RegisterJobs(jobs); err != nil {
			return fmt.Errorf("module %q RegisterJobs: %w", m.ID(), err)
		}
		if err := m.RegisterEventHandlers(events); err != nil {
			return fmt.Errorf("module %q RegisterEventHandlers: %w", m.ID(), err)
		}
	}
	return nil
}

// Health aggregates per-module health reports keyed by module ID.
func (r *Registry) Health(ctx context.Context) map[string]HealthStatus {
	out := make(map[string]HealthStatus, len(r.modules))
	for _, m := range r.modules {
		out[m.ID()] = m.Health(ctx)
	}
	return out
}

// RouteInventory returns a deterministic METHOD\tPATH listing of registered
// Fiber routes (excluding Fiber's internal method-not-allowed handlers when
// distinguishable). Suitable for golden assertions.
func RouteInventory(app *fiber.App) []string {
	if app == nil {
		return nil
	}
	routes := app.GetRoutes(true)
	seen := make(map[string]struct{}, len(routes))
	out := make([]string, 0, len(routes))
	for _, rt := range routes {
		method := strings.ToUpper(strings.TrimSpace(rt.Method))
		path := rt.Path
		if method == "" || path == "" {
			continue
		}
		// Fiber auto-registers HEAD mirrors for GET routes; omit them so the
		// golden inventory stays maintainable and reflects declared routes.
		switch method {
		case "HEAD", "CONNECT", "TRACE":
			continue
		}
		key := method + "\t" + path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
