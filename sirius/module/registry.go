package module

import (
	"context"
	"fmt"
	"sync"

	"github.com/gofiber/fiber/v2"
)

type registryState int

const (
	registryOpen registryState = iota
	registryMounting
	registryMounted
)

func (s registryState) String() string {
	switch s {
	case registryOpen:
		return "open"
	case registryMounting:
		return "mounting"
	case registryMounted:
		return "mounted"
	default:
		return fmt.Sprintf("registryState(%d)", int(s))
	}
}

// Registry holds compile-time registered Modules and mounts them onto an app.
//
// Lifecycle: Register/RegisterAll are allowed only while open; Mount may succeed
// exactly once. Module callbacks run without holding the registry lock.
type Registry struct {
	mu      sync.Mutex
	state   registryState
	modules []Module
	byID    map[string]Module
}

// NewRegistry returns an empty module registry.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]Module)}
}

// Register adds a module. Duplicate IDs and nil/typed-nil modules are rejected.
// Registration is refused after Mount starts or completes.
func (r *Registry) Register(m Module) error {
	return r.RegisterAll(m)
}

// RegisterAll validates the entire batch, then appends all modules or none.
func (r *Registry) RegisterAll(modules ...Module) error {
	if r == nil {
		return fmt.Errorf("module: nil registry")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != registryOpen {
		return fmt.Errorf("module: registration not allowed in state %s", r.state)
	}

	pending := make(map[string]struct{}, len(modules))
	for i, m := range modules {
		if isNilInterface(m) {
			return fmt.Errorf("module: nil module at index %d", i)
		}
		id := m.ID()
		if id == "" {
			return fmt.Errorf("module: empty module ID at index %d", i)
		}
		if _, exists := r.byID[id]; exists {
			return fmt.Errorf("module: duplicate module ID %q", id)
		}
		if _, exists := pending[id]; exists {
			return fmt.Errorf("module: duplicate module ID %q in batch", id)
		}
		pending[id] = struct{}{}
	}

	for _, m := range modules {
		r.byID[m.ID()] = m
		r.modules = append(r.modules, m)
	}
	return nil
}

// Modules returns registered modules in registration order.
func (r *Registry) Modules() []Module {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
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

// Mounted reports whether Mount has completed successfully.
func (r *Registry) Mounted() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state == registryMounted
}

// Mount registers routes, jobs, and event handlers for all modules.
// jobs/events may be nil (treated as no-op registrars).
//
// Exactly one successful Mount is permitted. On callback failure the registry
// returns to open (lifecycle-consistent) so registration may continue; the
// Fiber app may already be partially mutated and is not rolled back.
func (r *Registry) Mount(app *fiber.App, jobs JobRegistrar, events EventRegistrar) error {
	if r == nil {
		return fmt.Errorf("module: nil registry")
	}
	if app == nil {
		return fmt.Errorf("module: nil app")
	}

	r.mu.Lock()
	if r.state != registryOpen {
		state := r.state
		r.mu.Unlock()
		return fmt.Errorf("module: mount not allowed in state %s", state)
	}
	r.state = registryMounting
	modules := make([]Module, len(r.modules))
	copy(modules, r.modules)
	r.mu.Unlock()

	if jobs == nil {
		jobs = NoopJobRegistrar{}
	}
	if events == nil {
		events = NoopEventRegistrar{}
	}

	var mountErr error
	for _, m := range modules {
		if err := m.RegisterRoutes(app); err != nil {
			mountErr = fmt.Errorf("module %q RegisterRoutes: %w", m.ID(), err)
			break
		}
		if err := m.RegisterJobs(jobs); err != nil {
			mountErr = fmt.Errorf("module %q RegisterJobs: %w", m.ID(), err)
			break
		}
		if err := m.RegisterEventHandlers(events); err != nil {
			mountErr = fmt.Errorf("module %q RegisterEventHandlers: %w", m.ID(), err)
			break
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if mountErr != nil {
		r.state = registryOpen
		return mountErr
	}
	r.state = registryMounted
	return nil
}

// Health aggregates per-module health reports keyed by module ID.
func (r *Registry) Health(ctx context.Context) map[string]HealthStatus {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	modules := make([]Module, len(r.modules))
	copy(modules, r.modules)
	r.mu.Unlock()

	out := make(map[string]HealthStatus, len(modules))
	for _, m := range modules {
		out[m.ID()] = m.Health(ctx)
	}
	return out
}
