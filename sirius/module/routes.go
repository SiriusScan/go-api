package module

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

// RouteSetter is the legacy Fiber route registration contract used by sirius-api.
// New code should implement Module; AdaptRouteSetter bridges existing setters.
type RouteSetter interface {
	SetupRoutes(app *fiber.App)
}

// SetupRoutes preserves the historical RouteSetter batch registration helper.
// Nil and typed-nil setters are rejected before any mutation.
func SetupRoutes(app *fiber.App, setters ...RouteSetter) error {
	if app == nil {
		return fmt.Errorf("module: nil app")
	}
	for i, setter := range setters {
		if isNilInterface(setter) {
			return fmt.Errorf("module: nil RouteSetter at index %d", i)
		}
		setter.SetupRoutes(app)
	}
	return nil
}

type routeSetterModule struct {
	Base
	setter RouteSetter
}

// AdaptRouteSetter wraps a legacy RouteSetter as a Module.
// Nil and typed-nil setters are rejected; an empty module is never returned.
func AdaptRouteSetter(id, version string, setter RouteSetter) (Module, error) {
	if id == "" {
		return nil, fmt.Errorf("module: empty module ID")
	}
	if isNilInterface(setter) {
		return nil, fmt.Errorf("module: nil RouteSetter for %q", id)
	}
	return &routeSetterModule{
		Base: Base{
			ModuleID:      id,
			ModuleVersion: version,
		},
		setter: setter,
	}, nil
}

func (m *routeSetterModule) RegisterRoutes(app *fiber.App) error {
	if app == nil {
		return fmt.Errorf("module: nil app")
	}
	m.setter.SetupRoutes(app)
	return nil
}
