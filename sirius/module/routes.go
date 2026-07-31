package module

import "github.com/gofiber/fiber/v2"

// RouteSetter is the legacy Fiber route registration contract used by sirius-api.
// New code should implement Module; AdaptRouteSetter bridges existing setters.
type RouteSetter interface {
	SetupRoutes(app *fiber.App)
}

// SetupRoutes preserves the historical RouteSetter batch registration helper.
func SetupRoutes(app *fiber.App, setters ...RouteSetter) {
	for _, setter := range setters {
		if setter == nil {
			continue
		}
		setter.SetupRoutes(app)
	}
}

type routeSetterModule struct {
	Base
	setter RouteSetter
}

// AdaptRouteSetter wraps a legacy RouteSetter as a Module.
func AdaptRouteSetter(id, version string, setter RouteSetter) Module {
	return &routeSetterModule{
		Base: Base{
			ModuleID:      id,
			ModuleVersion: version,
		},
		setter: setter,
	}
}

func (m *routeSetterModule) RegisterRoutes(app *fiber.App) error {
	if m.setter == nil {
		return nil
	}
	m.setter.SetupRoutes(app)
	return nil
}
