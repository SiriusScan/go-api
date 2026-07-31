package module

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// RouteInventory returns METHOD\tPATH lines for routes on app.
//
// Behavior:
//   - Preserves Fiber stack order from GetRoutes(true) (per-method registration
//     order). This keeps static-vs-parameter precedence visible within a method.
//   - Preserves duplicates: consecutive identical registrations that Fiber merges
//     into one route with N handlers emit N lines; distinct stack entries each
//     emit at least one line.
//   - Includes legitimate declared methods, including CONNECT and TRACE.
//   - Omits only Fiber-generated HEAD mirrors: Fiber's Get/Group.Get always
//     registers HEAD before GET for the same path/handlers. A HEAD entry is
//     omitted when a GET exists for the same path. Explicit HEAD-only routes
//     (no GET for that path) are kept.
func RouteInventory(app *fiber.App) []string {
	if app == nil {
		return nil
	}
	routes := app.GetRoutes(true)

	getPaths := make(map[string]struct{})
	for _, rt := range routes {
		if strings.EqualFold(rt.Method, fiber.MethodGet) {
			getPaths[rt.Path] = struct{}{}
		}
	}

	out := make([]string, 0, len(routes))
	for _, rt := range routes {
		method := strings.ToUpper(strings.TrimSpace(rt.Method))
		path := rt.Path
		if method == "" || path == "" {
			continue
		}
		// Fiber Get registers Head(path, handlers).Add(GET, path, handlers).
		if method == fiber.MethodHead {
			if _, hasGET := getPaths[path]; hasGET {
				continue
			}
		}
		line := method + "\t" + path
		n := len(rt.Handlers)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			out = append(out, line)
		}
	}
	return out
}
