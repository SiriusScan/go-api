package module_test

import (
	"github.com/SiriusScan/go-api/sirius/module"
	"github.com/gofiber/fiber/v2"
)

// communityRouteModules builds stub Modules that register the Community route
// inventory mirrored from sirius-api/routes (main.go order). Handlers are no-ops;
// the inventory of METHOD+PATH is what golden tests lock.
func communityRouteModules() module.CommunityCore {
	noop := func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) }

	return module.CommunityCore{
		Host: module.AdaptRouteSetter(module.IDHost, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			hostRoutes := app.Group("/host")
			hostRoutes.Get("/", noop)
			hostRoutes.Post("/", noop)
			hostRoutes.Put("/:id", noop)
			hostRoutes.Post("/delete", noop)
			hostRoutes.Get("/vulnerabilities/all", noop)
			hostRoutes.Get("/source-coverage", noop)
			hostRoutes.Post("/with-source", noop)
			hostRoutes.Get("/:id/packages", noop)
			hostRoutes.Get("/:id/fingerprint", noop)
			hostRoutes.Get("/:id/software-stats", noop)
			hostRoutes.Get("/:id", noop)
			hostRoutes.Get("/statistics/:id", noop)
			hostRoutes.Get("/severity/:id", noop)
			hostRoutes.Get("/:id/sources", noop)
			hostRoutes.Get("/:id/history", noop)
			hostRoutes.Get("/:id/vulnerability/:vulnId/history", noop)
			hostRoutes.Get("/:ip/sources", noop)
			// Duplicate registration exists in production host_routes.go; omit second
			// source-coverage bind so Fiber inventory stays deterministic.
			app.Get("/vulnerability/:id/sources", noop)
		})),
		App: module.AdaptRouteSetter(module.IDApp, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			app.Get("/health", noop)
			app.Get("/api/v1/system/health", noop)
			app.Get("/api/v1/test", noop)
			app.Get("/api/v1/system/logs", noop)
			app.Get("/api/v1/system/resources", noop)
			app.Post("/api/v1/admin/command", noop)
			app.Get("/api/v1/performance/metrics", noop)
			app.Get("/api/v1/logs/stats", noop)
			app.Delete("/api/v1/logs/clear", noop)
			app.Put("/api/v1/logs/:logId", noop)
			app.Delete("/api/v1/logs/:logId", noop)
			app.Post("/api/v1/logs", noop)
			app.Get("/api/v1/logs", noop)
			appRoutes := app.Group("/app")
			appRoutes.Post("/:appName", noop)
		})),
		Vulnerability: module.AdaptRouteSetter(module.IDVulnerability, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			vulnerabilityRoutes := app.Group("/vulnerability")
			vulnerabilityRoutes.Get("/:id", noop)
			vulnerabilityRoutes.Post("/", noop)
			vulnerabilityRoutes.Post("/delete", noop)
		})),
		Template: module.AdaptRouteSetter(module.IDTemplate, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			templates := app.Group("/templates")
			templates.Get("/", noop)
			templates.Get("/:id", noop)
			templates.Post("/", noop)
			templates.Put("/:id", noop)
			templates.Delete("/:id", noop)
		})),
		Script: module.AdaptRouteSetter(module.IDScript, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			// Placeholder module; no routes in Community today.
		})),
		AgentTemplateRepository: module.AdaptRouteSetter(module.IDAgentTemplateRepository, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			api := app.Group("/api")
			repos := api.Group("/agent-templates/repositories")
			repos.Get("/", noop)
			repos.Post("/", noop)
			repos.Put("/:id", noop)
			repos.Delete("/:id", noop)
			repos.Post("/:id/sync", noop)
			repos.Get("/:id/sync-status", noop)
		})),
		AgentTemplate: module.AdaptRouteSetter(module.IDAgentTemplate, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			api := app.Group("/api")
			templates := api.Group("/agent-templates")
			templates.Get("/", noop)
			templates.Get("/:id", noop)
			templates.Post("/", noop)
			templates.Put("/:id", noop)
			templates.Delete("/:id", noop)
			templates.Post("/validate", noop)
			templates.Post("/:id/test", noop)
			templates.Post("/:id/deploy", noop)
			templates.Get("/analytics", noop)
			templates.Get("/:id/results", noop)
		})),
		Event: module.AdaptRouteSetter(module.IDEvent, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			api := app.Group("/api/v1/events")
			api.Get("/", noop)
			api.Get("/:id", noop)
			api.Get("/stats", noop)
			api.Get("/by-entity", noop)
			api.Get("/by-severity/:severity", noop)
		})),
		Snapshot: module.AdaptRouteSetter(module.IDSnapshot, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			api := app.Group("/api/v1")
			stats := api.Group("/statistics")
			stats.Get("/vulnerability-trends", noop)
			stats.Get("/vulnerability-snapshots", noop)
			stats.Get("/vulnerability-snapshot/:snapshotId", noop)
			stats.Post("/vulnerability-snapshot", noop)
		})),
		Statistics: module.AdaptRouteSetter(module.IDStatistics, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			api := app.Group("/api/v1/statistics")
			hosts := api.Group("/hosts")
			hosts.Get("/most-vulnerable", noop)
		})),
		Scan: module.AdaptRouteSetter(module.IDScan, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			api := app.Group("/api/v1/scans")
			api.Post("/cancel", noop)
			api.Post("/force-stop", noop)
			api.Post("/reset", noop)
			api.Get("/status", noop)
		})),
		APIKey: module.AdaptRouteSetter(module.IDAPIKey, module.CommunityModuleVersion, routeFunc(func(app *fiber.App) {
			keys := app.Group("/api/v1/keys")
			keys.Post("/", noop)
			keys.Get("/", noop)
			keys.Delete("/:id", noop)
		})),
	}
}

type routeFunc func(app *fiber.App)

func (f routeFunc) SetupRoutes(app *fiber.App) { f(app) }
