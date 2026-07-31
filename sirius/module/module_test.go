package module_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SiriusScan/go-api/sirius/module"
	"github.com/gofiber/fiber/v2"
)

func TestContractVersion(t *testing.T) {
	if module.ContractVersion != "v1" {
		t.Fatalf("ContractVersion = %q, want v1", module.ContractVersion)
	}
}

func TestCommunityModuleIDInventoryGolden(t *testing.T) {
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, communityRouteModules()); err != nil {
		t.Fatalf("RegisterCommunity: %v", err)
	}

	got := strings.Join(reg.ModuleIDs(), "\n") + "\n"
	wantPath := filepath.Join("testdata", "community_module_ids.golden")
	wantBytes, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want := string(wantBytes)
	if got != want {
		t.Fatalf("community module ID inventory mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}

	// Also lock the exported constant list.
	if strings.Join(module.CommunityModuleIDs, "\n")+"\n" != want {
		t.Fatalf("CommunityModuleIDs drifted from golden inventory")
	}
}

func TestCommunityRouteInventoryGolden(t *testing.T) {
	app := fiber.New()
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, communityRouteModules()); err != nil {
		t.Fatalf("RegisterCommunity: %v", err)
	}
	if err := reg.Mount(app, nil, nil); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	got := strings.Join(module.RouteInventory(app), "\n") + "\n"
	wantPath := filepath.Join("testdata", "community_routes.golden")
	wantBytes, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(wantBytes) {
		t.Fatalf("community route inventory mismatch\n--- got ---\n%s--- want ---\n%s", got, string(wantBytes))
	}
}

func TestCustomModuleRegistersRouteWithoutEditingCommunitySeam(t *testing.T) {
	app := fiber.New()
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, communityRouteModules()); err != nil {
		t.Fatalf("RegisterCommunity: %v", err)
	}

	testMod := &simpleModule{
		module.Base{ModuleID: "test.extra", ModuleVersion: "0.1.0"},
		func(app *fiber.App) error {
			app.Get("/api/v1/test-extension", func(c *fiber.Ctx) error {
				return c.SendString("ok")
			})
			return nil
		},
	}
	if err := reg.Register(testMod); err != nil {
		t.Fatalf("Register test module: %v", err)
	}
	if err := reg.Mount(app, nil, nil); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	inv := module.RouteInventory(app)
	found := false
	for _, line := range inv {
		if line == "GET\t/api/v1/test-extension" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected test extension route in inventory, got:\n%s", strings.Join(inv, "\n"))
	}

	// Community IDs remain a prefix; custom module is appended.
	ids := reg.ModuleIDs()
	if len(ids) != len(module.CommunityModuleIDs)+1 {
		t.Fatalf("module count = %d, want %d", len(ids), len(module.CommunityModuleIDs)+1)
	}
	if ids[len(ids)-1] != "test.extra" {
		t.Fatalf("last module ID = %q, want test.extra", ids[len(ids)-1])
	}
}

func TestCapabilityMiddlewareDefaultAllow(t *testing.T) {
	app := fiber.New()
	app.Get("/gated", module.CapabilityMiddleware(nil, "reporting.enterprise"), func(c *fiber.Ctx) error {
		return c.SendString("allowed")
	})

	req := httptest.NewRequest("GET", "/gated", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200 (Community allow/no-op)", resp.StatusCode)
	}
}

func TestCapabilityMiddlewareDenyHook(t *testing.T) {
	app := fiber.New()
	deny := denyChecker{}
	app.Get("/gated", module.CapabilityMiddleware(deny, "reporting.enterprise"), func(c *fiber.Ctx) error {
		return c.SendString("allowed")
	})

	req := httptest.NewRequest("GET", "/gated", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestRegisterCommunityRejectsMissingModule(t *testing.T) {
	reg := module.NewRegistry()
	core := communityRouteModules()
	core.Scan = nil
	if err := module.RegisterCommunity(reg, core); err == nil {
		t.Fatal("expected error for missing community module")
	}
}

func TestModuleHealthAndNoopRegistrars(t *testing.T) {
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, communityRouteModules()); err != nil {
		t.Fatalf("RegisterCommunity: %v", err)
	}
	health := reg.Health(context.Background())
	if got := health[module.IDHost].Status; got != "ok" {
		t.Fatalf("host health = %q, want ok", got)
	}
	app := fiber.New()
	if err := reg.Mount(app, module.NoopJobRegistrar{}, module.NoopEventRegistrar{}); err != nil {
		t.Fatalf("Mount: %v", err)
	}
}

func TestSetupRoutesCompat(t *testing.T) {
	app := fiber.New()
	called := false
	module.SetupRoutes(app, routeFunc(func(app *fiber.App) {
		called = true
		app.Get("/compat", func(c *fiber.Ctx) error { return nil })
	}))
	if !called {
		t.Fatal("SetupRoutes did not invoke RouteSetter")
	}
}

type simpleModule struct {
	module.Base
	routes func(app *fiber.App) error
}

func (m *simpleModule) RegisterRoutes(app *fiber.App) error { return m.routes(app) }

type denyChecker struct{}

func (denyChecker) Has(string) bool { return false }
