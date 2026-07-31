package module_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/SiriusScan/go-api/sirius/module"
	"github.com/gofiber/fiber/v2"
)

func TestContractVersion(t *testing.T) {
	if module.ContractVersion != "v1" {
		t.Fatalf("ContractVersion = %q, want v1", module.ContractVersion)
	}
}

func TestCommunityModuleIDsDefensiveCopy(t *testing.T) {
	ids := module.CommunityModuleIDs()
	wantPath := filepath.Join("testdata", "community_module_ids.golden")
	wantBytes, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want := string(wantBytes)
	got := strings.Join(ids, "\n") + "\n"
	if got != want {
		t.Fatalf("CommunityModuleIDs mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}

	ids[0] = "mutated"
	again := module.CommunityModuleIDs()
	if again[0] != module.IDHost {
		t.Fatalf("CommunityModuleIDs is not a defensive copy; canonical changed to %q", again[0])
	}
}

func TestRegisterCommunityOrdersCanonicalIDs(t *testing.T) {
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, syntheticCommunityCore(t)); err != nil {
		t.Fatalf("RegisterCommunity: %v", err)
	}
	got := strings.Join(reg.ModuleIDs(), "\n") + "\n"
	want := strings.Join(module.CommunityModuleIDs(), "\n") + "\n"
	if got != want {
		t.Fatalf("registered IDs drifted from CommunityModuleIDs()\n got %s want %s", got, want)
	}
}

func TestCustomModuleRegistersRouteWithoutEditingCommunitySeam(t *testing.T) {
	app := fiber.New()
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, syntheticCommunityCore(t)); err != nil {
		t.Fatalf("RegisterCommunity: %v", err)
	}

	testMod := &simpleModule{
		Base: module.Base{ModuleID: "test.extra", ModuleVersion: "0.1.0"},
		routes: func(app *fiber.App) error {
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

	ids := reg.ModuleIDs()
	if len(ids) != len(module.CommunityModuleIDs())+1 {
		t.Fatalf("module count = %d, want %d", len(ids), len(module.CommunityModuleIDs())+1)
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

func TestModuleHealthAndNoopRegistrars(t *testing.T) {
	reg := module.NewRegistry()
	if err := module.RegisterCommunity(reg, syntheticCommunityCore(t)); err != nil {
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
	if !reg.Mounted() {
		t.Fatal("expected Mounted() true after success")
	}
}

func TestSetupRoutesCompat(t *testing.T) {
	app := fiber.New()
	called := false
	if err := module.SetupRoutes(app, routeFunc(func(app *fiber.App) {
		called = true
		app.Get("/compat", func(c *fiber.Ctx) error { return nil })
	})); err != nil {
		t.Fatalf("SetupRoutes: %v", err)
	}
	if !called {
		t.Fatal("SetupRoutes did not invoke RouteSetter")
	}
}

func TestSetupRoutesRejectsNilAndTypedNil(t *testing.T) {
	app := fiber.New()
	if err := module.SetupRoutes(app, nil); err == nil {
		t.Fatal("expected error for nil RouteSetter")
	}
	var typedNil *concreteSetter
	if err := module.SetupRoutes(app, typedNil); err == nil {
		t.Fatal("expected error for typed-nil RouteSetter")
	}
}

func TestAdaptRouteSetterRejectsNilAndTypedNil(t *testing.T) {
	if _, err := module.AdaptRouteSetter("x", "1", nil); err == nil {
		t.Fatal("expected error for nil RouteSetter")
	}
	var typedNil *concreteSetter
	if _, err := module.AdaptRouteSetter("x", "1", typedNil); err == nil {
		t.Fatal("expected error for typed-nil RouteSetter")
	}
	if _, err := module.AdaptRouteSetter("", "1", routeFunc(func(*fiber.App) {})); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestRegisterRejectsNilAndTypedNilModule(t *testing.T) {
	reg := module.NewRegistry()
	if err := reg.Register(nil); err == nil {
		t.Fatal("expected error for nil module")
	}
	var typedNil *simpleModule
	if err := reg.Register(typedNil); err == nil {
		t.Fatal("expected error for typed-nil module")
	}
	if len(reg.ModuleIDs()) != 0 {
		t.Fatalf("registry mutated after nil reject: %v", reg.ModuleIDs())
	}
}

func TestRegisterCommunityAtomicNoPartialState(t *testing.T) {
	seed := &simpleModule{Base: module.Base{ModuleID: "seed", ModuleVersion: "1"}}
	reg := module.NewRegistry()
	if err := reg.Register(seed); err != nil {
		t.Fatalf("seed register: %v", err)
	}

	core := syntheticCommunityCore(t)
	core.Scan = nil
	if err := module.RegisterCommunity(reg, core); err == nil {
		t.Fatal("expected error for missing community module")
	}
	if got := reg.ModuleIDs(); len(got) != 1 || got[0] != "seed" {
		t.Fatalf("partial community registration leaked: %v", got)
	}

	core = syntheticCommunityCore(t)
	core.Scan = &simpleModule{Base: module.Base{ModuleID: "wrong.id", ModuleVersion: "1"}}
	if err := module.RegisterCommunity(reg, core); err == nil {
		t.Fatal("expected error for mismatched ID")
	}
	if got := reg.ModuleIDs(); len(got) != 1 || got[0] != "seed" {
		t.Fatalf("partial community registration leaked after ID mismatch: %v", got)
	}

	var typedNil *simpleModule
	core = syntheticCommunityCore(t)
	core.Host = typedNil
	if err := module.RegisterCommunity(reg, core); err == nil {
		t.Fatal("expected error for typed-nil community module")
	}
	if got := reg.ModuleIDs(); len(got) != 1 || got[0] != "seed" {
		t.Fatalf("partial community registration leaked after typed-nil: %v", got)
	}
}

func TestRegisterAllAtomicDuplicateInBatch(t *testing.T) {
	reg := module.NewRegistry()
	a := &simpleModule{Base: module.Base{ModuleID: "a", ModuleVersion: "1"}}
	dup := &simpleModule{Base: module.Base{ModuleID: "a", ModuleVersion: "1"}}
	if err := reg.RegisterAll(a, dup); err == nil {
		t.Fatal("expected duplicate batch error")
	}
	if len(reg.ModuleIDs()) != 0 {
		t.Fatalf("registry mutated after batch reject: %v", reg.ModuleIDs())
	}
}

func TestRegistryLifecycleMountOnceAndLateRegister(t *testing.T) {
	reg := module.NewRegistry()
	if err := reg.Register(&simpleModule{
		Base: module.Base{ModuleID: "a", ModuleVersion: "1"},
		routes: func(app *fiber.App) error {
			app.Get("/a", func(c *fiber.Ctx) error { return nil })
			return nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Mount(fiber.New(), nil, nil); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if err := reg.Mount(fiber.New(), nil, nil); err == nil {
		t.Fatal("expected second Mount to fail")
	}
	if err := reg.Register(&simpleModule{Base: module.Base{ModuleID: "b", ModuleVersion: "1"}}); err == nil {
		t.Fatal("expected late Register to fail")
	}
}

func TestRegistryMountFailureLeavesOpen(t *testing.T) {
	reg := module.NewRegistry()
	if err := reg.Register(&simpleModule{
		Base: module.Base{ModuleID: "bad", ModuleVersion: "1"},
		routes: func(app *fiber.App) error {
			return context.Canceled
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Mount(fiber.New(), nil, nil); err == nil {
		t.Fatal("expected mount failure")
	}
	if reg.Mounted() {
		t.Fatal("Mounted() true after failed mount")
	}
	if err := reg.Register(&simpleModule{Base: module.Base{ModuleID: "ok", ModuleVersion: "1"}}); err != nil {
		t.Fatalf("register after failed mount should succeed: %v", err)
	}
}

func TestRegistryRejectsRegisterDuringMount(t *testing.T) {
	reg := module.NewRegistry()
	started := make(chan struct{})
	release := make(chan struct{})

	if err := reg.Register(&simpleModule{
		Base: module.Base{ModuleID: "blocker", ModuleVersion: "1"},
		routes: func(app *fiber.App) error {
			close(started)
			<-release
			return nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- reg.Mount(fiber.New(), nil, nil)
	}()

	<-started
	if err := reg.Register(&simpleModule{Base: module.Base{ModuleID: "late", ModuleVersion: "1"}}); err == nil {
		t.Fatal("expected register during mount to fail")
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("Mount: %v", err)
	}
}

func TestRegistryConcurrentMountOnlyOneSucceeds(t *testing.T) {
	reg := module.NewRegistry()
	if err := reg.Register(&simpleModule{
		Base: module.Base{ModuleID: "a", ModuleVersion: "1"},
		routes: func(app *fiber.App) error {
			return nil
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			errs <- reg.Mount(fiber.New(), nil, nil)
		}()
	}
	wg.Wait()
	close(errs)

	var ok, fail int
	for err := range errs {
		if err == nil {
			ok++
		} else {
			fail++
		}
	}
	if ok != 1 || fail != n-1 {
		t.Fatalf("concurrent mount results: ok=%d fail=%d want ok=1 fail=%d", ok, fail, n-1)
	}
	if !reg.Mounted() {
		t.Fatal("expected Mounted after concurrent mounts")
	}
}

type simpleModule struct {
	module.Base
	routes func(app *fiber.App) error
}

func (m *simpleModule) RegisterRoutes(app *fiber.App) error {
	if m.routes == nil {
		return nil
	}
	return m.routes(app)
}

type denyChecker struct{}

func (denyChecker) Has(string) bool { return false }

type routeFunc func(app *fiber.App)

func (f routeFunc) SetupRoutes(app *fiber.App) { f(app) }

type concreteSetter struct{}

func (*concreteSetter) SetupRoutes(*fiber.App) {}

func syntheticCommunityCore(t *testing.T) module.CommunityCore {
	t.Helper()
	adapt := func(id string) module.Module {
		m, err := module.AdaptRouteSetter(id, module.CommunityModuleVersion, routeFunc(func(*fiber.App) {}))
		if err != nil {
			t.Fatalf("AdaptRouteSetter(%q): %v", id, err)
		}
		return m
	}
	return module.CommunityCore{
		Host:                    adapt(module.IDHost),
		App:                     adapt(module.IDApp),
		Vulnerability:           adapt(module.IDVulnerability),
		Template:                adapt(module.IDTemplate),
		Script:                  adapt(module.IDScript),
		AgentTemplateRepository: adapt(module.IDAgentTemplateRepository),
		AgentTemplate:           adapt(module.IDAgentTemplate),
		Event:                   adapt(module.IDEvent),
		Snapshot:                adapt(module.IDSnapshot),
		Statistics:              adapt(module.IDStatistics),
		Scan:                    adapt(module.IDScan),
		APIKey:                  adapt(module.IDAPIKey),
	}
}
