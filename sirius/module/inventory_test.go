package module_test

import (
	"strings"
	"testing"

	"github.com/SiriusScan/go-api/sirius/module"
	"github.com/gofiber/fiber/v2"
)

func TestRouteInventoryPreservesOrderDuplicatesAndMethods(t *testing.T) {
	app := fiber.New()
	noop := func(c *fiber.Ctx) error { return nil }

	// Static route before parameterized route (Fiber match precedence).
	app.Get("/host/source-coverage", noop)
	app.Get("/host/:id", noop)
	// Consecutive duplicate registration merges handlers in Fiber; inventory
	// should still surface both via handler count.
	app.Post("/dup", noop)
	app.Post("/dup", noop)
	// Legitimate uncommon methods must not be dropped.
	app.Connect("/tunnel", noop)
	app.Trace("/trace", noop)
	// Explicit HEAD-only route (no GET) must be kept.
	app.Head("/head-only", noop)

	inv := module.RouteInventory(app)

	idx := func(line string) int {
		for i, l := range inv {
			if l == line {
				return i
			}
		}
		return -1
	}

	staticIdx := idx("GET\t/host/source-coverage")
	paramIdx := idx("GET\t/host/:id")
	if staticIdx < 0 || paramIdx < 0 {
		t.Fatalf("missing static/param routes in inventory:\n%s", strings.Join(inv, "\n"))
	}
	if staticIdx >= paramIdx {
		t.Fatalf("static route must appear before parameterized route: static=%d param=%d\n%s",
			staticIdx, paramIdx, strings.Join(inv, "\n"))
	}

	dupCount := 0
	for _, line := range inv {
		if line == "POST\t/dup" {
			dupCount++
		}
	}
	if dupCount != 2 {
		t.Fatalf("duplicate POST /dup count = %d, want 2\n%s", dupCount, strings.Join(inv, "\n"))
	}

	if idx("CONNECT\t/tunnel") < 0 {
		t.Fatalf("CONNECT route missing:\n%s", strings.Join(inv, "\n"))
	}
	if idx("TRACE\t/trace") < 0 {
		t.Fatalf("TRACE route missing:\n%s", strings.Join(inv, "\n"))
	}
	if idx("HEAD\t/head-only") < 0 {
		t.Fatalf("explicit HEAD-only route missing:\n%s", strings.Join(inv, "\n"))
	}

	// Fiber Get mirrors must be omitted when GET exists for the same path.
	for _, line := range inv {
		if line == "HEAD\t/host/source-coverage" || line == "HEAD\t/host/:id" {
			t.Fatalf("Fiber-generated HEAD mirror should be omitted: %s\n%s", line, strings.Join(inv, "\n"))
		}
	}
}
