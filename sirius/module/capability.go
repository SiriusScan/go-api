package module

import "github.com/gofiber/fiber/v2"

// CapabilityChecker is the entitlement hook point for future licensing.
// Community defaults to AllowAllChecker (always allow / no-op enforcement).
type CapabilityChecker interface {
	Has(capability string) bool
}

// AllowAllChecker grants every capability. This is the Community default.
type AllowAllChecker struct{}

// Has always returns true.
func (AllowAllChecker) Has(string) bool { return true }

// CapabilityMiddleware returns Fiber middleware that rejects requests when the
// checker denies the required capability. A nil checker defaults to AllowAllChecker.
//
// This task only provides the hook point; licensing/entitlements are out of scope.
func CapabilityMiddleware(checker CapabilityChecker, capability string) fiber.Handler {
	if checker == nil {
		checker = AllowAllChecker{}
	}
	return func(c *fiber.Ctx) error {
		if capability == "" || checker.Has(capability) {
			return c.Next()
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":      "CAPABILITY_NOT_LICENSED",
			"capability": capability,
		})
	}
}
