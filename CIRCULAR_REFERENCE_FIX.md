# Circular Reference Fix for GORM Models

## Problem

When executing a scan, the application would crash with an infinite recursion error (~986,809 stack frames) when trying to log or print GORM model instances.

### Root Cause

The GORM models had bidirectional many-to-many relationships that created circular references:

1. **Host ↔ Port**
   - `Host` has `Ports []Port`
   - `Port` has `Hosts []Host`
   
2. **Host ↔ Vulnerability**
   - `Host` has `Vulnerabilities []Vulnerability`
   - `Vulnerability` has `Hosts []Host`

When Go's `fmt` package tries to print these structures (via `log.Printf()`, `fmt.Println()`, etc.), it recursively prints all nested fields, causing infinite recursion:

```
Host → Ports → Hosts → Ports → Hosts → ... (INFINITE LOOP)
```

## Solution

Implemented custom `String()` methods for the affected models that provide safe string representations without traversing the circular references:

### Modified Files

1. **`sirius/postgres/models/host.go`**
   - Added `String()` method to `Host` struct
   - Added `String()` method to `Port` struct

2. **`sirius/postgres/models/vulnerability.go`**
   - Added `String()` method to `Vulnerability` struct
   - Added `fmt` import

### Implementation

```go
// Host.String() - Safe representation
func (h Host) String() string {
	return fmt.Sprintf("Host{ID:%d, HID:%s, IP:%s, Hostname:%s, Ports:%d, Services:%d, Vulnerabilities:%d}",
		h.ID, h.HID, h.IP, h.Hostname, len(h.Ports), len(h.Services), len(h.Vulnerabilities))
}

// Port.String() - Safe representation
func (p Port) String() string {
	return fmt.Sprintf("Port{ID:%d, Number:%d, Protocol:%s, State:%s, Hosts:%d}",
		p.ID, p.Number, p.Protocol, p.State, len(p.Hosts))
}

// Vulnerability.String() - Safe representation
func (v Vulnerability) String() string {
	return fmt.Sprintf("Vulnerability{ID:%d, VID:%s, Title:%s, RiskScore:%.2f, Hosts:%d}",
		v.ID, v.VID, v.Title, v.RiskScore, len(v.Hosts))
}
```

### Key Points

- These `String()` methods only show **counts** of related entities (e.g., `len(h.Ports)`)
- They **do not** recursively traverse into the related entities
- This breaks the circular reference chain while still providing useful debugging information

## Testing

After applying this fix:

1. Updated `go.sum` files for:
   - `go-api`
   - `app-scanner`
   - `app-terminal`

2. Restarted services:
   ```bash
   docker-compose -f docker-compose.yaml -f docker-compose.dev.yaml restart sirius-engine
   ```

3. All services now start successfully without stack overflow errors

## Best Practices Going Forward

When working with GORM models that have bidirectional relationships:

1. **Always implement custom `String()` methods** for models with circular references
2. **Never log entire GORM model instances** with loaded relationships
3. **Be selective with GORM's `Preload()`** - only load what you need
4. **Use field-specific logging** when debugging: `log.Printf("Host IP: %s", host.IP)` instead of `log.Printf("Host: %v", host)`

## Related Issues

This fix resolves the scanner crash that occurred during scan execution when the scanner attempted to log host data with loaded relationships.

---

**Fixed:** 2025-11-03  
**Affected Components:** go-api, app-scanner, app-terminal  
**Severity:** Critical (Caused complete service failure)

