# Stack Overflow Fix - Comprehensive Analysis and Solution

## Executive Summary

**Problem:** Scanner crashed with stack overflow (~986,809 frames) when executing scans  
**Root Cause:** Multiple cascading issues related to logging complex objects with circular references  
**Solution:** Safe logging patterns + defensive String() methods with pointer receivers  
**Status:** ✅ Fixed and deployed

---

## 🔍 Root Cause Analysis

### Issue 1: Dangerous Logging Pattern ⚠️ CRITICAL

**Location:** `app-scanner/internal/scan/manager.go:606`

```go
// ❌ DANGEROUS - Logs entire object graph
log.Printf("Enumeration results: %+v", enumResults)
```

**Why this breaks:**
- `%+v` triggers Go's fmt package to recursively print ALL fields
- If ANY field has a circular reference (even at runtime), infinite recursion occurs
- The `enumResults` is a `sirius.Host` with nested structures:
  - `Ports []Port`
  - `Vulnerabilities []Vulnerability` 
  - `Vulnerability.Metadata map[string]interface{}` (can contain ANYTHING at runtime)
- Even without type-level circular references, runtime data can create cycles

### Issue 2: Two Different Host Types

The codebase has **TWO separate Host definitions:**

1. **`sirius/postgres/models/host.go`** - GORM database model
   ```go
   type Host struct {
       Ports []Port `gorm:"many2many:host_ports"`
       Vulnerabilities []Vulnerability `gorm:"many2many:host_vulnerabilities"`
   }
   ```

2. **`sirius/sirius.go`** - API/SDK type (used by scanner)
   ```go
   type Host struct {
       Ports []Port
       Vulnerabilities []Vulnerability
   }
   ```

**The Problem:** Initial fix only added String() methods to `models.Host`, but scanner uses `sirius.Host`!

### Issue 3: Wrong Receiver Type on String() Methods

**First Attempt (WRONG):**
```go
func (h Host) String() string { ... }  // Value receiver
```

**Why it fails:**
- GORM returns **pointers** (`*Host`, `*Port`, `*Vulnerability`)
- Value receiver `(h Host)` only matches when called on a value
- Pointer receiver `(h *Host)` works for both pointers and values
- Result: Our String() methods were never called!

### Issue 4: Circular References in GORM Models

**models.Host ↔ models.Port:**
```go
// Host has Ports
type Host struct {
    Ports []Port `gorm:"many2many:host_ports"`
}

// Port has Hosts (CIRCULAR!)
type Port struct {
    Hosts []Host `gorm:"many2many:host_ports"`
}
```

**models.Host ↔ models.Vulnerability:**
```go
// Host has Vulnerabilities
type Host struct {
    Vulnerabilities []Vulnerability `gorm:"many2many:host_vulnerabilities"`
}

// Vulnerability has Hosts (CIRCULAR!)
type Vulnerability struct {
    Hosts []Host `gorm:"many2many:host_vulnerabilities"`
}
```

**The Recursion Chain:**
```
log.Printf("%+v", host)
  → fmt.printValue(host)
    → fmt.printValue(host.Ports[0])
      → fmt.printValue(host.Ports[0].Hosts[0])
        → fmt.printValue(host.Ports[0].Hosts[0].Ports[0])
          → fmt.printValue(host.Ports[0].Hosts[0].Ports[0].Hosts[0])
            → ... (INFINITE LOOP - 986,809 frames!)
```

---

## ✅ Comprehensive Solution

### 1. Remove Dangerous Logging Patterns

**Changed:**
```go
// ❌ BEFORE
log.Printf("Enumeration results: %+v", enumResults)
log.Printf("Processing target: %+v", target)
```

**To:**
```go
// ✅ AFTER - Only log specific fields
log.Printf("Enumeration results: IP=%s, Hostname=%s, Ports=%d, Services=%d, OS=%s", 
    enumResults.IP, enumResults.Hostname, len(enumResults.Ports), len(enumResults.Services), enumResults.OS)
    
log.Printf("Processing target: Type=%s, Value=%s, Timeout=%d", 
    target.Type, target.Value, target.Timeout)
```

**Files Modified:**
- `app-scanner/internal/scan/manager.go` (lines 388, 606)

### 2. Add Safe String() Methods to All Types

#### sirius.Host (API/SDK type)

```go
// String returns a safe string representation preventing infinite recursion
func (h *Host) String() string {
    return fmt.Sprintf("Host{IP:%s, Hostname:%s, OS:%s, Ports:%d, Services:%d, Vulnerabilities:%d}",
        h.IP, h.Hostname, h.OS, len(h.Ports), len(h.Services), len(h.Vulnerabilities))
}
```

#### sirius.Port

```go
func (p *Port) String() string {
    return fmt.Sprintf("Port{Number:%d, Protocol:%s, State:%s}", p.Number, p.Protocol, p.State)
}
```

#### sirius.Vulnerability

```go
func (v *Vulnerability) String() string {
    return fmt.Sprintf("Vulnerability{VID:%s, Title:%s, Severity:%s, RiskScore:%.2f, Metadata:%d fields}",
        v.VID, v.Title, v.Severity, v.RiskScore, len(v.Metadata))
}
```

**Files Modified:**
- `go-api/sirius/sirius.go`

### 3. Fix models.Host String() Methods with Pointer Receivers

#### models.Host

```go
// String returns a safe string representation without circular references
// Uses pointer receiver to work with GORM-loaded entities
func (h *Host) String() string {
    if h == nil {
        return "Host{nil}"
    }
    return fmt.Sprintf("Host{ID:%d, HID:%s, IP:%s, Hostname:%s, Ports:%d, Services:%d, Vulnerabilities:%d}",
        h.ID, h.HID, h.IP, h.Hostname, len(h.Ports), len(h.Services), len(h.Vulnerabilities))
}
```

#### models.Port

```go
func (p *Port) String() string {
    if p == nil {
        return "Port{nil}"
    }
    return fmt.Sprintf("Port{ID:%d, Number:%d, Protocol:%s, State:%s, Hosts:%d}",
        p.ID, p.Number, p.Protocol, p.State, len(p.Hosts))
}
```

#### models.Vulnerability

```go
func (v *Vulnerability) String() string {
    if v == nil {
        return "Vulnerability{nil}"
    }
    return fmt.Sprintf("Vulnerability{ID:%d, VID:%s, Title:%s, RiskScore:%.2f, Hosts:%d}",
        v.ID, v.VID, v.Title, v.RiskScore, len(v.Hosts))
}
```

**Files Modified:**
- `go-api/sirius/postgres/models/host.go`
- `go-api/sirius/postgres/models/vulnerability.go`

---

## 🛡️ Defense in Depth Strategy

Our solution implements multiple layers of protection:

### Layer 1: Safe Logging (Primary Defense)
- ✅ Never log complex objects with `%v` or `%+v`
- ✅ Always log specific fields explicitly
- ✅ Use field counts for collections (e.g., `len(host.Ports)`)

### Layer 2: Defensive String() Methods (Fallback)
- ✅ All major types have String() methods
- ✅ Pointer receivers work with GORM entities
- ✅ Only show summaries, never nested objects
- ✅ Nil-safe implementations

### Layer 3: Type Safety
- ✅ No type-level circular references in API types (`sirius.Host`)
- ✅ GORM model circular references safely handled by String() methods

---

## 📋 Code Review Checklist

Before merging ANY code, verify:

### Logging Patterns
- [ ] No `log.Printf("%v", complexObject)`
- [ ] No `log.Printf("%+v", complexObject)`
- [ ] No `fmt.Printf("%#v", complexObject)`
- [ ] Complex objects logged field-by-field
- [ ] Collections logged by count, not contents

### String() Methods
- [ ] All types with nested structures have String() methods
- [ ] String() methods use **pointer receivers** `(*Type)`
- [ ] String() methods are nil-safe
- [ ] String() methods show summaries, not full data

### GORM Models
- [ ] Many-to-many relationships never logged directly
- [ ] Bidirectional relationships have String() protection
- [ ] Use `Preload()` selectively, not eagerly

---

## 🎯 Best Practices Going Forward

### DO ✅

1. **Log specific fields:**
   ```go
   log.Printf("Host discovered: IP=%s, Ports=%d", host.IP, len(host.Ports))
   ```

2. **Use pointer receivers for String():**
   ```go
   func (h *Host) String() string { ... }
   ```

3. **Show counts, not contents:**
   ```go
   fmt.Sprintf("Host{Ports:%d, Vulns:%d}", len(h.Ports), len(h.Vulnerabilities))
   ```

4. **Implement String() for all complex types**

5. **Test logging in development:**
   ```go
   // In tests, verify logging doesn't panic
   log.Printf("Test: %s", myObject)
   ```

### DON'T ❌

1. **Never log complex objects with %v:**
   ```go
   // ❌ DANGEROUS
   log.Printf("Host: %+v", host)
   log.Printf("Result: %#v", result)
   ```

2. **Never use value receivers on GORM models:**
   ```go
   // ❌ WRONG - Won't work with GORM pointers
   func (h Host) String() string { ... }
   ```

3. **Never recursively print nested structures:**
   ```go
   // ❌ DANGEROUS
   for _, port := range host.Ports {
       log.Printf("Port: %+v", port)  // Could print port.Hosts!
   }
   ```

4. **Never trust runtime data in Metadata maps:**
   ```go
   // ❌ DANGEROUS - Metadata could contain circular refs
   log.Printf("Metadata: %+v", vuln.Metadata)
   ```

---

## 🧪 Testing

### Verification Steps

1. ✅ Scanner starts without errors
2. ✅ Scanner can execute scans
3. ✅ No stack overflow during enumeration
4. ✅ No stack overflow during vulnerability scans
5. ✅ Logs show useful information without full object dumps

### Test Commands

```bash
# Start services
docker-compose -f docker-compose.yaml -f docker-compose.dev.yaml up -d

# Watch scanner logs
docker-compose logs -f sirius-engine | grep -E "Enumeration|Processing"

# Trigger a scan (via UI or API)

# Verify no stack overflow errors
docker-compose logs sirius-engine | grep -i "stack overflow"
```

---

## 📊 Impact Assessment

### Before Fix
- ❌ Scanner crashed with stack overflow on ANY scan
- ❌ ~986,809 stack frames before crash
- ❌ Services restarted repeatedly
- ❌ Complete system failure

### After Fix
- ✅ Scanner runs successfully
- ✅ Clean, readable logs
- ✅ No circular reference issues
- ✅ Better debuggability (specific field logging)
- ✅ Performance improvement (less memory, faster logging)

---

## 🔄 Related Issues

This fix prevents similar issues with:
- Event logging in app-terminal
- Agent command responses
- Database query results
- API responses with nested data

---

## 📚 References

- Go fmt package: https://pkg.go.dev/fmt
- GORM associations: https://gorm.io/docs/belongs_to.html
- Go pointer vs value receivers: https://go.dev/tour/methods/4

---

**Fixed:** 2025-11-03  
**Affected Components:** go-api, app-scanner  
**Severity:** Critical (Complete system failure)  
**Status:** ✅ Resolved and verified

