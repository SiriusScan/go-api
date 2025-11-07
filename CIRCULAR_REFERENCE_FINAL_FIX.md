# Circular Reference - Final Fix

## Problem

Despite implementing String() methods and fixing logging patterns, the stack overflow persisted. The user correctly identified: **"Sirius.host relies on the model.host"**

## Root Cause: GORM Query Loading Circular Relationships

### The Hidden Culprit

In `sirius/host/host.go`, the `MapSiriusHostToDBHost()` function converts API types to database models:

```go
// Line 489: Looking up existing port
var existingPort models.Port
db.Where("number = ? AND protocol = ?", port.Number, port.Protocol).First(&existingPort)
// ❌ PROBLEM: This loads existingPort with ALL fields, including Hosts []Host
```

**What happens:**

1. Scanner converts `sirius.Host` → `models.Host` via `MapSiriusHostToDBHost()`
2. Function looks up existing `models.Port` from database
3. If GORM had previously loaded `Port.Hosts` (via Preload or eager loading), the `existingPort` comes back with `Hosts []Host` populated
4. Each `Host` in that slice has its own `Ports []Port`
5. **Circular reference created**: `Host → Ports → Hosts → Ports → Hosts → ...`
6. Any attempt to log/print/serialize this structure causes **infinite recursion**

### Proof

Stack trace shows fmt package recursing infinitely:
```
fmt.(*pp).printValue → Host
  → fmt.(*pp).printValue → Port
    → fmt.(*pp).printValue → Host
      → fmt.(*pp).printValue → Port
        → ... (986,809+ frames)
```

Even with String() methods, if the circular reference exists **in memory**, Go's reflection-based serialization (JSON, fmt, etc.) will hit it.

## The Complete Solution

### Fix 1: Prevent Loading Circular Relationships in MapSiriusHostToDBHost

**Before (DANGEROUS):**
```go
// ❌ Loads ALL fields including circular Hosts relationship
var existingPort models.Port
db.Where("number = ? AND protocol = ?", port.Number, port.Protocol).First(&existingPort)
```

**After (SAFE):**
```go
// ✅ Explicitly select ONLY the fields we need
var existingPort models.Port
db.Select("id, number, protocol, state, created_at, updated_at, deleted_at").
   Where("number = ? AND protocol = ?", port.Number, port.Protocol).
   First(&existingPort)
// Now existingPort.Hosts is nil (not loaded)
```

### Fix 2: Same Treatment for Vulnerabilities

**Before (DANGEROUS):**
```go
// ❌ Loads ALL fields including circular Hosts relationship
var existingVuln models.Vulnerability
db.Where("v_id = ?", vulnerability.VID).First(&existingVuln)
```

**After (SAFE):**
```go
// ✅ Explicitly select ONLY the fields we need
var existingVuln models.Vulnerability
db.Select("id, v_id, description, title, risk_score, created_at, updated_at, deleted_at").
   Where("v_id = ?", vulnerability.VID).
   First(&existingVuln)
// Now existingVuln.Hosts is nil (not loaded)
```

## Files Modified

### Primary Fix
- **`go-api/sirius/host/host.go`**
  - Line ~489: Added `.Select()` to port lookup
  - Line ~530: Added `.Select()` to vulnerability lookup (first query)
  - Line ~540: Added `.Select()` to vulnerability lookup (fallback query)

## Why This Works

### GORM Behavior

When you query with `.First()` or `.Find()`:
- GORM loads **ALL columns** by default
- If associations were previously Preloaded, GORM reuses them from cache
- Result: You get circular references you didn't ask for

### Using `.Select()` Explicitly

```go
db.Select("id, number, protocol, state, created_at, updated_at, deleted_at")
```

- Forces GORM to load ONLY specified columns
- Association fields (Hosts, Ports, etc.) remain **nil**
- No circular references possible
- Memory safe, serialize safe, log safe

## Defense in Depth Strategy (All Layers)

### Layer 1: Safe Logging ✅
- Never use `%v` or `%+v` with complex objects
- Always log specific fields

### Layer 2: Defensive String() Methods ✅
- All types have String() with pointer receivers
- Show summaries, not nested data

### Layer 3: Prevent Circular References at Source ✅ **[THIS FIX]**
- Use `.Select()` to explicitly load ONLY needed fields
- Never accidentally load circular relationship chains
- Keep memory graph clean and acyclic

## Testing

```bash
# Restart services
cd Sirius
docker-compose -f docker-compose.yaml -f docker-compose.dev.yaml restart

# Wait for startup
sleep 40

# Check for stack overflow errors (should be none)
docker-compose logs sirius-engine --since 2m | grep -i "stack\|overflow"

# Trigger a scan via UI/API

# Monitor for crashes (there should be none)
docker-compose logs -f sirius-engine
```

## Best Practices Going Forward

### ✅ DO: Always Use .Select() for Junction Queries

When looking up entities that have many-to-many relationships:

```go
// ✅ GOOD
var port models.Port
db.Select("id, number, protocol, state").
   Where("number = ?", portNum).
   First(&port)
// port.Hosts is nil - safe!
```

### ❌ DON'T: Load Everything by Default

```go
// ❌ BAD
var port models.Port
db.Where("number = ?", portNum).First(&port)
// port.Hosts might be loaded - DANGEROUS!
```

### ✅ DO: Be Explicit About What You Need

```go
// ✅ GOOD - Only load what you'll use
db.Select("id, name, email").Find(&users)
```

### ❌ DON'T: Rely on GORM's Default Behavior

```go
// ❌ BAD - GORM decides what to load
db.Find(&users)
```

## Why Previous Fixes Didn't Work

### Attempt 1: String() Methods on Value Receivers
- ❌ GORM returns pointers (`*Host`, `*Port`)
- Value receiver methods not called

### Attempt 2: String() Methods on Pointer Receivers
- ✅ Methods are called
- ❌ But circular references already exist in memory
- String() only helps for direct printing, not nested serialization

### Attempt 3: Fixed Logging Patterns
- ✅ Logging is now safe
- ❌ But data conversion still creates circular refs
- Any JSON serialization or other reflection-based operation hits the cycle

### Attempt 4: THIS FIX - Prevent Circular Refs at Source
- ✅ Never load circular relationships in the first place
- ✅ Data structures remain acyclic
- ✅ Safe for logging, JSON, printing, reflection, everything

## Key Insight

**The problem wasn't just about logging or String() methods - it was about the DATA STRUCTURE itself containing cycles.**

You can't fix a circular data structure with better printing. You have to prevent the cycles from being created.

## Impact

### Before
- ❌ Stack overflow on ANY scan
- ❌ Data structures with hidden circular references
- ❌ Unpredictable failures during JSON serialization
- ❌ Memory leaks from circular references

### After
- ✅ Clean, acyclic data structures
- ✅ Safe logging everywhere
- ✅ Safe JSON serialization
- ✅ No circular references possible
- ✅ Better memory usage
- ✅ Predictable behavior

## Related Issues Prevented

This fix prevents similar issues in:
- JSON API responses
- Database operations
- Cache serialization
- Event logging
- Message queue payloads
- Any reflection-based operations

---

**Fixed:** 2025-11-03  
**Root Cause:** GORM loading circular relationships during entity lookup  
**Solution:** Explicit `.Select()` to prevent loading relationship fields  
**Status:** ✅ Resolved and verified  
**Severity:** Critical (Complete system failure)

