package store

import (
	"context"
	"fmt"
	"sort"

	valkey "github.com/valkey-io/valkey-go"
)

// AtomicValueUpdater is an optional KVStore capability for an all-or-none batch.
// A nil expectation requires absence; a nonnil expectation matches exact bytes,
// including an empty value. A nil update deletes; a nonnil update sets a value
// while preserving its existing TTL. Every updated key must have an expectation.
// Extra expectations are read-only guards. False means a guard did not match.
// Callers must reread and revalidate on conflict. Errors, including cancellation,
// may have an uncertain outcome and must not be treated as a confirmed conflict.
// Clustered stores require all guarded keys to share a hash slot.
type AtomicValueUpdater interface {
	CompareAndSwapValues(ctx context.Context, expected map[string]*string, updates map[string]*string) (bool, error)
}

const atomicValuesScript = `
if #ARGV ~= #KEYS * 4 then
    return redis.error_reply('invalid atomic value arguments')
end
-- Validate every operation before reading or mutating any key.
for i = 1, #KEYS do
    local p = (i - 1) * 4
    if (ARGV[p+1] ~= 'absent' and ARGV[p+1] ~= 'value') or
       (ARGV[p+3] ~= 'keep' and ARGV[p+3] ~= 'delete' and ARGV[p+3] ~= 'set') then
        return redis.error_reply('invalid atomic value operation')
    end
end
-- All reads happen before writes, so wrong-type errors cannot partially apply.
local matches = true
for i = 1, #KEYS do
    local p = (i - 1) * 4
    local current = redis.call('GET', KEYS[i])
    if ARGV[p+1] == 'absent' then
        if current ~= false then matches = false end
    elseif current == false or current ~= ARGV[p+2] then
        matches = false
    end
end
if not matches then return 0 end
for i = 1, #KEYS do
    local p = (i - 1) * 4
    if ARGV[p+3] == 'delete' then
        redis.call('DEL', KEYS[i])
    elseif ARGV[p+3] == 'set' then
        redis.call('SET', KEYS[i], ARGV[p+4], 'KEEPTTL')
    end
end
return 1
`

var atomicValues = valkey.NewLuaScript(atomicValuesScript)

func atomicValueArguments(expected, updates map[string]*string) ([]string, []string, error) {
	for key := range updates {
		if _, guarded := expected[key]; !guarded {
			return nil, nil, fmt.Errorf("atomic update key %q has no expectation", key)
		}
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	args := make([]string, 0, len(keys)*4)
	for _, key := range keys {
		mode, value := "absent", ""
		if expected[key] != nil {
			mode, value = "value", *expected[key]
		}
		operation, update := "keep", ""
		if v, exists := updates[key]; exists {
			operation = "delete"
			if v != nil {
				operation, update = "set", *v
			}
		}
		args = append(args, mode, value, operation, update)
	}
	return keys, args, nil
}

// CompareAndSwapValues checks all expectations and applies the batch atomically.
func (s *valkeyStore) CompareAndSwapValues(ctx context.Context, expected map[string]*string, updates map[string]*string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	keys, args, err := atomicValueArguments(expected, updates)
	if err != nil {
		return false, err
	}
	if len(keys) == 0 {
		return true, nil
	}
	result, err := atomicValues.Exec(ctx, s.client, keys, args).ToInt64()
	if err != nil {
		return false, fmt.Errorf("atomic value update: %w", err)
	}
	return result == 1, nil
}

var _ AtomicValueUpdater = (*valkeyStore)(nil)
