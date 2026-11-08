package store

import (
	"context"
	"fmt"
	valkey "github.com/valkey-io/valkey-go"
)

// ValueCompareAndSetter is an optional KVStore capability for conditional
// updates. Missing keys do not match, even when expected is the empty string.
// Callers must reread and revalidate after a false result, not blindly retry.
type ValueCompareAndSetter interface {
	CompareAndSetValue(ctx context.Context, key, expected, value string) (bool, error)
}

const compareAndSetValueScript = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end
redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
return 1
`

var compareAndSetValue = valkey.NewLuaScript(compareAndSetValueScript)

// CompareAndSetValue changes an existing value atomically and preserves its TTL.
func (s *valkeyStore) CompareAndSetValue(ctx context.Context, key, expected, value string) (bool, error) {
	result, err := compareAndSetValue.Exec(ctx, s.client, []string{key}, []string{expected, value}).ToInt64()
	if err != nil {
		return false, fmt.Errorf("compare-and-set key %q: %w", key, err)
	}
	return result == 1, nil
}

var _ ValueCompareAndSetter = (*valkeyStore)(nil)
