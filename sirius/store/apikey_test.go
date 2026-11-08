package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// memoryKV is an in-memory KVStore used to prove scope persistence without a
// live Valkey. Only the methods API-key code calls are implemented.
type memoryKV struct {
	data map[string]string
}

func newMemoryKV() *memoryKV {
	return &memoryKV{data: map[string]string{}}
}

func (m *memoryKV) SetValue(_ context.Context, key, value string) error {
	m.data[key] = value
	return nil
}

func (m *memoryKV) SetValueWithTTL(ctx context.Context, key, value string, _ int) error {
	return m.SetValue(ctx, key, value)
}

func (m *memoryKV) GetValue(_ context.Context, key string) (ValkeyResponse, error) {
	value, ok := m.data[key]
	if !ok {
		return ValkeyResponse{}, errors.New("not found")
	}
	return ValkeyResponse{Message: ValkeyValue{Value: value}, Type: "string"}, nil
}

func (m *memoryKV) GetTTL(context.Context, string) (int, error) { return -1, nil }

func (m *memoryKV) SetExpire(context.Context, string, int) error { return nil }

func (m *memoryKV) ListKeys(_ context.Context, pattern string) ([]string, error) {
	prefix := strings.TrimSuffix(pattern, "*")
	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *memoryKV) DeleteValue(_ context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *memoryKV) Close() error { return nil }

func TestStoreAPIKeyLegacyOmitsScopes(t *testing.T) {
	kv := newMemoryKV()
	meta, err := StoreAPIKey(context.Background(), kv, "sk_legacykeyvalue", "legacy", "root")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Scopes != nil {
		t.Fatalf("legacy scopes = %#v; want nil", meta.Scopes)
	}
	if !meta.AllowsUnrestricted() {
		t.Fatal("legacy key must be unrestricted")
	}
	if meta.HasScope(ScopeMCPRead) {
		t.Fatal("unrestricted key must not implicitly match mcp:read")
	}

	raw, ok := kv.data[valkeyKey(meta.ID)]
	if !ok {
		t.Fatal("metadata was not stored")
	}
	if strings.Contains(raw, "scopes") {
		t.Fatalf("legacy JSON persisted scopes: %s", raw)
	}

	loaded, err := ValidateAPIKey(context.Background(), kv, "sk_legacykeyvalue")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.AllowsUnrestricted() || loaded.HasScope(ScopeMCPRead) {
		t.Fatalf("validated legacy meta = %#v", loaded)
	}
}

func TestStoreAPIKeyWithScopesRoundTrip(t *testing.T) {
	kv := newMemoryKV()
	rawKey := "sk_scopedkeyvalue"
	meta, err := StoreAPIKeyWithScopes(context.Background(), kv, rawKey, "mcp reader", "root", []string{" mcp:read ", "mcp:read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Scopes) != 1 || meta.Scopes[0] != ScopeMCPRead {
		t.Fatalf("stored scopes = %#v", meta.Scopes)
	}
	if meta.AllowsUnrestricted() || !meta.HasScope(ScopeMCPRead) {
		t.Fatalf("scope predicates = unrestricted %v has %v", meta.AllowsUnrestricted(), meta.HasScope(ScopeMCPRead))
	}

	loaded, err := ValidateAPIKey(context.Background(), kv, rawKey)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AllowsUnrestricted() || !loaded.HasScope(ScopeMCPRead) {
		t.Fatalf("validated scopes = %#v", loaded.Scopes)
	}
	if loaded.LastUsedAt == "" {
		t.Fatal("validation did not stamp last_used_at")
	}

	listed, err := ListAPIKeys(context.Background(), kv)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || !listed[0].HasScope(ScopeMCPRead) {
		t.Fatalf("listed = %#v", listed)
	}
}

func TestStoreAPIKeyWithScopesFailClosed(t *testing.T) {
	kv := newMemoryKV()
	cases := [][]string{
		nil,
		{},
		{"mcp:write"},
		{"MCP:READ"},
		{"mcp:read", "admin"},
		{" "},
		{"mcp:read " + "extra"},
	}
	for _, scopes := range cases {
		if _, err := StoreAPIKeyWithScopes(context.Background(), kv, "sk_shouldnotstore", "bad", "root", scopes); err == nil {
			t.Fatalf("scopes %#v were accepted", scopes)
		}
	}
	if len(kv.data) != 0 {
		t.Fatalf("failed scopes wrote keys: %#v", kv.data)
	}
}

func TestNormalizeAPIKeyScopes(t *testing.T) {
	got, err := NormalizeAPIKeyScopes(nil)
	if err != nil || got != nil {
		t.Fatalf("nil scopes = %#v err=%v", got, err)
	}
	got, err = NormalizeAPIKeyScopes([]string{})
	if err != nil || got != nil {
		t.Fatalf("empty scopes = %#v err=%v", got, err)
	}
	if _, err := NormalizeAPIKeyScopes([]string{"inventory:read"}); err == nil {
		t.Fatal("unknown grouping scope was accepted")
	}
}

func TestValidateAPIKeyUnknownPersistedScopeFailsClosed(t *testing.T) {
	kv := newMemoryKV()
	meta, err := StoreAPIKey(context.Background(), kv, "sk_tampered", "tampered", "root")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a persisted key whose scopes were widened outside the helper.
	meta.Scopes = []string{"mcp:read", "admin"}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := kv.SetValue(context.Background(), valkeyKey(meta.ID), string(data)); err != nil {
		t.Fatal(err)
	}

	loaded, err := ValidateAPIKey(context.Background(), kv, "sk_tampered")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AllowsUnrestricted() {
		t.Fatal("non-empty unknown scopes must not be treated as unrestricted")
	}
	if loaded.HasScope(ScopeMCPRead) {
		t.Fatal("a key carrying an unknown scope must not match mcp:read")
	}
	if loaded.HasScope("admin") {
		t.Fatal("unknown scope matched")
	}
}

func TestLegacyJSONWithoutScopesStaysUnrestricted(t *testing.T) {
	kv := newMemoryKV()
	const rawKey = "sk_oldjson"
	id := hashKey(rawKey)
	legacy := `{"id":"` + id + `","label":"old","prefix":"sk_old...","created_by":"root","created_at":"2020-01-01T00:00:00Z","last_used_at":""}`
	if err := kv.SetValue(context.Background(), valkeyKey(id), legacy); err != nil {
		t.Fatal(err)
	}
	loaded, err := ValidateAPIKey(context.Background(), kv, rawKey)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.AllowsUnrestricted() || len(loaded.Scopes) != 0 {
		t.Fatalf("legacy JSON loaded as %#v", loaded)
	}
}
