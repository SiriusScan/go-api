package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeKV is an in-memory KVStore for API key unit tests.
type fakeKV struct {
	mu   sync.Mutex
	data map[string]string
}

func newFakeKV() *fakeKV {
	return &fakeKV{data: map[string]string{}}
}

func (f *fakeKV) SetValue(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return nil
}

func (f *fakeKV) SetValueWithTTL(ctx context.Context, key, value string, _ int) error {
	return f.SetValue(ctx, key, value)
}

func (f *fakeKV) GetValue(_ context.Context, key string) (ValkeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return ValkeyResponse{}, errors.New("not found")
	}
	return ValkeyResponse{Message: ValkeyValue{Value: v}}, nil
}

func (f *fakeKV) GetTTL(context.Context, string) (int, error) { return -1, nil }

func (f *fakeKV) SetExpire(context.Context, string, int) error { return nil }

func (f *fakeKV) ListKeys(_ context.Context, pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := strings.TrimSuffix(pattern, "*")
	var keys []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (f *fakeKV) DeleteValue(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}

func (f *fakeKV) Close() error { return nil }

func TestStoreAPIKey_WithOwnerAndScopes(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	raw := "sk_test_owner_scoped_key_abcdefghijklmnopqrstuvwxyz"

	meta, err := StoreAPIKey(ctx, kv, raw, "enroll", "alice@example.com", "subj-alice", []string{ScopeAgentEnroll})
	if err != nil {
		t.Fatalf("StoreAPIKey: %v", err)
	}
	if meta.OwnerSubjectID != "subj-alice" {
		t.Errorf("OwnerSubjectID = %q, want subj-alice", meta.OwnerSubjectID)
	}
	if len(meta.Scopes) != 1 || meta.Scopes[0] != ScopeAgentEnroll {
		t.Errorf("Scopes = %#v, want [%q]", meta.Scopes, ScopeAgentEnroll)
	}
	if meta.CreatedBy != "alice@example.com" {
		t.Errorf("CreatedBy = %q, want alice@example.com", meta.CreatedBy)
	}

	got, err := GetAPIKeyMeta(ctx, kv, meta.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyMeta: %v", err)
	}
	if got.OwnerSubjectID != "subj-alice" {
		t.Errorf("persisted OwnerSubjectID = %q", got.OwnerSubjectID)
	}
	if !HasScope(got, ScopeAgentEnroll) {
		t.Error("expected HasScope(agent:enroll) true for stored key")
	}
}

func TestHasScope_LegacyEmptyMeansFullAccess(t *testing.T) {
	cases := []APIKeyMeta{
		{},
		{Scopes: nil},
		{Scopes: []string{}},
	}
	for i, meta := range cases {
		if !HasScope(meta, ScopeAgentEnroll) {
			t.Errorf("case %d: HasScope(legacy) = false, want true", i)
		}
		if !HasScope(meta, "any:scope") {
			t.Errorf("case %d: HasScope(any) = false, want true", i)
		}
		if IsScoped(meta) {
			t.Errorf("case %d: IsScoped = true, want false", i)
		}
	}
}

func TestHasScope_AgentEnroll(t *testing.T) {
	meta := APIKeyMeta{Scopes: []string{ScopeAgentEnroll}}
	if !IsScoped(meta) {
		t.Error("IsScoped = false, want true")
	}
	if !HasScope(meta, ScopeAgentEnroll) {
		t.Error("HasScope(agent:enroll) = false, want true")
	}
	if HasScope(meta, "other:scope") {
		t.Error("HasScope(other:scope) = true, want false")
	}
}

func TestListAPIKeysByOwner_Filter(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()

	_, err := StoreAPIKey(ctx, kv, "sk_owner_a_11111111111111111111111111111111", "a1", "a", "owner-a", []string{ScopeAgentEnroll})
	if err != nil {
		t.Fatalf("store a1: %v", err)
	}
	_, err = StoreAPIKey(ctx, kv, "sk_owner_a_22222222222222222222222222222222", "a2", "a", "owner-a", nil)
	if err != nil {
		t.Fatalf("store a2: %v", err)
	}
	_, err = StoreAPIKey(ctx, kv, "sk_owner_b_33333333333333333333333333333333", "b1", "b", "owner-b", []string{ScopeAgentEnroll})
	if err != nil {
		t.Fatalf("store b1: %v", err)
	}
	_, err = StoreAPIKey(ctx, kv, "sk_legacy_44444444444444444444444444444444", "legacy", "sys", "", nil)
	if err != nil {
		t.Fatalf("store legacy: %v", err)
	}

	owned, err := ListAPIKeysByOwner(ctx, kv, "owner-a")
	if err != nil {
		t.Fatalf("ListAPIKeysByOwner: %v", err)
	}
	if len(owned) != 2 {
		t.Fatalf("len(owned) = %d, want 2", len(owned))
	}
	for _, m := range owned {
		if m.OwnerSubjectID != "owner-a" {
			t.Errorf("unexpected owner %q", m.OwnerSubjectID)
		}
	}

	none, err := ListAPIKeysByOwner(ctx, kv, "owner-missing")
	if err != nil {
		t.Fatalf("ListAPIKeysByOwner missing: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("len(none) = %d, want 0", len(none))
	}
}

func TestAPIKeyMeta_BackwardCompatUnmarshal(t *testing.T) {
	legacy := `{
		"id": "abc123",
		"label": "root",
		"prefix": "sk_deadbeef...",
		"created_by": "system",
		"created_at": "2026-01-01T00:00:00Z",
		"last_used_at": ""
	}`
	var meta APIKeyMeta
	if err := json.Unmarshal([]byte(legacy), &meta); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if meta.ID != "abc123" || meta.Label != "root" || meta.CreatedBy != "system" {
		t.Errorf("legacy fields not preserved: %+v", meta)
	}
	if meta.OwnerSubjectID != "" {
		t.Errorf("OwnerSubjectID = %q, want empty", meta.OwnerSubjectID)
	}
	if meta.Scopes != nil {
		t.Errorf("Scopes = %#v, want nil", meta.Scopes)
	}
	if !HasScope(meta, ScopeAgentEnroll) {
		t.Error("legacy key should have full access via HasScope")
	}
	if IsScoped(meta) {
		t.Error("legacy key should not be IsScoped")
	}
}

func TestValidateAPIKey_PreservesOwnerAndScopes(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()
	raw := "sk_validate_preserve_owner_scopes_0123456789abcdef"

	stored, err := StoreAPIKey(ctx, kv, raw, "enroll", "bob", "subj-bob", []string{ScopeAgentEnroll})
	if err != nil {
		t.Fatalf("StoreAPIKey: %v", err)
	}

	validated, err := ValidateAPIKey(ctx, kv, raw)
	if err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	if validated.OwnerSubjectID != "subj-bob" {
		t.Errorf("OwnerSubjectID overwritten: got %q", validated.OwnerSubjectID)
	}
	if len(validated.Scopes) != 1 || validated.Scopes[0] != ScopeAgentEnroll {
		t.Errorf("Scopes overwritten: %#v", validated.Scopes)
	}
	if validated.LastUsedAt == "" {
		t.Error("LastUsedAt not set")
	}
	if validated.ID != stored.ID {
		t.Errorf("ID mismatch: %q vs %q", validated.ID, stored.ID)
	}

	// Confirm persisted value still has owner/scopes.
	persisted, err := GetAPIKeyMeta(ctx, kv, stored.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyMeta: %v", err)
	}
	if persisted.OwnerSubjectID != "subj-bob" {
		t.Errorf("persisted OwnerSubjectID = %q", persisted.OwnerSubjectID)
	}
	if !HasScope(persisted, ScopeAgentEnroll) {
		t.Error("persisted scopes lost agent:enroll")
	}
}
