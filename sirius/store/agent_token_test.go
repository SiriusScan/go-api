package store

import (
	"context"
	"testing"
)

func TestStoreAgentTokenOwned_WithOwnerPins(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()

	token, err := GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken: %v", err)
	}

	if err := StoreAgentTokenOwned(ctx, kv, "agent-1", token, "local:alice", "keyhash123"); err != nil {
		t.Fatalf("StoreAgentTokenOwned: %v", err)
	}

	meta, err := GetAgentToken(ctx, kv, "agent-1")
	if err != nil {
		t.Fatalf("GetAgentToken: %v", err)
	}
	if meta.OwnerSubjectID != "local:alice" {
		t.Errorf("OwnerSubjectID = %q, want local:alice", meta.OwnerSubjectID)
	}
	if meta.EnrollingKeyID != "keyhash123" {
		t.Errorf("EnrollingKeyID = %q, want keyhash123", meta.EnrollingKeyID)
	}
	if meta.Token != token {
		t.Error("token mismatch after store")
	}
}

func TestStoreAgentToken_LegacyEmptyOwner(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()

	if err := StoreAgentToken(ctx, kv, "agent-legacy", "tok-legacy"); err != nil {
		t.Fatalf("StoreAgentToken: %v", err)
	}

	meta, err := GetAgentToken(ctx, kv, "agent-legacy")
	if err != nil {
		t.Fatalf("GetAgentToken: %v", err)
	}
	if meta.OwnerSubjectID != "" {
		t.Errorf("legacy OwnerSubjectID = %q, want empty", meta.OwnerSubjectID)
	}
	if meta.EnrollingKeyID != "" {
		t.Errorf("legacy EnrollingKeyID = %q, want empty", meta.EnrollingKeyID)
	}
}

func TestValidateAgentToken_PreservesOwnerPins(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()

	if err := StoreAgentTokenOwned(ctx, kv, "agent-2", "secret", "local:bob", "enroll-key"); err != nil {
		t.Fatalf("StoreAgentTokenOwned: %v", err)
	}

	meta, err := ValidateAgentToken(ctx, kv, "agent-2", "secret")
	if err != nil {
		t.Fatalf("ValidateAgentToken: %v", err)
	}
	if meta.OwnerSubjectID != "local:bob" {
		t.Errorf("OwnerSubjectID after validate = %q", meta.OwnerSubjectID)
	}
	if meta.EnrollingKeyID != "enroll-key" {
		t.Errorf("EnrollingKeyID after validate = %q", meta.EnrollingKeyID)
	}

	again, err := GetAgentToken(ctx, kv, "agent-2")
	if err != nil {
		t.Fatalf("GetAgentToken: %v", err)
	}
	if again.OwnerSubjectID != "local:bob" || again.EnrollingKeyID != "enroll-key" {
		t.Errorf("pins not preserved on disk: %#v", again)
	}
}

func TestConnectedAgentsKey(t *testing.T) {
	got := ConnectedAgentsKey("local:uuid-1")
	want := "agents:connected:local:uuid-1"
	if got != want {
		t.Errorf("ConnectedAgentsKey = %q, want %q", got, want)
	}
}

func TestListConnectedAgentIDsForOwner(t *testing.T) {
	ctx := context.Background()
	kv := newFakeKV()

	ids, err := ListConnectedAgentIDsForOwner(ctx, kv, "local:nobody")
	if err != nil {
		t.Fatalf("missing key should not error: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty list, got %#v", ids)
	}

	key := ConnectedAgentsKey("local:alice")
	if err := kv.SetValue(ctx, key, `["a1","a2"]`); err != nil {
		t.Fatalf("SetValue: %v", err)
	}

	ids, err = ListConnectedAgentIDsForOwner(ctx, kv, "local:alice")
	if err != nil {
		t.Fatalf("ListConnectedAgentIDsForOwner: %v", err)
	}
	if len(ids) != 2 || ids[0] != "a1" || ids[1] != "a2" {
		t.Errorf("got %#v, want [a1 a2]", ids)
	}
}
