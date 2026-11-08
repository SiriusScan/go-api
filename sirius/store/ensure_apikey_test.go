package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type ensureAPIKeyKV struct {
	KVStore
	value            string
	exists           bool
	readErr          error
	createErr        error
	winner           string
	collisionReadErr error
	creates, writes  int
}

func (s *ensureAPIKeyKV) GetValue(context.Context, string) (ValkeyResponse, error) {
	if s.readErr != nil {
		return ValkeyResponse{}, s.readErr
	}
	if !s.exists {
		return ValkeyResponse{}, fmt.Errorf("missing: %w", ErrKeyNotFound)
	}
	return ValkeyResponse{Message: ValkeyValue{Value: s.value}}, nil
}
func (s *ensureAPIKeyKV) SetValue(_ context.Context, _, value string) error {
	s.writes++
	s.value = value
	s.exists = true
	return nil
}
func (s *ensureAPIKeyKV) SetValueIfAbsent(_ context.Context, _, value string) (bool, error) {
	s.creates++
	if s.createErr != nil {
		return false, s.createErr
	}
	if s.winner != "" {
		s.value = s.winner
		s.exists = true
		s.readErr = s.collisionReadErr
		return false, nil
	}
	if s.exists {
		return false, nil
	}
	s.value = value
	s.exists = true
	return true, nil
}
func TestEnsureAPIKeyFailsClosed(t *testing.T) {
	outage := errors.New("read outage")
	for _, tc := range []struct {
		name, value string
		readErr     error
	}{
		{"outage", "", outage}, {"malformed", "{", nil}, {"null", "null", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kv := &ensureAPIKeyKV{exists: true, value: tc.value, readErr: tc.readErr}
			_, err := EnsureAPIKey(context.Background(), kv, "sk_synthetic", "new", "test")
			if err == nil {
				t.Fatal("unsafe record accepted")
			}
			if tc.readErr != nil && !errors.Is(err, tc.readErr) {
				t.Fatalf("lost read error: %v", err)
			}
			if kv.writes != 0 || kv.creates != 0 || kv.value != tc.value {
				t.Fatal("failed read changed stored metadata")
			}
		})
	}
}
func TestEnsureAPIKeyAtomicCreation(t *testing.T) {
	kv := &ensureAPIKeyKV{}
	got, err := EnsureAPIKey(context.Background(), kv, "sk_synthetic", "new", "test")
	if err != nil {
		t.Fatal(err)
	}
	if kv.creates != 1 || kv.writes != 0 || got.ID != hashKey("sk_synthetic") || !got.AllowsUnrestricted() {
		t.Fatalf("non-atomic creation: %+v / %+v", got, kv)
	}
	var saved APIKeyMeta
	if err := json.Unmarshal([]byte(kv.value), &saved); err != nil || !reflect.DeepEqual(saved, got) {
		t.Fatalf("wrong metadata: %+v / %v", saved, err)
	}
	legacy := struct{ KVStore }{&ensureAPIKeyKV{}}
	if _, err := EnsureAPIKey(context.Background(), legacy, "sk_synthetic", "new", "test"); err == nil {
		t.Fatal("unsupported atomic creation accepted")
	}
}
func TestEnsureAPIKeyPreservesScopedWinner(t *testing.T) {
	meta := APIKeyMeta{ID: hashKey("sk_synthetic"), Label: "restricted", Scopes: []string{ScopeMCPRead}}
	data, _ := json.Marshal(meta)
	for _, existing := range []bool{false, true} {
		kv := &ensureAPIKeyKV{exists: existing, value: string(data)}
		if !existing {
			kv.winner = string(data)
		}
		got, err := EnsureAPIKey(context.Background(), kv, "sk_synthetic", "new", "test")
		if err != nil || !reflect.DeepEqual(meta, got) || kv.value != string(data) || kv.writes != 0 {
			t.Fatalf("scoped winner overwritten: %+v / %v / %+v", got, err, kv)
		}
		want := 1
		if existing {
			want = 0
		}
		if kv.creates != want {
			t.Fatalf("creates=%d want=%d", kv.creates, want)
		}
	}
}
func TestEnsureAPIKeyCreationAndCollisionFailures(t *testing.T) {
	failure := errors.New("synthetic failure")
	for _, tc := range []struct {
		name string
		kv   *ensureAPIKeyKV
		want error
	}{
		{"create error", &ensureAPIKeyKV{createErr: failure}, failure},
		{"collision read error", &ensureAPIKeyKV{winner: "{}", collisionReadErr: failure}, failure},
		{"collision deleted", &ensureAPIKeyKV{winner: "{}", collisionReadErr: ErrKeyNotFound}, ErrKeyNotFound},
		{"collision malformed", &ensureAPIKeyKV{winner: "{"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EnsureAPIKey(context.Background(), tc.kv, "sk_synthetic", "new", "test")
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if tc.kv.writes != 0 || tc.kv.creates != 1 {
				t.Fatalf("unexpected mutation or retry: %+v", tc.kv)
			}
		})
	}
}
