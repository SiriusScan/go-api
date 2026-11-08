package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// All keys and records in these tests are synthetic. The fixture can pause one
// GET after taking its snapshot, making concurrent revocation/replacement
// deterministic without sleeps or a live Valkey.
type apiKeyValidationKV struct {
	KVStore
	mu           sync.Mutex
	data         map[string]string
	readErr      error
	casErr       error
	writes       int
	refreshes    int
	lastExpected string
	pauseRead    bool
	readCaptured chan struct{}
	resumeRead   chan struct{}
}

func (s *apiKeyValidationKV) GetValue(ctx context.Context, key string) (ValkeyResponse, error) {
	s.mu.Lock()
	if s.readErr != nil {
		err := s.readErr
		s.mu.Unlock()
		return ValkeyResponse{}, err
	}
	value, exists := s.data[key]
	pause := s.pauseRead && exists
	if pause {
		s.pauseRead = false
	}
	s.mu.Unlock()
	if !exists {
		return ValkeyResponse{}, ErrKeyNotFound
	}
	if pause {
		close(s.readCaptured)
		select {
		case <-s.resumeRead:
		case <-ctx.Done():
			return ValkeyResponse{}, ctx.Err()
		}
	}
	return ValkeyResponse{Message: ValkeyValue{Value: value}}, nil
}

func (s *apiKeyValidationKV) SetValue(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	s.data[key] = value
	return nil
}

func (s *apiKeyValidationKV) DeleteValue(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *apiKeyValidationKV) CompareAndSetValue(ctx context.Context, key, expected, value string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshes++
	s.lastExpected = expected
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.casErr != nil {
		return false, s.casErr
	}
	current, exists := s.data[key]
	if !exists || current != expected {
		return false, nil
	}
	s.data[key] = value
	return true, nil
}

func apiKeyValidationFixture(t *testing.T, rawKey string) (*apiKeyValidationKV, APIKeyMeta, string) {
	t.Helper()
	meta := APIKeyMeta{
		ID: hashKey(rawKey), Label: "synthetic key", Prefix: "sk_fake_",
		CreatedBy: "test", CreatedAt: "2020-01-01T00:00:00Z",
		LastUsedAt: "2020-01-01T00:00:00Z",
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	// Noncanonical formatting ensures CAS uses the exact stored bytes, not a
	// reserialized copy of the metadata.
	original := " \n" + string(data) + "\n"
	kv := &apiKeyValidationKV{data: map[string]string{valkeyKey(meta.ID): original}}
	return kv, meta, original
}

func TestValidateAPIKeyDoesNotRestoreConcurrentRevocationOrReplacement(t *testing.T) {
	for _, change := range []string{"revoke", "replace with restricted metadata"} {
		t.Run(change, func(t *testing.T) {
			const rawKey = "sk_fake_validation_race"
			ctx := context.Background()
			kv, originalMeta, original := apiKeyValidationFixture(t, rawKey)
			kv.pauseRead = true
			kv.readCaptured = make(chan struct{})
			kv.resumeRead = make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(kv.resumeRead) }) }
			t.Cleanup(release)
			done := make(chan error, 1)
			go func() {
				_, err := ValidateAPIKey(ctx, kv, rawKey)
				done <- err
			}()
			select {
			case <-kv.readCaptured:
			case <-time.After(5 * time.Second):
				t.Fatal("validator did not capture metadata")
			}

			key := valkeyKey(originalMeta.ID)
			var replacement string
			switch change {
			case "revoke":
				if err := RevokeAPIKey(ctx, kv, originalMeta.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := kv.GetValue(ctx, key); !errors.Is(err, ErrKeyNotFound) {
					t.Fatalf("revocation did not remove key: %v", err)
				}
			default:
				if _, err := StoreAPIKeyWithScopes(ctx, kv, rawKey, "restricted replacement", "test replacement", []string{ScopeMCPRead}); err != nil {
					t.Fatal(err)
				}
				response, err := kv.GetValue(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
				replacement = response.Message.Value
			}
			release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("validation of captured metadata failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("validator did not finish")
			}

			kv.mu.Lock()
			stored, exists := kv.data[key]
			writes, refreshes, expected := kv.writes, kv.refreshes, kv.lastExpected
			kv.mu.Unlock()
			wantWrites := 0
			if change != "revoke" {
				wantWrites = 1 // The explicit replacement, never the stale touch.
			}
			if writes != wantWrites || refreshes != 1 || expected != original {
				t.Errorf("unsafe touch: writes=%d refreshes=%d exact snapshot=%v", writes, refreshes, expected == original)
			}
			if change == "revoke" {
				if exists {
					t.Error("successful revocation was undone by stale validation")
				}
				if _, err := ValidateAPIKey(ctx, kv, rawKey); !errors.Is(err, ErrKeyNotFound) {
					t.Fatalf("revoked key was accepted by fresh validation: %v", err)
				}
			} else {
				if !exists || stored != replacement {
					t.Error("concurrent replacement metadata was overwritten")
				}
				loaded, err := ValidateAPIKey(ctx, kv, rawKey)
				if err != nil || loaded.AllowsUnrestricted() || !loaded.HasScope(ScopeMCPRead) || loaded.Label != "restricted replacement" {
					t.Fatalf("fresh validation lost replacement restrictions: meta=%+v err=%v", loaded, err)
				}
			}
		})
	}
}

func TestValidateAPIKeyConditionalLastUsed(t *testing.T) {
	const rawKey = "sk_fake_conditional_touch"
	for _, mode := range []string{"supported", "CAS failure", "legacy store"} {
		t.Run(mode, func(t *testing.T) {
			kv, originalMeta, original := apiKeyValidationFixture(t, rawKey)
			var backend KVStore = kv
			switch mode {
			case "CAS failure":
				kv.casErr = errors.New("synthetic CAS outage")
			case "legacy store":
				// Expose only KVStore, hiding the optional atomic capability.
				backend = struct{ KVStore }{kv}
			}
			loaded, err := ValidateAPIKey(context.Background(), backend, rawKey)
			if err != nil {
				t.Fatalf("best-effort last-used update failed validation: %v", err)
			}
			if _, err := time.Parse(time.RFC3339, loaded.LastUsedAt); err != nil || loaded.LastUsedAt == originalMeta.LastUsedAt {
				t.Fatalf("last-used timestamp was not refreshed: %q", loaded.LastUsedAt)
			}
			stored := kv.data[valkeyKey(originalMeta.ID)]
			if mode == "supported" {
				var persisted APIKeyMeta
				if err := json.Unmarshal([]byte(stored), &persisted); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(persisted, loaded) {
					t.Fatalf("persisted metadata differs from validation: %+v vs %+v", persisted, loaded)
				}
			} else if stored != original {
				t.Fatal("unsafe unconditional last-used fallback changed metadata")
			}
			loaded.LastUsedAt = originalMeta.LastUsedAt
			if !reflect.DeepEqual(loaded, originalMeta) {
				t.Fatal("last-used update changed unrelated metadata")
			}
			wantRefreshes := 1
			if mode == "legacy store" {
				wantRefreshes = 0
			}
			if kv.writes != 0 || kv.refreshes != wantRefreshes {
				t.Fatalf("writes=%d refreshes=%d; want no writes and %d refreshes", kv.writes, kv.refreshes, wantRefreshes)
			}
			if mode != "legacy store" && kv.lastExpected != original {
				t.Fatal("conditional update did not compare the exact stored record")
			}
		})
	}
}

func TestValidateAPIKeyInvalidRecordsAreNotTouched(t *testing.T) {
	for _, mode := range []string{"missing", "read failure", "malformed JSON"} {
		t.Run(mode, func(t *testing.T) {
			const rawKey = "sk_fake_invalid_record"
			kv := &apiKeyValidationKV{data: map[string]string{}}
			switch mode {
			case "read failure":
				kv.readErr = errors.New("synthetic read outage")
			case "malformed JSON":
				kv.data[valkeyKey(hashKey(rawKey))] = "malformed"
			}
			if _, err := ValidateAPIKey(context.Background(), kv, rawKey); err == nil {
				t.Fatal("invalid record was accepted")
			}
			if kv.writes != 0 || kv.refreshes != 0 {
				t.Fatal("invalid record was touched")
			}
		})
	}
}
