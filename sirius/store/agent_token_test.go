package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// All tokens and stores in these tests are synthetic and local to the test.
type enrollmentKV struct {
	KVStore
	mu                         sync.Mutex
	data                       map[string]string
	readErr, createErr         error
	writes, creates, refreshes int
	afterRead                  func(map[string]string, string)
}

func (s *enrollmentKV) GetValue(ctx context.Context, key string) (ValkeyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ValkeyResponse{}, err
	}
	if s.readErr != nil {
		return ValkeyResponse{}, s.readErr
	}
	value, ok := s.data[key]
	if !ok {
		return ValkeyResponse{}, fmt.Errorf("missing fixture: %w", ErrKeyNotFound)
	}
	if s.afterRead != nil {
		s.afterRead(s.data, key)
	}
	return ValkeyResponse{Message: ValkeyValue{Value: value}}, nil
}
func (s *enrollmentKV) SetValue(context.Context, string, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	return errors.New("unconditional writes forbidden")
}
func (s *enrollmentKV) SetValueIfAbsent(ctx context.Context, key, value string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates++
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.createErr != nil {
		return false, s.createErr
	}
	if _, ok := s.data[key]; ok {
		return false, nil
	}
	s.data[key] = value
	return true, nil
}
func (s *enrollmentKV) CompareAndSetValue(ctx context.Context, key, expected, value string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshes++
	if err := ctx.Err(); err != nil {
		return false, err
	}
	old, ok := s.data[key]
	if !ok || old != expected {
		return false, nil
	}
	s.data[key] = value
	return true, nil
}

func TestAgentTokenExistsFailsClosed(t *testing.T) {
	outage := errors.New("synthetic outage")
	for _, tc := range []struct {
		name, value             string
		present                 bool
		readErr                 error
		exists, wantErr, legacy bool
	}{
		{name: "absent"},
		{name: "existing", present: true, value: `{"token":"fake-token"}`, exists: true, legacy: true},
		{name: "malformed", present: true, value: `malformed`, exists: true, legacy: true},
		{name: "outage", readErr: outage, wantErr: true, legacy: true},
		{name: "untyped missing", readErr: errors.New("not found"), wantErr: true, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kv := &enrollmentKV{data: map[string]string{}, readErr: tc.readErr}
			if tc.present {
				kv.data[agentTokenKey("fixture")] = tc.value
			}
			exists, err := AgentTokenExists(context.Background(), kv, "fixture")
			if exists != tc.exists || (err != nil) != tc.wantErr {
				t.Fatalf("exists=%v err=%v", exists, err)
			}
			if got := HasAgentToken(context.Background(), kv, "fixture"); got != tc.legacy {
				t.Fatalf("legacy=%v", got)
			}
			if tc.readErr != nil && !errors.Is(err, tc.readErr) {
				t.Fatal("read error was not preserved")
			}
		})
	}
}

func TestStoreAgentTokenIfAbsentOneConcurrentWinner(t *testing.T) {
	kv := &enrollmentKV{data: map[string]string{}}
	var winners atomic.Int32
	var wg sync.WaitGroup
	var winner string
	var mu sync.Mutex
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("fake-token-%d", i)
			ok, err := StoreAgentTokenIfAbsent(context.Background(), kv, "fixture", token)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				winners.Add(1)
				mu.Lock()
				winner = token
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
	meta, err := GetAgentToken(context.Background(), kv, "fixture")
	if err != nil || meta.Token != winner || meta.AgentID != "fixture" || meta.CreatedAt == "" {
		t.Fatalf("unexpected winner metadata: %v", err)
	}
	if kv.writes != 0 {
		t.Fatal("used unconditional write")
	}
}

func TestStoreAgentTokenIfAbsentRejectsUnsafeStorage(t *testing.T) {
	ctx := context.Background()
	plain := newMemoryKV()
	if ok, err := StoreAgentTokenIfAbsent(ctx, plain, "fixture", "fake-token"); ok || err == nil {
		t.Fatal("store without atomic create accepted")
	}
	kv := &enrollmentKV{data: map[string]string{}, createErr: errors.New("synthetic write failure")}
	if ok, err := StoreAgentTokenIfAbsent(ctx, kv, "fixture", "fake-token"); ok || !errors.Is(err, kv.createErr) {
		t.Fatalf("write error lost: %v", err)
	}
	if len(kv.data) != 0 || kv.writes != 0 {
		t.Fatal("unsafe fallback write")
	}
	kv.createErr = nil
	for _, tc := range [][2]string{{"", "fake-token"}, {"fixture", ""}} {
		if ok, err := StoreAgentTokenIfAbsent(ctx, kv, tc[0], tc[1]); ok || err == nil {
			t.Fatal("empty identifier/token accepted")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if ok, err := StoreAgentTokenIfAbsent(cancelled, kv, "fixture", "fake-token"); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestValidateAgentTokenDoesNotRestoreChangedRecords(t *testing.T) {
	original, _ := json.Marshal(AgentTokenMeta{AgentID: "fixture", Token: "fake-original", LastSeen: "old"})
	for _, change := range []string{"deleted", "replaced", "unchanged"} {
		t.Run(change, func(t *testing.T) {
			kv := &enrollmentKV{data: map[string]string{agentTokenKey("fixture"): string(original)}}
			kv.afterRead = func(data map[string]string, key string) {
				if change == "deleted" {
					delete(data, key)
				}
				if change == "replaced" {
					data[key] = `{"agent_id":"fixture","token":"fake-replacement"}`
				}
			}
			if _, err := ValidateAgentToken(context.Background(), kv, "fixture", "fake-original"); err != nil {
				t.Fatal(err)
			}
			raw, exists := kv.data[agentTokenKey("fixture")]
			if change == "deleted" && exists {
				t.Fatal("deleted token restored")
			}
			if change == "replaced" && raw != `{"agent_id":"fixture","token":"fake-replacement"}` {
				t.Fatal("replacement overwritten")
			}
			if change == "unchanged" && raw == string(original) {
				t.Fatal("last-seen was not refreshed")
			}
			if kv.writes != 0 || kv.refreshes != 1 {
				t.Fatal("unsafe last-seen update")
			}
		})
	}
	// A legacy KVStore can validate, but cannot safely refresh LastSeen.
	plain := newMemoryKV()
	plain.data[agentTokenKey("fixture")] = string(original)
	if _, err := ValidateAgentToken(context.Background(), plain, "fixture", "fake-original"); err != nil {
		t.Fatal(err)
	}
	if plain.data[agentTokenKey("fixture")] != string(original) {
		t.Fatal("legacy store performed unconditional refresh")
	}
}
