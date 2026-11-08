package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

// This opt-in test uses only a fresh random, expiring key. It never reads or
// writes currentScan or other application keys. Unit suites need no live store.
func TestCompareAndSetValueIntegration(t *testing.T) {
	address := os.Getenv("SIRIUS_TEST_VALKEY_ADDR")
	if address == "" {
		t.Skip("set SIRIUS_TEST_VALKEY_ADDR for isolated-key CAS integration test")
	}
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{address}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	kv := &valkeyStore{client: client}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	key := "sirius:test:cas:" + hex.EncodeToString(suffix[:])
	defer kv.DeleteValue(context.Background(), key)
	if ok, err := kv.CompareAndSetValue(ctx, key, "", "new"); err != nil || ok {
		t.Fatalf("missing key matched: %t / %v", ok, err)
	}
	if err := kv.SetValueWithTTL(ctx, key, "original", 60); err != nil {
		t.Fatal(err)
	}
	if ok, err := kv.CompareAndSetValue(ctx, key, "wrong", "new"); err != nil || ok {
		t.Fatalf("mismatch matched: %t / %v", ok, err)
	}
	if ok, err := kv.CompareAndSetValue(ctx, key, "original", "updated"); err != nil || !ok {
		t.Fatalf("matching CAS failed: %t / %v", ok, err)
	}
	if ttl, err := kv.GetTTL(ctx, key); err != nil || ttl <= 0 || ttl > 60 {
		t.Fatalf("TTL lost: %d / %v", ttl, err)
	}
	if resp, err := kv.GetValue(ctx, key); err != nil || resp.Message.Value != "updated" {
		t.Fatalf("wrong value: %+v / %v", resp, err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := kv.CompareAndSetValue(ctx, key, "updated", "winner")
			if err != nil {
				t.Error(err)
			}
			if ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("expected one concurrent winner, got %d", successes.Load())
	}
	if err := kv.DeleteValue(ctx, key); err != nil {
		t.Fatal(err)
	}
	if ok, err := kv.CompareAndSetValue(ctx, key, "winner", "resurrected"); err != nil || ok {
		t.Fatalf("deleted key resurrected: %t / %v", ok, err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if ok, err := kv.CompareAndSetValue(cancelled, key, "winner", "changed"); err == nil || ok {
		t.Fatalf("cancelled operation succeeded: %t / %v", ok, err)
	}
}
