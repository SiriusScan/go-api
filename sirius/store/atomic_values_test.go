package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

func atomicString(s string) *string { return &s }

func TestAtomicValueArguments(t *testing.T) {
	keys, args, err := atomicValueArguments(map[string]*string{"z": nil, "a": atomicString(""), "r": atomicString("guard")}, map[string]*string{"z": atomicString("created"), "a": nil})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keys, []string{"a", "r", "z"}) || !reflect.DeepEqual(args, []string{"value", "", "delete", "", "value", "guard", "keep", "", "absent", "", "set", "created"}) {
		t.Fatalf("unexpected encoding: %q / %q", keys, args)
	}
	if _, _, err := atomicValueArguments(nil, map[string]*string{"unguarded": nil}); err == nil {
		t.Fatal("unguarded deletion accepted")
	}
	kv := &valkeyStore{}
	if ok, err := kv.CompareAndSwapValues(context.Background(), nil, nil); !ok || err != nil {
		t.Fatalf("empty batch: %v / %v", ok, err)
	}
	if ok, err := kv.CompareAndSwapValues(context.Background(), nil, map[string]*string{"unguarded": atomicString("x")}); ok || err == nil {
		t.Fatal("unguarded write accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := kv.CompareAndSwapValues(ctx, nil, nil); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v / %v", ok, err)
	}
}

// The address must point to a disposable, isolated server, never an application
// store. Each invocation uses unique keys and cleans them up, so -count and
// independent concurrent test processes do not contaminate one another.
func TestAtomicValuesIsolated(t *testing.T) {
	address := os.Getenv("SIRIUS_TEST_ATOMIC_ISOLATED_ADDR")
	if address == "" {
		t.Skip("set SIRIUS_TEST_ATOMIC_ISOLATED_ADDR to a disposable isolated server")
	}
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{address}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	kv := &valkeyStore{client: client}
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	prefix := "sirius:test:atomic:" + hex.EncodeToString(suffix[:]) + ":"
	key := func(name string) string { return prefix + name }
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, name := range []string{"a", "z", "new", "missing", "aa", "zz-list", "ttl", "generation", "manifest", "validation-a", "validation-z"} {
			if err := kv.DeleteValue(cleanup, key(name)); err != nil {
				t.Errorf("cleanup %s: %v", name, err)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	set := func(t *testing.T, key, value string) {
		t.Helper()
		if err := kv.SetValue(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	check := func(t *testing.T, key string, want *string) {
		t.Helper()
		got, err := kv.GetValue(ctx, key)
		if want == nil {
			if !errors.Is(err, ErrKeyNotFound) {
				t.Fatalf("%s expected absent: %+v / %v", key, got, err)
			}
			return
		}
		if err != nil || got.Message.Value != *want {
			t.Fatalf("%s got %+v / %v, want %q", key, got, err, *want)
		}
	}
	cas := func(t *testing.T, expected, updates map[string]*string, want bool) {
		t.Helper()
		ok, err := kv.CompareAndSwapValues(ctx, expected, updates)
		if err != nil || ok != want {
			t.Fatalf("CAS got %t / %v, want %t", ok, err, want)
		}
	}
	t.Run("absence empty collision and all or none", func(t *testing.T) {
		set(t, key("a"), "")
		set(t, key("z"), "original")
		cas(t, map[string]*string{key("a"): nil, key("new"): nil}, map[string]*string{key("new"): atomicString("bad")}, false)
		check(t, key("new"), nil)
		cas(t, map[string]*string{key("missing"): atomicString("")}, nil, false)
		cas(t, map[string]*string{key("a"): atomicString(""), key("z"): atomicString("wrong")}, map[string]*string{key("a"): atomicString("bad"), key("z"): nil}, false)
		check(t, key("a"), atomicString(""))
		check(t, key("z"), atomicString("original"))
		cas(t, map[string]*string{key("a"): atomicString(""), key("z"): atomicString("original"), key("new"): nil}, map[string]*string{key("a"): nil, key("new"): atomicString("")}, true)
		check(t, key("a"), nil)
		check(t, key("new"), atomicString(""))
		check(t, key("z"), atomicString("original"))
	})
	t.Run("wrong type validates before mutation", func(t *testing.T) {
		set(t, key("aa"), "original")
		if err := client.Do(ctx, client.B().Lpush().Key(key("zz-list")).Element("x").Build()).Error(); err != nil {
			t.Fatal(err)
		}
		ok, err := kv.CompareAndSwapValues(ctx, map[string]*string{key("aa"): atomicString("original"), key("zz-list"): nil}, map[string]*string{key("aa"): atomicString("bad")})
		if ok || err == nil {
			t.Fatalf("wrong type accepted: %t / %v", ok, err)
		}
		check(t, key("aa"), atomicString("original"))
	})
	t.Run("ttl and cancellation", func(t *testing.T) {
		if err := kv.SetValueWithTTL(ctx, key("ttl"), "before", 60); err != nil {
			t.Fatal(err)
		}
		cas(t, map[string]*string{key("ttl"): atomicString("before")}, map[string]*string{key("ttl"): atomicString("after")}, true)
		if ttl, err := kv.GetTTL(ctx, key("ttl")); err != nil || ttl <= 0 || ttl > 60 {
			t.Fatalf("TTL lost: %d / %v", ttl, err)
		}
		canceled, stop := context.WithCancel(ctx)
		stop()
		if ok, err := kv.CompareAndSwapValues(canceled, map[string]*string{key("ttl"): atomicString("after")}, map[string]*string{key("ttl"): nil}); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %t / %v", ok, err)
		}
		check(t, key("ttl"), atomicString("after"))
	})
	t.Run("concurrent exactly one batch winner", func(t *testing.T) {
		set(t, key("generation"), "old")
		var winners atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := kv.CompareAndSwapValues(ctx, map[string]*string{key("generation"): atomicString("old"), key("manifest"): nil}, map[string]*string{key("generation"): atomicString(key("new")), key("manifest"): atomicString("complete")})
				if err != nil {
					t.Error(err)
				}
				if ok {
					winners.Add(1)
				}
			}()
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("winners = %d", winners.Load())
		}
		check(t, key("generation"), atomicString(key("new")))
		check(t, key("manifest"), atomicString("complete"))
	})
	t.Run("invalid script input cannot partially mutate", func(t *testing.T) {
		set(t, key("validation-a"), "before")
		set(t, key("validation-z"), "before")
		err := atomicValues.Exec(ctx, client, []string{key("validation-a"), key("validation-z")}, []string{"value", "before", "set", "bad", "value", "before", "invalid", "bad"}).Error()
		if err == nil {
			t.Fatal("invalid operation accepted")
		}
		check(t, key("validation-a"), atomicString("before"))
		check(t, key("validation-z"), atomicString("before"))
	})
}
