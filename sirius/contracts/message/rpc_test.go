package message

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestReplyRouterCorrelatesConcurrentRequests(t *testing.T) {
	var router ReplyRouter
	const count = 100
	requests := make([]RPCRequest, count)
	waiters := make([]*ReplyWaiter, count)
	for i := 0; i < count; i++ {
		var err error
		requests[i], waiters[i], err = router.Register("exclusive-reply")
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := router.Deliver(requests[i].CorrelationID, []byte(requests[i].CorrelationID)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	for i, w := range waiters {
		value, err := w.Wait(context.Background())
		if err != nil || string(value) != requests[i].CorrelationID || requests[i].ReplyTo != "exclusive-reply" {
			t.Fatalf("cross delivery at %d: %q %v", i, value, err)
		}
	}
	if err := router.Deliver(requests[0].CorrelationID, nil); !errors.Is(err, ErrUnknownCorrelation) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestReplyRouterCancellationRemovesRegistration(t *testing.T) {
	var router ReplyRouter
	if _, _, err := router.Register(""); err == nil {
		t.Fatal("empty destination accepted")
	}
	req, w, err := router.Register("exclusive-reply")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait: %v", err)
	}
	if err := router.Deliver(req.CorrelationID, nil); !errors.Is(err, ErrUnknownCorrelation) {
		t.Fatalf("late reply: %v", err)
	}
}
