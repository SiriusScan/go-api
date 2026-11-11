package message

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

var ErrUnknownCorrelation = errors.New("unknown or already completed correlation ID")

// RPCRequest identifies one request and the reply destination chosen by its
// caller. Reply destinations must be private to the caller or have a consumer
// that routes every delivery through the same ReplyRouter.
type RPCRequest struct {
	CorrelationID string
	ReplyTo       string
}

// ReplyRouter dispatches replies to registered requests without consuming a
// reply for an unrelated request. Its zero value is ready to use.
type ReplyRouter struct {
	mu      sync.Mutex
	pending map[string]chan []byte
}

// Register creates a fresh correlation and returns its request metadata and a
// waiter. The caller must eventually call Wait, including when publishing fails.
func (r *ReplyRouter) Register(replyTo string) (RPCRequest, *ReplyWaiter, error) {
	if replyTo == "" {
		return RPCRequest{}, nil, errors.New("reply destination is required")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return RPCRequest{}, nil, fmt.Errorf("generate correlation ID: %w", err)
	}
	id := hex.EncodeToString(random[:])
	ch := make(chan []byte, 1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = make(map[string]chan []byte)
	}
	if _, exists := r.pending[id]; exists {
		return RPCRequest{}, nil, errors.New("duplicate correlation ID")
	}
	r.pending[id] = ch
	return RPCRequest{CorrelationID: id, ReplyTo: replyTo}, &ReplyWaiter{router: r, id: id, replies: ch}, nil
}

// Deliver sends a reply only to the waiter with the matching correlation ID.
// Duplicate, late, and unsolicited replies are rejected.
func (r *ReplyRouter) Deliver(correlationID string, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.pending[correlationID]
	if !ok {
		return ErrUnknownCorrelation
	}
	delete(r.pending, correlationID)
	ch <- append([]byte(nil), payload...)
	return nil
}

// ReplyWaiter is a single-use handle returned by Register.
type ReplyWaiter struct {
	router  *ReplyRouter
	id      string
	replies <-chan []byte
}

// Wait returns the matched reply or context cancellation. Cancellation removes
// its registration; a later delivery will be rejected.
func (w *ReplyWaiter) Wait(ctx context.Context) ([]byte, error) {
	select {
	case reply := <-w.replies:
		return reply, nil
	case <-ctx.Done():
		w.router.mu.Lock()
		delete(w.router.pending, w.id)
		w.router.mu.Unlock()
		return nil, ctx.Err()
	}
}
