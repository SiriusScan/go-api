package logging

import (
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

func TestFinalFlushRetainsEventsOnFailure(t *testing.T) {
	t.Parallel()
	ep := &EventPersistence{
		buffer:        []models.Event{{EventID: "final-flush-test"}},
		stopChan:      make(chan bool),
		flushInterval: time.Hour,
	}
	close(ep.stopChan)
	done := make(chan struct{})
	go func() {
		ep.flushRoutine()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("flush routine did not stop after final flush failure")
	}
	if len(ep.buffer) != 1 || ep.buffer[0].EventID != "final-flush-test" {
		t.Fatalf("failed final flush discarded buffered events: %v", ep.buffer)
	}
}
