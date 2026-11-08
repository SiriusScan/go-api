package nvd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type stalledBody struct {
	ctx     context.Context
	entered chan struct{}
	closed  bool
}

func (b *stalledBody) Read([]byte) (int, error) {
	close(b.entered)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *stalledBody) Close() error { b.closed = true; return nil }

func TestGetCVEContextCancelsStalledHeadersAndBody(t *testing.T) {
	for _, mode := range []string{"headers", "body"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var body *stalledBody
			client := &http.Client{Timeout: DefaultRequestTimeout, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if _, ok := r.Context().Deadline(); !ok {
					t.Error("NVD request has no deadline")
				}
				if mode == "headers" {
					close(entered)
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				body = &stalledBody{ctx: r.Context(), entered: entered}
				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
			})}
			done := make(chan error, 1)
			go func() { _, err := getCVE(ctx, "CVE-2024-0001", client); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v, want context.Canceled", err)
				}
				if body != nil && !body.closed {
					t.Error("response body was not closed")
				}
			case <-time.After(time.Second):
				t.Fatal("canceled NVD request did not return")
			}
		})
	}
}

func TestGetCVEBoundsStalledHeadersAndBody(t *testing.T) {
	for _, mode := range []string{"headers", "body"} {
		t.Run(mode, func(t *testing.T) {
			client := &http.Client{Timeout: 25 * time.Millisecond, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if mode == "headers" {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return &http.Response{StatusCode: http.StatusOK, Body: &stalledBody{ctx: r.Context(), entered: make(chan struct{})}, Header: make(http.Header)}, nil
			})}
			started := time.Now()
			_, err := getCVE(context.Background(), "CVE-2024-0001", client)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("got %v, want deadline exceeded", err)
			}
			if time.Since(started) > time.Second {
				t.Fatal("lookup exceeded its bounded client deadline")
			}
		})
	}
}

func TestGetCVEHonorsEarlierParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		parentDeadline, _ := ctx.Deadline()
		deadline, ok := r.Context().Deadline()
		if !ok || deadline.After(parentDeadline) {
			t.Error("request extended caller deadline")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	_, err := getCVE(ctx, "CVE-2024-0001", client)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
}

func TestGetCVELegacyWrapperIsBoundedAndCompatible(t *testing.T) {
	if defaultClient.Timeout != DefaultRequestTimeout || DefaultRequestTimeout <= 0 {
		t.Fatal("default client is not bounded")
	}
	old := defaultClient
	t.Cleanup(func() { defaultClient = old })
	id := "CVE-2024-0001&extra=value"
	defaultClient = &http.Client{Timeout: DefaultRequestTimeout, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > DefaultRequestTimeout || time.Until(deadline) <= 0 {
			t.Error("legacy request lacks bounded deadline")
		}
		if r.URL.Query().Get("cveId") != id || len(r.URL.Query()) != 1 {
			t.Errorf("incorrect query: %s", r.URL.RawQuery)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("missing Accept header")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001"}}]}`)), Header: make(http.Header)}, nil
	})}
	cve, err := GetCVE(id)
	if err != nil || cve.ID != "CVE-2024-0001" {
		t.Fatalf("got %+v, %v", cve, err)
	}
}

func TestGetCVEContextAlreadyCanceledDoesNotSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("sent a canceled lookup"); return nil, nil })}
	_, err := getCVE(ctx, "CVE-2024-0001", client)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestGetCVEResponseCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantErr    bool
	}{
		{"empty", `{"vulnerabilities":[]}`, 200, false},
		{"bad JSON", `{`, 200, true},
		{"unavailable", `{}`, 503, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			cve, err := getCVE(context.Background(), "CVE-2024-0001", client)
			if (err != nil) != tc.wantErr || cve.ID != "" {
				t.Fatalf("got %+v, %v", cve, err)
			}
		})
	}
}
