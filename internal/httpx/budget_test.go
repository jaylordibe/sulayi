package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The budget is a hard limit on what reaches the target: a refused request is
// never sent, and the refusal says the budget was the reason.
func TestBudgetRefusesBeyondTheLimitAndSendsNothing(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) {
		o.MaxRequests = 2
		o.CleanupAllowance = 1
	})
	defer c.Close()

	get := func(ctx context.Context) error {
		_, err := c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/"})
		return err
	}
	for i := 0; i < 2; i++ {
		if err := get(context.Background()); err != nil {
			t.Fatalf("request %d within the budget: %v", i+1, err)
		}
	}
	err := get(context.Background())
	var spent *ErrBudgetExceeded
	if !errors.As(err, &spent) || !NotSent(err) {
		t.Fatalf("over budget: err = %v, want a budget refusal that was not sent", err)
	}

	// Cleanup draws on its own allowance once the budget is spent, and that
	// allowance is itself finite.
	if err := get(Cleanup(context.Background())); err != nil {
		t.Fatalf("cleanup within its allowance was refused: %v", err)
	}
	if err := get(Cleanup(context.Background())); !errors.As(err, &spent) || !spent.Cleanup {
		t.Fatalf("cleanup beyond its allowance: err = %v, want a cleanup budget refusal", err)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("the target received %d requests, want 3", got)
	}
	u := c.Usage()
	if u.Used != 2 || u.CleanupUsed != 1 || u.Limit != 2 || u.CleanupAllowance != 1 {
		t.Errorf("usage = %+v", u)
	}
}

// A request cancelled while waiting for its pacing slot never left the process,
// and says so: that is what lets a write's caller know there is nothing to
// clean up.
func TestCancelledPacingWaitIsNotSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) { o.RequestsPerSecond = 0.001 })
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/"})
	if !NotSent(err) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want a not-sent cancellation", err)
	}
}

func TestNotSentIsFalseForTransportFailures(t *testing.T) {
	if NotSent(nil) {
		t.Error("nil was reported as not sent")
	}
	if NotSent(errors.New("connection reset")) {
		t.Error("an ordinary transport failure was reported as not sent; it may have reached the target")
	}
}
