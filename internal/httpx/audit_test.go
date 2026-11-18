package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Every Do call is recorded exactly once, whether it was sent or refused, and
// a refusal is recorded as a refusal rather than as a request that failed.
func TestEveryCallIsAuditedOnceIncludingRefusals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	var recs []AuditRecord
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) {
		o.MaxRequests = 2
		o.Audit = func(r AuditRecord) error { recs = append(recs, r); return nil }
	})
	defer c.Close()

	ctx := context.Background()
	_, _ = c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/a", Identity: "alice"})
	_, _ = c.Do(ctx, Request{Method: "POST", URL: srv.URL + "/b", Body: []byte(`{}`)}) // guard: nil fails closed
	_, _ = c.Do(ctx, Request{Method: "GET", URL: "http://203.0.113.9/"})               // out of scope
	_, _ = c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/c"})
	_, _ = c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/d"}) // over budget

	want := []struct {
		outcome, identity string
		status            int
	}{
		{"sent", "alice", http.StatusTeapot},
		{"refused", "anonymous", 0},
		{"refused", "anonymous", 0},
		{"sent", "anonymous", http.StatusTeapot},
		{"refused", "anonymous", 0},
	}
	if len(recs) != len(want) {
		t.Fatalf("records = %d, want %d: %+v", len(recs), len(want), recs)
	}
	for i, w := range want {
		r := recs[i]
		if r.Seq != int64(i+1) || r.Outcome != w.outcome || r.Identity != w.identity || r.Status != w.status {
			t.Errorf("record %d = %+v, want seq %d %s as %s status %d", i, r, i+1, w.outcome, w.identity, w.status)
		}
		if r.Outcome == "refused" && r.Reason == "" {
			t.Errorf("record %d is a refusal with no reason", i)
		}
	}
}

// A request log that cannot be written stops the client: nothing is sent once
// the log has a gap.
func TestAuditFailureStopsFurtherRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) {
		o.Audit = func(AuditRecord) error { return errors.New("disk full") }
	})
	defer c.Close()

	_, _ = c.Do(context.Background(), Request{Method: "GET", URL: srv.URL + "/"})
	_, err := c.Do(context.Background(), Request{Method: "GET", URL: srv.URL + "/"})
	if !NotSent(err) {
		t.Fatalf("err = %v, want a not-sent refusal after the log failed", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("the target received %d requests, want 1", got)
	}
}
