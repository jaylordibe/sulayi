package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// An error returned by Do reaches ledger details and the report, so its text
// must already be redacted. Go's url.Error renders the full request URL; here
// the URL carries a secret in its query and a registered secret in its path, and
// the server drops the connection so a url.Error is what comes back.
func TestErrorsLeaveDoRedacted(t *testing.T) {
	const querySecret = "q5ecret-query-value-0123456789"
	const pathSecret = "p5ecret-path-value-0123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("no hijacker")
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), nil)
	defer c.Close()
	c.red.Register(pathSecret, "[REDACTED]")

	_, err := c.Do(context.Background(), Request{Method: "GET",
		URL: srv.URL + "/orders/" + pathSecret + "?access_token=" + querySecret})
	if err == nil {
		t.Fatal("a dropped connection returned no error")
	}
	if s := err.Error(); strings.Contains(s, querySecret) || strings.Contains(s, pathSecret) {
		t.Fatalf("the error text carries a secret: %q", s)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), querySecret) || strings.Contains(e.Error(), pathSecret) {
			t.Fatalf("a secret is reachable through the error chain: %q", e.Error())
		}
	}

	// Meaning survives redaction: a cancellation is still a cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Do(ctx, Request{Method: "GET", URL: srv.URL + "/"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; redaction lost the cancellation", err)
	}
}
