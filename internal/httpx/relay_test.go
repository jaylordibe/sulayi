package httpx

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

// The browser never changes the target, whatever the profile: aggressive
// permits state-changing requests to the assessment, not to a page's scripts.
func TestRelayRefusesStateChangingRequestsInEveryProfile(t *testing.T) {
	for _, p := range []model.Profile{model.ProfileSafe, model.ProfileStandard, model.ProfileAggressive} {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
		g, err := NewGuard(p, []string{"GET /api/logout"})
		if err != nil {
			t.Fatal(err)
		}
		var recs []AuditRecord
		c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) {
			o.Guard = g
			o.Audit = func(r AuditRecord) error { recs = append(recs, r); return nil }
		})
		for _, r := range []struct{ method, path string }{
			{"POST", "/api/items"}, {"DELETE", "/api/items/1"}, {"PUT", "/api/items/1"},
			{"PATCH", "/api/items/1"}, {"GET", "/api/logout"},
		} {
			_, err := c.Relay(context.Background(), Request{Method: r.method, URL: srv.URL + r.path})
			var refused *ErrRefused
			if !errors.As(err, &refused) {
				t.Errorf("%s: %s %s: err = %v, want a refusal", p, r.method, r.path, err)
			}
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("%s: the target received %d request(s)", p, n)
		}
		if len(recs) != 5 {
			t.Errorf("%s: %d audit record(s), want one per refused request", p, len(recs))
		}
		for _, r := range recs {
			if r.Outcome != "refused" {
				t.Errorf("%s: outcome %q, want refused", p, r.Outcome)
			}
		}
		c.Close()
		srv.Close()
	}
}

func TestRelayPassesScopeAndReturnsTheRawResponse(t *testing.T) {
	bundle := bytes.Repeat([]byte("x"), 2*DefaultMaxBodyBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc")
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), nil)
	defer c.Close()

	got, err := c.Relay(context.Background(), Request{Method: "GET", URL: srv.URL + "/main.js"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, bundle) {
		t.Errorf("body = %d bytes, want the whole %d-byte bundle", len(got.Body), len(bundle))
	}
	if got.Header.Get("Set-Cookie") != "sid=abc" {
		t.Errorf("headers were not returned raw: %v", got.Header)
	}

	_, err = c.Relay(context.Background(), Request{Method: "GET", URL: "http://example.com/"})
	var oos *ErrOutOfScope
	if !errors.As(err, &oos) {
		t.Errorf("off-scope relay: err = %v, want out of scope", err)
	}
}

func TestRelayRefusesAResponseOverItsLimit(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxRelayBodyBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) }))
	defer srv.Close()
	var recs []AuditRecord
	c := newClient(t, loopbackPolicy(t, portOf(t, srv.URL)), func(o *Options) {
		o.Audit = func(r AuditRecord) error { recs = append(recs, r); return nil }
	})
	defer c.Close()
	_, err := c.Relay(context.Background(), Request{Method: "GET", URL: srv.URL + "/huge"})
	var tooLarge *ErrRelayTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("err = %v, want the too-large error, which is not a refusal: the request was sent", err)
	}
	if len(recs) != 1 || recs[0].Outcome != "sent" || recs[0].Reason == "" {
		t.Errorf("audit = %+v, want one sent record with the reason it was not delivered", recs)
	}
}
