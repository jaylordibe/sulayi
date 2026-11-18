package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

// guardFixture is a target that counts every request it receives, so a test can
// assert that a refused request never reached it rather than merely that an
// error came back.
type guardFixture struct {
	srv  *httptest.Server
	hits atomic.Int64
	c    *Client
}

func newGuardFixture(t *testing.T, g *Guard) *guardFixture {
	t.Helper()
	f := &guardFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(f.srv.Close)
	f.c = newClient(t, loopbackPolicy(t, portOf(t, f.srv.URL)), func(o *Options) { o.Guard = g })
	t.Cleanup(f.c.Close)
	return f
}

func (f *guardFixture) do(t *testing.T, method, path string, body string) error {
	t.Helper()
	_, err := f.c.Do(context.Background(), Request{Method: method, URL: f.srv.URL + path, Body: []byte(body)})
	return err
}

// expectRefused asserts the request was refused by the guard and sent nothing.
func (f *guardFixture) expectRefused(t *testing.T, method, path, body string) {
	t.Helper()
	before := f.hits.Load()
	err := f.do(t, method, path, body)
	var refused *ErrRefused
	if !errors.As(err, &refused) {
		t.Errorf("%s %s %q: err = %v, want a safety refusal", method, path, body, err)
	}
	if n := f.hits.Load() - before; n != 0 {
		t.Errorf("%s %s %q: the target received %d request(s) after a refusal", method, path, body, n)
	}
}

func (f *guardFixture) expectSent(t *testing.T, method, path, body string) {
	t.Helper()
	before := f.hits.Load()
	if err := f.do(t, method, path, body); err != nil {
		t.Errorf("%s %s %q: err = %v, want it sent", method, path, body, err)
	}
	if n := f.hits.Load() - before; n != 1 {
		t.Errorf("%s %s %q: the target received %d request(s), want 1", method, path, body, n)
	}
}

func mustGuard(t *testing.T, p model.Profile, stateChanging ...string) *Guard {
	t.Helper()
	g, err := NewGuard(p, stateChanging)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g
}

// A client built without a guard behaves as the safe profile: nothing
// state-changing leaves it.
func TestNilGuardFailsClosed(t *testing.T) {
	f := newGuardFixture(t, nil)
	f.expectSent(t, "GET", "/orders/1", "")
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		f.expectRefused(t, m, "/orders/1", `{"status":"x"}`)
	}
}

// safe refuses every state-changing request, including a read-only method the
// operator named as state-changing.
func TestSafeProfileRefusesEveryStateChangingRequest(t *testing.T) {
	f := newGuardFixture(t, mustGuard(t, model.ProfileSafe, "GET /logout"))
	f.expectSent(t, "GET", "/orders/1", "")
	f.expectRefused(t, "GET", "/logout", "")
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		f.expectRefused(t, m, "/orders/1", `{"status":"x"}`)
	}
}

// A configured state-changing operation is recognised from the URL, including
// path parameters, whatever its method.
func TestConfiguredStateChangingTemplateMatchesConcretePaths(t *testing.T) {
	f := newGuardFixture(t, mustGuard(t, model.ProfileStandard, "GET /orders/{id}/cancel"))
	f.expectRefused(t, "GET", "/orders/7/cancel", "")
	f.expectSent(t, "GET", "/orders/7", "")
}

// standard sends only the exact registered fixture request. Every way of
// reaching a different record, a different query or a different field is
// refused before anything is sent.
func TestStandardProfilePermitsOnlyExactRegisteredFixtureRequests(t *testing.T) {
	g := mustGuard(t, model.ProfileStandard)
	f := newGuardFixture(t, g)
	granted := f.srv.URL + "/orders/1?v=2"
	if err := g.Grant("PATCH", granted, []string{"status", "note"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	g.Seal()

	f.expectSent(t, "PATCH", "/orders/1?v=2", `{"status":"x"}`)
	f.expectSent(t, "patch", "/orders/1?v=2", `{"status":"x","note":"y"}`)

	f.expectRefused(t, "PATCH", "/orders/2?v=2", `{"status":"x"}`)        // another record
	f.expectRefused(t, "PATCH", "/orders/1", `{"status":"x"}`)            // query dropped
	f.expectRefused(t, "PATCH", "/orders/1?v=3", `{"status":"x"}`)        // query changed
	f.expectRefused(t, "PATCH", "/orders/1/?v=2", `{"status":"x"}`)       // trailing slash
	f.expectRefused(t, "PATCH", "/x/../orders/1?v=2", `{"status":"x"}`)   // dot segment
	f.expectRefused(t, "PATCH", "/orders/%2e%2e/1?v=2", `{"status":"x"}`) // encoded dot segment
	f.expectRefused(t, "PUT", "/orders/1?v=2", `{"status":"x"}`)          // another method
	f.expectRefused(t, "PATCH", "/orders/1?v=2", `{"owner":"bob"}`)       // unregistered field
	f.expectRefused(t, "PATCH", "/orders/1?v=2", `{"status":"x","owner":"bob"}`)
	f.expectRefused(t, "PATCH", "/orders/1?v=2", ``)               // no body
	f.expectRefused(t, "PATCH", "/orders/1?v=2", `status=x`)       // not JSON
	f.expectRefused(t, "PATCH", "/orders/1?v=2", `[{"status":1}]`) // not an object
	f.expectRefused(t, "DELETE", "/orders/1?v=2", "")
	f.expectRefused(t, "POST", "/orders", `{"status":"x"}`)
}

// The comparison is on the canonical target, so an explicit default port and
// host case are the same target, while a different port is not.
func TestGrantKeyCanonicalisesOnlyWhatIsEquivalent(t *testing.T) {
	a, err := grantKey("PATCH", "HTTP://Example.TEST/orders/1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := grantKey("PATCH", "http://example.test:80/orders/1")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("equivalent targets differ: %q vs %q", a, b)
	}
	c, _ := grantKey("PATCH", "http://example.test:8080/orders/1")
	if a == c {
		t.Error("a different port compared equal")
	}
	if _, err := grantKey("PATCH", "http://example.test/orders/1#frag"); err == nil {
		t.Error("a fragment was accepted")
	}
}

// Nothing can be registered once the guard is sealed, and standard never
// registers DELETE or a grant that names no fields.
func TestGrantsAreClosedAndNarrow(t *testing.T) {
	g := mustGuard(t, model.ProfileStandard)
	if err := g.Grant("DELETE", "http://x.test/orders/1", []string{"status"}); err == nil {
		t.Error("a DELETE grant was accepted")
	}
	if err := g.Grant("PATCH", "http://x.test/orders/1", nil); err == nil {
		t.Error("a grant naming no fields was accepted")
	}
	g.Seal()
	if err := g.Grant("PATCH", "http://x.test/orders/1", []string{"status"}); err == nil {
		t.Error("a grant was accepted after Seal")
	}
	if err := g.AddStateChangingTemplate("GET /logout"); err == nil {
		t.Error("a rule was added after Seal")
	}
}

// aggressive permits state-changing requests; scope still applies, and is
// asserted by the scope tests.
func TestAggressiveProfilePermitsStateChangingRequests(t *testing.T) {
	f := newGuardFixture(t, mustGuard(t, model.ProfileAggressive, "GET /logout"))
	for i, m := range []string{"POST", "PUT", "PATCH", "DELETE", "GET"} {
		path := "/orders/" + strconv.Itoa(i)
		if m == "GET" {
			path = "/logout"
		}
		f.expectSent(t, m, path, "")
	}
}

func TestMalformedStateChangingOperationIsRejected(t *testing.T) {
	for _, id := range []string{"", "GET", "logout", "GET logout"} {
		if _, err := NewGuard(model.ProfileStandard, []string{id}); err == nil {
			t.Errorf("state-changing operation %q was accepted", id)
		}
	}
}
