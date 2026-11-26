package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// authFixture is a target that counts requests and answers a login with a
// token in its body.
func authFixture(t *testing.T, g *Guard) (*guardFixture, string) {
	t.Helper()
	f := &guardFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.hits.Add(1)
		w.Header().Set("Set-Cookie", "sid=s3ssion-value-0123456789; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"}`))
	}))
	t.Cleanup(f.srv.Close)
	f.c = newClient(t, loopbackPolicy(t, portOf(t, f.srv.URL)), func(o *Options) { o.Guard = g })
	t.Cleanup(f.c.Close)
	return f, f.srv.URL + "/api/auth/login"
}

// The configured login is the one state-changing request safe permits, and it
// returns the raw response — the token redaction would otherwise mask — to the
// caller only.
func TestConfiguredLoginIsPermittedUnderSafe(t *testing.T) {
	g := mustGuard(t, model.ProfileSafe)
	f, login := authFixture(t, g)
	if err := g.AllowAuthentication("POST", login, []string{"identifier", "password"}); err != nil {
		t.Fatal(err)
	}
	g.Seal()

	resp, err := f.c.Authenticate(context.Background(), Request{Method: "POST", URL: login,
		Body: []byte(`{"identifier":"a@example.test","password":"pw"}`)})
	if err != nil {
		t.Fatalf("the configured login was refused under safe: %v", err)
	}
	if !strings.Contains(string(resp.Body), "eyJhbGciOiJIUzI1NiJ9") {
		t.Error("the raw token is not available to the login flow")
	}
	if len(resp.SetCookies) != 1 {
		t.Errorf("set-cookies = %v", resp.SetCookies)
	}
	// Form bodies are verified too.
	if _, err := f.c.Authenticate(context.Background(), Request{Method: "POST", URL: login,
		Body: []byte(`identifier=a%40example.test&password=pw`)}); err != nil {
		t.Errorf("a form login with the configured fields was refused: %v", err)
	}
}

// The authentication exception is not a general bypass. Each way of reaching it
// other than the exact configured request, through Authenticate, is refused
// before anything is sent.
func TestAuthenticationExceptionIsNotABypass(t *testing.T) {
	g := mustGuard(t, model.ProfileSafe)
	f, login := authFixture(t, g)
	if err := g.AllowAuthentication("POST", login, []string{"identifier", "password"}); err != nil {
		t.Fatal(err)
	}
	g.Seal()
	ctx := context.Background()
	good := []byte(`{"identifier":"a","password":"b"}`)

	refusedAuth := func(name string, r Request) {
		t.Helper()
		before := f.hits.Load()
		_, err := f.c.Authenticate(ctx, r)
		var refused *ErrRefused
		if !errors.As(err, &refused) {
			t.Errorf("%s: err = %v, want a safety refusal", name, err)
		}
		if f.hits.Load() != before {
			t.Errorf("%s: the request reached the target", name)
		}
	}
	refusedAuth("another path", Request{Method: "POST", URL: f.srv.URL + "/api/orders", Body: good})
	refusedAuth("another method", Request{Method: "PUT", URL: login, Body: good})
	refusedAuth("a query added", Request{Method: "POST", URL: login + "?x=1", Body: good})
	refusedAuth("an unconfigured field", Request{Method: "POST", URL: login,
		Body: []byte(`{"identifier":"a","password":"b","role":"admin"}`)})
	refusedAuth("an unconfigured form field", Request{Method: "POST", URL: login,
		Body: []byte(`identifier=a&password=b&role=admin`)})

	// The identical request through Do — the path every check uses — is refused.
	f.expectRefused(t, "POST", "/api/auth/login", string(good))

	if err := g.AllowAuthentication("POST", f.srv.URL+"/api/other", []string{"x"}); err == nil {
		t.Error("an authentication request was registered after Seal")
	}
	if err := mustGuard(t, model.ProfileSafe).AllowAuthentication("DELETE", login, nil); err == nil {
		t.Error("a DELETE was accepted as an authentication request")
	}
}

// Authentication requests are still subject to scope and the budget, and are
// recorded in the request log.
func TestAuthenticationRequestsStillPassEveryOtherGate(t *testing.T) {
	g := mustGuard(t, model.ProfileStandard)
	f := &guardFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { f.hits.Add(1) }))
	defer f.srv.Close()
	var recs []AuditRecord
	c := newClient(t, loopbackPolicy(t, portOf(t, f.srv.URL)), func(o *Options) {
		o.Guard = g
		o.MaxRequests = 1
		o.Audit = func(r AuditRecord) error { recs = append(recs, r); return nil }
	})
	defer c.Close()
	login := f.srv.URL + "/login"
	offScope := "http://203.0.113.7/login"
	for _, u := range []string{login, offScope} {
		if err := g.AllowAuthentication("POST", u, []string{"password"}); err != nil {
			t.Fatal(err)
		}
	}
	g.Seal()

	if _, err := c.Authenticate(context.Background(), Request{Method: "POST", URL: offScope,
		Body: []byte(`{"password":"x"}`)}); !NotSent(err) {
		t.Errorf("an out-of-scope login: err = %v, want refused", err)
	}
	if _, err := c.Authenticate(context.Background(), Request{Method: "POST", URL: login,
		Body: []byte(`{"password":"x"}`)}); err != nil {
		t.Fatalf("login within budget: %v", err)
	}
	var spent *ErrBudgetExceeded
	if _, err := c.Authenticate(context.Background(), Request{Method: "POST", URL: login,
		Body: []byte(`{"password":"x"}`)}); !errors.As(err, &spent) {
		t.Errorf("a login beyond the budget: err = %v, want a budget refusal", err)
	}
	if f.hits.Load() != 1 {
		t.Errorf("the target received %d requests, want 1", f.hits.Load())
	}
	if len(recs) != 3 {
		t.Errorf("request log lines = %d, want 3 (one per attempt, refusals included)", len(recs))
	}
}

// A record Sulayi creates may be created once and deleted once, exactly as
// registered. Nothing else becomes possible: not a second create, not a
// different body, not a DELETE of any other record, and not the same DELETE
// twice.
func TestStandardPermitsOneExactCreateAndOneExactCleanup(t *testing.T) {
	g, err := NewGuard(model.ProfileStandard, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newGuardFixture(t, g)
	body := `{"token":"r4nd0m"}`
	if err := g.GrantCreate(f.srv.URL+"/api/tokens", []byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := g.GrantCleanup(f.srv.URL + "/api/tokens/7"); err != nil {
		t.Fatal(err)
	}
	g.Seal()

	f.expectRefused(t, http.MethodPost, "/api/tokens", `{"token":"other"}`)
	f.expectSent(t, http.MethodPost, "/api/tokens", body)
	f.expectRefused(t, http.MethodPost, "/api/tokens", body)

	f.expectRefused(t, http.MethodDelete, "/api/tokens/8", "")
	f.expectRefused(t, http.MethodDelete, "/api/tokens/7", `{"x":1}`)
	f.expectSent(t, http.MethodDelete, "/api/tokens/7", "")
	f.expectRefused(t, http.MethodDelete, "/api/tokens/7", "")

	if err := g.GrantCleanup(f.srv.URL + "/api/tokens/9"); err == nil {
		t.Error("a cleanup grant was accepted after the guard was sealed")
	}
}

// Safe sends nothing state-changing, one-shot grants included.
func TestSafeIgnoresOneShotGrants(t *testing.T) {
	g, err := NewGuard(model.ProfileSafe, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newGuardFixture(t, g)
	if err := g.GrantCleanup(f.srv.URL + "/api/tokens/7"); err != nil {
		t.Fatal(err)
	}
	f.expectRefused(t, http.MethodDelete, "/api/tokens/7", "")
}

// Aggressive permits every state-changing request, so one-shot grants are not
// recorded: each identity creating the same kind of record must not collide.
func TestAggressiveDoesNotRecordOneShotGrants(t *testing.T) {
	g, err := NewGuard(model.ProfileAggressive, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := g.GrantCreate("http://127.0.0.1:1/api/tokens", []byte(`{"t":1}`)); err != nil {
			t.Fatalf("create grant %d: %v", i+1, err)
		}
	}
}
