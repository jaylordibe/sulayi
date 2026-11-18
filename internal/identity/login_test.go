package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/redact"
	"github.com/jaylordibe/sulayi/internal/scope"
)

const (
	testIdentifier = "alice@example.test"
	testPassword   = "S3cret-login-password!"
)

// loginApp is a target whose login issues a token or a cookie session. It
// counts logins and canary calls, and can be told to expire sessions.
type loginApp struct {
	mu       sync.Mutex
	valid    map[string]bool // live tokens or session ids
	seq      int
	logins   atomic.Int64
	canaries atomic.Int64
	writes   atomic.Int64
	// badStatus is what a request without a live session gets.
	badStatus int
	// rejectLogin makes every login fail the way Laravel does: 400.
	rejectLogin bool
}

func newLoginApp() *loginApp {
	return &loginApp{valid: map[string]bool{}, badStatus: http.StatusUnauthorized}
}

func (a *loginApp) issue() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	tok := fmt.Sprintf("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ%d0In0.c2lnbmF0dXJlLXZhbHVl", a.seq)
	a.valid[tok] = true
	return tok
}

func (a *loginApp) live(tok string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.valid[tok]
}

func (a *loginApp) expireAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.valid = map[string]bool{}
}

func (a *loginApp) credentialsOK(r *http.Request) bool {
	var id, pw string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		id, pw = r.PostForm.Get("identifier"), r.PostForm.Get("password")
	} else {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		id, pw = body["identifier"], body["password"]
	}
	return !a.rejectLogin && id == testIdentifier && pw == testPassword
}

// bearerHandler behaves like the NestJS starter: POST /api/auth/login returns
// {"accessToken": ...}; protected routes need Authorization: Bearer.
func (a *loginApp) bearerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		a.logins.Add(1)
		if r.Method != http.MethodPost || !a.credentialsOK(r) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"Invalid username or password"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"accessToken":%q,"expiresIn":900}`, a.issue())
	})
	authed := func(r *http.Request) bool {
		return a.live(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		a.canaries.Add(1)
		if !authed(r) {
			w.WriteHeader(a.badStatus)
			return
		}
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	mux.HandleFunc("/api/orders/1", func(w http.ResponseWriter, r *http.Request) {
		a.writes.Add(1)
		if !authed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	return mux
}

// cookieHandler is a cookie session with a CSRF cookie: GET /csrf sets a
// URL-encoded XSRF-TOKEN; the login must echo it, decoded, in X-XSRF-TOKEN and
// sets the session cookie.
func (a *loginApp) cookieHandler() http.Handler {
	const csrf = "csrf token/with+chars="
	mux := http.NewServeMux()
	mux.HandleFunc("/csrf", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: url.QueryEscape(csrf), Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		a.logins.Add(1)
		ck, _ := r.Cookie("XSRF-TOKEN")
		if ck == nil || r.Header.Get("X-XSRF-TOKEN") != csrf || !a.credentialsOK(r) {
			w.WriteHeader(419)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "app_session", Value: a.issue(), Path: "/", HttpOnly: true,
			Domain: "wider.example.test"})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		a.canaries.Add(1)
		ck, _ := r.Cookie("app_session")
		if ck == nil || !a.live(ck.Value) || r.Header.Get("X-XSRF-TOKEN") != csrf {
			w.WriteHeader(419)
			return
		}
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	return mux
}

// preflightHandler issues a token in a JSON preflight that the login form
// must carry, as NextAuth's credentials flow does.
func (a *loginApp) preflightHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/csrf", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "pre-cookie-0123456789", Path: "/"})
		_, _ = w.Write([]byte(`{"csrfToken":"preflight-token-0123456789"}`))
	})
	mux.HandleFunc("/api/auth/callback/credentials", func(w http.ResponseWriter, r *http.Request) {
		a.logins.Add(1)
		_ = r.ParseForm()
		ck, _ := r.Cookie("csrf")
		if r.PostForm.Get("csrfToken") != "preflight-token-0123456789" || ck == nil || !a.credentialsOK(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Login answered with a redirect, as many form flows are: the session
		// is in the 302, and it must not be followed.
		http.SetCookie(w, &http.Cookie{Name: "session-token", Value: a.issue(), Path: "/"})
		w.Header().Set("Location", "https://elsewhere.example.test/")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		a.canaries.Add(1)
		ck, _ := r.Cookie("session-token")
		if ck == nil || !a.live(ck.Value) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	return mux
}

type loginHarness struct {
	srv    *httptest.Server
	client *httpx.Client
	red    *redact.Redactor
	set    *Set
	ctl    *Control
}

// newLoginHarness wires a login identity exactly as the CLI does: the login is
// registered with a safe-profile guard, the identity resolves credentials
// through the given lookup, and it signs in.
func newLoginHarness(t *testing.T, h http.Handler, login *Login, live bool) *loginHarness {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	var port int
	parts := strings.Split(srv.URL, ":")
	if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &port); err != nil {
		t.Fatal(err)
	}
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := httpx.NewGuard(model.ProfileSafe, nil)
	if err != nil {
		t.Fatal(err)
	}
	red := redact.New()
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: red, Timeout: 5 * time.Second, Guard: guard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	id := Identity{ID: "alice", Role: "member", Auth: Authentication{Scheme: SchemeLogin, Login: login}}
	if live {
		id.Live = Liveness{Method: "GET", Path: "/api/me"}
	}
	if problems := id.Validate("identities[0]"); len(problems) > 0 {
		t.Fatalf("identity does not validate: %v", problems)
	}
	method, u, fields, _ := id.LoginRequest(srv.URL)
	if err := guard.AllowAuthentication(method, u, fields); err != nil {
		t.Fatal(err)
	}
	guard.Seal()
	lookup := func(n string) (string, bool) {
		switch n {
		case "ALICE_ID":
			return testIdentifier, true
		case "ALICE_PW":
			return testPassword, true
		}
		return "", false
	}
	set := ResolveWith([]Identity{id}, srv.URL, client, red, lookup)
	set.SignIn(context.Background())
	ctl, _ := set.ByID("alice")
	return &loginHarness{srv: srv, client: client, red: red, set: set, ctl: ctl}
}

func credentialFields() []LoginField {
	return []LoginField{
		{Name: "identifier", Source: CredentialSource{Env: "ALICE_ID"}},
		{Name: "password", Source: CredentialSource{Env: "ALICE_PW"}},
	}
}

func bearerLogin() *Login {
	return &Login{Path: "/api/auth/login", Fields: credentialFields(), Session: Session{Bearer: "/accessToken"}}
}

// A JWT login, the NestJS starter's shape: the identity signs in under the safe
// profile, sends the token, and the token is redacted from anything captured.
func TestBearerLoginSignsInAndRedactsTheToken(t *testing.T) {
	app := newLoginApp()
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), true)

	if ok, _, why := h.ctl.Usable(); !ok {
		t.Fatalf("not usable after login: %s", why)
	}
	auth := h.ctl.Headers()["Authorization"]
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer eyJ") {
		t.Fatalf("Authorization = %v", auth)
	}
	if got := h.ctl.Probe(context.Background()); got != LivenessGood {
		t.Fatalf("canary = %s, want good", got)
	}
	tok := strings.TrimPrefix(auth[0], "Bearer ")
	for _, secret := range []string{tok, testPassword, testIdentifier} {
		if strings.Contains(h.red.String("echo "+secret), secret) {
			t.Errorf("%q was not registered with the redactor", secret)
		}
	}
	st := h.ctl.Status()
	if st.Role != "member" || !strings.Contains(st.Source, "login POST /api/auth/login") {
		t.Errorf("status = role %q, source %q", st.Role, st.Source)
	}
}

// A login is successful when it issues a session, not when it avoids a 401:
// Laravel answers bad credentials with 400. The failure says why and never
// repeats what was sent.
func TestRejectedLoginBlocksTheIdentityWithoutEchoingCredentials(t *testing.T) {
	app := newLoginApp()
	app.rejectLogin = true
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), true)

	ok, cause, why := h.ctl.Usable()
	if ok || cause != model.CauseMissingIdentity {
		t.Fatalf("usable = %v (%s); a failed login must leave the identity unusable", ok, cause)
	}
	st := h.ctl.Status()
	if !strings.Contains(st.Problem, "returned 400") {
		t.Errorf("problem = %q, want the status named", st.Problem)
	}
	for _, s := range []string{why, st.Problem} {
		if strings.Contains(s, testPassword) || strings.Contains(s, testIdentifier) {
			t.Errorf("the failure repeats a credential: %q", s)
		}
	}
	if h.ctl.Headers()["Authorization"] != nil {
		t.Error("an identity that failed to sign in still presents a credential")
	}
}

func TestLoginWithoutTheTokenAtThePointerFails(t *testing.T) {
	app := newLoginApp()
	l := bearerLogin()
	l.Session.Bearer = "/token"
	h := newLoginHarness(t, app.bearerHandler(), l, false)
	if ok, _, _ := h.ctl.Usable(); ok {
		t.Fatal("an identity whose login response carried no token at the pointer is usable")
	}
	if !strings.Contains(h.ctl.Status().Problem, "no token at /token") {
		t.Errorf("problem = %q", h.ctl.Status().Problem)
	}
}

// A cookie session with a CSRF cookie: the preflight's cookie is decoded into
// the header, the session cookie is sent back, and the cookie's Domain cannot
// widen where it goes — requests stay bound to the target's origin.
func TestCookieSessionWithCSRF(t *testing.T) {
	app := newLoginApp()
	l := &Login{
		Path: "/login", Form: true, Fields: credentialFields(),
		Preflight: &Preflight{Path: "/csrf"},
		Session:   Session{Cookies: true},
		CSRF:      &CSRF{Cookie: "XSRF-TOKEN", Header: "X-XSRF-TOKEN"},
	}
	h := newLoginHarness(t, app.cookieHandler(), l, true)
	if ok, _, why := h.ctl.Usable(); !ok {
		t.Fatalf("not usable: %s", why)
	}
	if got := h.ctl.Probe(context.Background()); got != LivenessGood {
		t.Fatalf("canary = %s, want good: %s", got, h.ctl.Status().Problem)
	}
	hdr := h.ctl.Headers()
	if !strings.Contains(strings.Join(hdr["Cookie"], ""), "app_session=") {
		t.Errorf("Cookie = %v", hdr["Cookie"])
	}
	if strings.Contains(h.red.String("csrf token/with+chars="), "csrf token/with+chars=") {
		t.Error("the decoded CSRF value was not registered with the redactor")
	}
}

// A value read from the preflight's JSON fills a login field, the preflight's
// own cookie is carried into the login, and a cookie session issued on a 302 is
// taken without following the redirect — which points off-origin here, and
// would be refused if it were followed.
func TestPreflightValueAndRedirectedLogin(t *testing.T) {
	app := newLoginApp()
	l := &Login{
		Path: "/api/auth/callback/credentials", Form: true,
		Fields:    append(credentialFields(), LoginField{Name: "csrfToken", FromPreflight: "/csrfToken"}),
		Preflight: &Preflight{Path: "/api/auth/csrf"},
		Session:   Session{Cookies: true},
	}
	h := newLoginHarness(t, app.preflightHandler(), l, true)
	if ok, _, why := h.ctl.Usable(); !ok {
		t.Fatalf("not usable: %s", why)
	}
	if got := h.ctl.Probe(context.Background()); got != LivenessGood {
		t.Fatalf("canary = %s: %s", got, h.ctl.Status().Problem)
	}
	if app.logins.Load() != 1 {
		t.Errorf("logins = %d", app.logins.Load())
	}
}

// A bearer token is read from a 2xx body. A redirect issues no token, however
// the response looks.
func TestBearerLoginAnsweredWithRedirectFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/home")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"}`))
	})
	h := newLoginHarness(t, mux, bearerLogin(), false)
	if ok, _, _ := h.ctl.Usable(); ok {
		t.Fatal("a bearer login answered with 302 counted as signed in")
	}
}

// An expired session is recovered by signing in again, once, when the canary
// says the session is no longer accepted. The failed request is not replayed,
// and the interval in which the session was dead is recorded so that results
// from it are withdrawn.
func TestExpiredSessionIsRecoveredWithoutReplay(t *testing.T) {
	app := newLoginApp()
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), true)
	ctx := context.Background()
	if h.ctl.Probe(ctx) != LivenessGood {
		t.Fatal("not good before expiry")
	}

	before := h.ctl.Headers()["Authorization"][0]
	app.expireAll()
	ex, _ := h.ctl.DoWithBody(ctx, "GET", h.srv.URL+"/api/orders/1", nil, nil)
	if ex.Response == nil || ex.Response.Status != 401 {
		t.Fatalf("the request after expiry got %v", ex.Response)
	}
	h.ctl.NoteSuspicious(ctx)

	st := h.ctl.Status()
	if st.Liveness != LivenessGood {
		t.Fatalf("liveness = %s after recovery: %s", st.Liveness, st.Problem)
	}
	if n := app.writes.Load(); n != 1 {
		t.Errorf("the request that failed reached the target %d times; it must never be replayed", n)
	}
	if app.logins.Load() != 2 || st.Reauthentications != 1 {
		t.Errorf("logins = %d, reauthentications = %d; want 2 and 1", app.logins.Load(), st.Reauthentications)
	}
	if len(st.Windows) != 1 || st.Windows[0].To.IsZero() || st.Windows[0].FirstBad.IsZero() {
		t.Fatalf("windows = %+v, want one closed window", st.Windows)
	}
	if !st.Windows[0].Contains(st.Windows[0].FirstBad) {
		t.Error("the window does not contain the moment the session was found dead")
	}
	if after := h.ctl.Headers()["Authorization"][0]; after == before {
		t.Error("the identity is still presenting the expired session")
	}
}

// A canary answered with 403 is an authorization decision, not an expired
// session. Signing in again would change nothing, so it is not done.
func TestForbiddenCanaryDoesNotSignInAgain(t *testing.T) {
	app := newLoginApp()
	app.badStatus = http.StatusForbidden
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), true)
	app.expireAll()
	h.ctl.NoteSuspicious(context.Background())

	st := h.ctl.Status()
	if app.logins.Load() != 1 {
		t.Errorf("logins = %d; a 403 must not trigger a new sign-in", app.logins.Load())
	}
	if st.Liveness != LivenessBad || !strings.Contains(st.Problem, "authorization response") {
		t.Errorf("liveness %s, problem %q", st.Liveness, st.Problem)
	}
	if ok, cause, _ := h.ctl.Usable(); ok || cause != model.CauseAuthenticationFailed {
		t.Errorf("usable = %v (%s); work depending on it must be blocked", ok, cause)
	}
}

// Re-authentication is bounded per run: login endpoints are rate limited and
// lock accounts.
func TestReauthenticationIsBounded(t *testing.T) {
	app := newLoginApp()
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), true)
	ctx := context.Background()
	for i := 0; i < MaxReauthentications+3; i++ {
		app.expireAll()
		h.ctl.NoteSuspicious(ctx)
	}
	if got := app.logins.Load(); got != int64(1+MaxReauthentications) {
		t.Errorf("logins = %d, want %d (one sign-in plus at most %d again)", got, 1+MaxReauthentications,
			MaxReauthentications)
	}
	st := h.ctl.Status()
	if st.Liveness != LivenessBad || !strings.Contains(st.Problem, "which is the limit") {
		t.Errorf("after the limit: liveness %s, problem %q", st.Liveness, st.Problem)
	}
}

// Twenty requests finding the session dead at once produce one sign-in.
func TestConcurrentSuspicionSignsInOnce(t *testing.T) {
	app := newLoginApp()
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), true)
	app.expireAll()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			h.ctl.NoteSuspicious(context.Background())
		}()
	}
	close(start)
	wg.Wait()
	if got := app.logins.Load(); got != 2 {
		t.Errorf("logins = %d, want 2: the first sign-in and exactly one more", got)
	}
}

// Without a canary, an expired session cannot be told from a denial, so
// nothing is attempted and the identity says why.
func TestLoginIdentityWithoutCanaryIsWarnedAbout(t *testing.T) {
	app := newLoginApp()
	h := newLoginHarness(t, app.bearerHandler(), bearerLogin(), false)
	if !strings.Contains(strings.Join(h.ctl.Status().Warnings, " "), "no liveness canary") {
		t.Errorf("warnings = %v", h.ctl.Status().Warnings)
	}
}

func TestLoginValidation(t *testing.T) {
	base := func() *Login { return bearerLogin() }
	cases := map[string]func(*Login){
		"GET login":            func(l *Login) { l.Method = "GET" },
		"absolute URL":         func(l *Login) { l.Path = "https://elsewhere.example.test/login" },
		"protocol-relative":    func(l *Login) { l.Path = "//elsewhere.example.test/login" },
		"no fields":            func(l *Login) { l.Fields = nil },
		"both sessions":        func(l *Login) { l.Session.Cookies = true },
		"no session":           func(l *Login) { l.Session = Session{} },
		"bad pointer":          func(l *Login) { l.Session.Bearer = "accessToken" },
		"preflight that posts": func(l *Login) { l.Preflight = &Preflight{Method: "POST", Path: "/x"} },
		"csrf on bearer":       func(l *Login) { l.CSRF = &CSRF{Cookie: "a", Header: "X-A"} },
		"field from missing preflight": func(l *Login) {
			l.Fields = append(l.Fields, LoginField{Name: "t", FromPreflight: "/t"})
		},
		"field with two sources": func(l *Login) {
			l.Fields[0].FromPreflight = "/x"
			l.Preflight = &Preflight{Path: "/p"}
		},
	}
	for name, mutate := range cases {
		l := base()
		mutate(l)
		id := Identity{ID: "a", Auth: Authentication{Scheme: SchemeLogin, Login: l}}
		if problems := id.Validate("identities[0]"); len(problems) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	withCred := Identity{ID: "a", Auth: Authentication{Scheme: SchemeLogin, Login: base(),
		Credential: CredentialSource{Env: "X"}}}
	if len(withCred.Validate("identities[0]")) == 0 {
		t.Error("a login identity with a static credential was accepted")
	}
}
