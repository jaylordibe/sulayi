// S4 evaluation fixtures (ADR-0023): one vulnerable and one secure application
// per injection and misconfiguration check, plus the misleading variants that
// would make a weaker oracle fire. Each pair differs only in the defect.
package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/sulayi/internal/check"
	"github.com/jaylordibe/sulayi/internal/engine"
	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/openapi"
	"github.com/jaylordibe/sulayi/internal/redact"
	"github.com/jaylordibe/sulayi/internal/scope"
)

const injectionToken = "injectionEvalTOKEN0123456789abcdef"

const injectionSpec = `{"openapi":"3.0.3","info":{"title":"inj","version":"1"},
 "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
 "paths":{
  "/api/items":{"get":{"security":[],"parameters":[{"name":"id","in":"query","schema":{"type":"string"}}]}},
  "/api/orders":{"get":{"security":[],"parameters":[{"name":"id","in":"query","schema":{"type":"integer"}}]}},
  "/search":{"get":{"security":[],"parameters":[{"name":"q","in":"query"}]}},
  "/greet":{"get":{"security":[],"parameters":[{"name":"name","in":"query"}]}},
  "/go":{"get":{"security":[],"parameters":[{"name":"next","in":"query"}]}},
  "/api/report":{"get":{"security":[],"parameters":[{"name":"year","in":"query"}]}},
  "/api/me":{"get":{"security":[{"bearer":[]}]}}}}`

// runInjection assesses handler under a profile with every S4 check, as a
// signed-in identity, and returns the result and the requests the target saw.
func runInjection(t *testing.T, handler http.Handler, profile model.Profile) (engine.Result, []string) {
	t.Helper()
	return runInjectionAs(t, handler, profile, false)
}

// runInjectionAs signs in with a bearer token, or with a cookie session
// through the application's own login when cookie is true.
func runInjectionAs(t *testing.T, handler http.Handler, profile model.Profile, cookie bool) (engine.Result, []string) {
	t.Helper()
	return runInjectionCore(t, handler, profile, cookie, injectionToken)
}

// runInjectionWithoutToken configures the identity with no credential.
func runInjectionWithoutToken(t *testing.T) (engine.Result, []string) {
	t.Helper()
	return runInjectionCore(t, injectionApp{stack: true}.handler(), model.ProfileStandard, false, "")
}

func runInjectionCore(t *testing.T, handler http.Handler, profile model.Profile, cookie bool,
	token string) (engine.Result, []string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: injectionToken, Path: "/", HttpOnly: true})
			w.WriteHeader(204)
			return
		}
		signedIn := r.Header.Get("Authorization") == "Bearer "+injectionToken
		if c, err := r.Cookie("sid"); err == nil && c.Value == injectionToken {
			signedIn = true
		}
		if !signedIn && r.URL.Path == "/api/me" {
			w.WriteHeader(401)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	port := serverPort(t, srv.URL)
	pol, err := scope.New([]scope.Entry{{Host: "127.0.0.1", Ports: []int{port}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := httpx.NewGuard(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	red := redact.New()
	client, err := httpx.New(httpx.Options{Policy: pol, Redactor: red, Timeout: 5 * time.Second, Guard: guard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	t.Setenv("INJECTION_EVAL_TOKEN", token)
	id := identity.Identity{ID: "alice", Auth: identity.Authentication{
		Scheme: identity.SchemeBearer, Credential: identity.CredentialSource{Env: "INJECTION_EVAL_TOKEN"}}}
	if cookie {
		id.Auth = identity.Authentication{Scheme: identity.SchemeLogin, Login: &identity.Login{
			Path:    "/login",
			Fields:  []identity.LoginField{{Name: "password", Source: identity.CredentialSource{Env: "INJECTION_EVAL_TOKEN"}}},
			Session: identity.Session{Cookies: true},
		}}
		method, u, fields, _ := id.LoginRequest(srv.URL)
		if err := guard.AllowAuthentication(method, u, fields); err != nil {
			t.Fatal(err)
		}
	}
	ids := identity.Resolve([]identity.Identity{id}, srv.URL, client, red)
	ids.SignIn(context.Background())
	parsed, err := openapi.Parse([]byte(injectionSpec), srv.URL,
		model.Source{Kind: model.SourceOpenAPIFile, Ref: "fixture", ObservedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	inj := check.Injection{Client: client, Control: ids.Primary()}
	res, err := engine.Run(context.Background(), engine.Options{
		RunID: "eval", Target: srv.URL, Profile: profile, Guard: guard,
		Surface: engine.Surface{SpecDerived: true, Operations: parsed.Operations, Fidelity: parsed.Fidelity},
		Checks: []engine.Check{
			check.SQLInjection{Injection: inj}, check.ReflectedXSS{Injection: inj},
			check.TemplateInjection{Injection: inj}, check.OpenRedirect{Injection: inj},
			check.StackTrace{Injection: inj}, check.CORSCredentialed{Injection: inj},
		},
		Identities: ids, Concurrency: 1, RequestsPerSecond: 500, EvidenceSink: injectionSink,
		Now: func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return res, seen
}

// injectionSink, when set by a test, receives every stored exchange.
var injectionSink func(model.Exchange) (string, error)

func findingOf(res engine.Result, checkID, opID string) (model.Finding, bool) {
	for _, f := range res.Findings {
		if f.CheckID == checkID && f.OperationID == opID {
			return f, true
		}
	}
	return model.Finding{}, false
}

func rowOf(t *testing.T, res engine.Result, checkID, opID string) model.CoverageEntry {
	t.Helper()
	for _, e := range res.Coverage {
		if e.CheckID == checkID && e.Subject == opID {
			return e
		}
	}
	t.Fatalf("no ledger row for %s on %s", checkID, opID)
	return model.CoverageEntry{}
}

// ---------------------------------------------------------------------------
// A small SQL WHERE evaluator: string and number literals, the id column, =,
// AND and OR, with a syntax error as a server error. It is what lets the
// vulnerable fixtures concatenate input into a query and be wrong in exactly
// the way a database is, without a database dependency (docs/dependencies.md).

type sqlRow struct {
	ID   int
	Name string
}

var sqlRows = []sqlRow{{1, "alpha"}, {2, "beta"}, {3, "gamma"}}

var sqlToken = regexp.MustCompile(`\s*(?:('(?:[^']|'')*')|(\d+)|(=)|([A-Za-z_]+)|(.))`)

func sqlWhere(where string) ([]sqlRow, error) {
	var toks []string
	rest := where
	for strings.TrimSpace(rest) != "" {
		m := sqlToken.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			return nil, fmt.Errorf("syntax error near %q", rest)
		}
		tok := strings.TrimSpace(rest[m[0]:m[1]])
		if m[10] >= 0 {
			return nil, fmt.Errorf("syntax error near %q", tok)
		}
		toks = append(toks, tok)
		rest = rest[m[1]:]
	}
	var out []sqlRow
	for _, r := range sqlRows {
		ok, err := sqlEval(toks, r)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// sqlEval evaluates comparisons joined by AND/OR, AND binding tighter.
func sqlEval(toks []string, r sqlRow) (bool, error) {
	value := func(t string) (string, error) {
		switch {
		case strings.EqualFold(t, "id"):
			return strconv.Itoa(r.ID), nil
		case strings.HasPrefix(t, "'"):
			if len(t) < 2 || !strings.HasSuffix(t, "'") {
				return "", fmt.Errorf("unterminated string")
			}
			return strings.ReplaceAll(t[1:len(t)-1], "''", "'"), nil
		case t != "" && t[0] >= '0' && t[0] <= '9':
			return t, nil
		}
		return "", fmt.Errorf("unexpected %q", t)
	}
	any := false
	all := true
	for i := 0; ; {
		if i+3 > len(toks) {
			return false, fmt.Errorf("incomplete comparison")
		}
		if toks[i+1] != "=" {
			return false, fmt.Errorf("expected =")
		}
		a, err := value(toks[i])
		if err != nil {
			return false, err
		}
		b, err := value(toks[i+2])
		if err != nil {
			return false, err
		}
		all = all && a == b
		i += 3
		if i == len(toks) {
			return any || all, nil
		}
		switch strings.ToUpper(toks[i]) {
		case "AND":
		case "OR":
			any = any || all
			all = true
		default:
			return false, fmt.Errorf("unexpected %q", toks[i])
		}
		i++
	}
}

func writeRows(w http.ResponseWriter, rows []sqlRow, err error, echo string) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"message":"database error"}`))
		return
	}
	if rows == nil {
		rows = []sqlRow{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"query": echo, "items": rows})
}

// ---------------------------------------------------------------------------
// The applications.

type injectionApp struct {
	sqlString, sqlNumber, xss, xssInScript, xssInAttribute, ssti, redirect, stack, cors bool
	// sqlValidates answers non-numeric ids with 422; sqlCasts reads the
	// leading digits, as PHP's intval does.
	sqlValidates, sqlCasts bool
}

var sstiExpr = regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`)

func (a injectionApp) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch {
		case a.sqlString:
			rows, err := sqlWhere("id = '" + id + "'")
			writeRows(w, rows, err, id)
		case a.sqlValidates:
			if _, err := strconv.Atoi(id); err != nil {
				w.WriteHeader(422)
				return
			}
			rows, err := sqlWhere("id = " + id)
			writeRows(w, rows, err, id)
		case a.sqlCasts:
			n, _ := strconv.Atoi(regexp.MustCompile(`^\d*`).FindString(id))
			rows, err := sqlWhere("id = " + strconv.Itoa(n))
			writeRows(w, rows, err, id)
		default:
			var rows []sqlRow
			for _, row := range sqlRows {
				if strconv.Itoa(row.ID) == id {
					rows = append(rows, row)
				}
			}
			writeRows(w, rows, nil, id)
		}
	})
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if a.sqlNumber {
			rows, err := sqlWhere("id = " + id)
			writeRows(w, rows, err, id)
			return
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		rows, _ := sqlWhere("id = " + strconv.Itoa(n))
		writeRows(w, rows, nil, id)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case a.xss:
			fmt.Fprintf(w, "<html><body><p>Results for %s</p></body></html>", q)
		case a.xssInAttribute:
			// Quotes are encoded, angle brackets are not: the tag stays
			// attribute text.
			q = strings.NewReplacer(`"`, "&quot;", "'", "&#39;").Replace(q)
			fmt.Fprintf(w, `<html><body><input name="q" value="%s"></body></html>`, q)
		case a.xssInScript:
			fmt.Fprintf(w, "<html><body><script>var q = '%s';</script></body></html>", strings.ReplaceAll(q, "'", "\\'"))
		default:
			fmt.Fprintf(w, "<html><body><p>Results for %s</p></body></html>", html.EscapeString(q))
		}
	})
	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if a.ssti {
			name = sstiExpr.ReplaceAllStringFunc(name, func(m string) string {
				p := sstiExpr.FindStringSubmatch(m)
				x, _ := strconv.Atoi(p[1])
				y, _ := strconv.Atoi(p[2])
				return strconv.Itoa(x * y)
			})
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello %s", name)
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if !a.redirect && (!strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//")) {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusFound)
	})
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := strconv.Atoi(r.URL.Query().Get("year")); err != nil {
			if a.stack {
				w.WriteHeader(500)
				_, _ = w.Write([]byte(`{"message":"Invalid year","env":{"DB_PASSWORD":"hunter22-db-secret"},"stack":"Error: Invalid year\n    at parseYear (/app/src/report.js:12:9)\n    at handler (/app/src/routes.js:40:3)"}`))
				return
			}
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"message":"Invalid year"}`))
			return
		}
		_, _ = w.Write([]byte(`{"total":12}`))
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && (a.cors || origin == "https://app.example") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u1","email":"alice@example.test"}`))
	})
	return mux
}

// ---------------------------------------------------------------------------
// The pairs.

func TestS4_VulnerableApplicationIsConfirmedByEveryCheck(t *testing.T) {
	app := injectionApp{sqlString: true, sqlNumber: true, xss: true, ssti: true, redirect: true, stack: true, cors: true}
	res, _ := runInjection(t, app.handler(), model.ProfileStandard)
	want := []struct{ check, op string }{
		{check.SQLInjectionID, "GET /api/items"},
		{check.SQLInjectionID, "GET /api/orders"},
		{check.ReflectedXSSID, "GET /search"},
		{check.TemplateInjectID, "GET /greet"},
		{check.OpenRedirectID, "GET /go"},
		{check.StackTraceID, "GET /api/report"},
	}
	for _, w := range want {
		f, ok := findingOf(res, w.check, w.op)
		if !ok || f.State != model.StateConfirmed {
			t.Errorf("%s on %s: finding = %+v, %v; row %+v", w.check, w.op, f.State, ok, rowOf(t, res, w.check, w.op))
		}
	}
}

func TestS4_SecureApplicationIsReportedByNoCheck(t *testing.T) {
	for name, app := range map[string]injectionApp{
		"parameterised":     {},
		"validates input":   {sqlValidates: true},
		"casts to a number": {sqlCasts: true},
	} {
		t.Run(name, func(t *testing.T) {
			res, _ := runInjection(t, app.handler(), model.ProfileStandard)
			for _, f := range res.Findings {
				t.Errorf("finding on the secure application: %s %s %s", f.CheckID, f.OperationID, f.State)
			}
			// Each check ran; it was not merely unable to.
			for _, w := range []struct{ check, op string }{
				{check.SQLInjectionID, "GET /api/items"},
				{check.ReflectedXSSID, "GET /search"},
				{check.TemplateInjectID, "GET /greet"},
				{check.OpenRedirectID, "GET /go"},
				{check.StackTraceID, "GET /api/report"},
				{check.CORSCredentialedID, "GET /api/me"},
			} {
				if row := rowOf(t, res, w.check, w.op); row.Disposition != model.DispositionExecuted {
					t.Errorf("%s on %s did not run: %+v", w.check, w.op, row)
				}
			}
		})
	}
}

// Reflection inside a script string is not proven to execute, so it stays
// suspected rather than confirmed.
func TestS4_ReflectionInsideAScriptIsOnlySuspected(t *testing.T) {
	res, _ := runInjection(t, injectionApp{xssInScript: true}.handler(), model.ProfileStandard)
	f, ok := findingOf(res, check.ReflectedXSSID, "GET /search")
	if !ok || f.State != model.StateSuspected {
		t.Fatalf("finding = %+v, %v; want suspected", f.State, ok)
	}
}

// Safe sends inert payloads only: no SQL condition and no template expression
// reaches the target, and those checks are blocked by profile, not run.
func TestS4_SafeProfileSendsOnlyInertPayloads(t *testing.T) {
	app := injectionApp{sqlString: true, xss: true, ssti: true}
	res, seen := runInjection(t, app.handler(), model.ProfileSafe)
	for _, req := range seen {
		if strings.Contains(req, "7193") || strings.Contains(req, "sulayi%27%3D") ||
			strings.Contains(req, "7%2A7919") || strings.Contains(req, "7*7919") {
			t.Errorf("the safe profile sent %s", req)
		}
	}
	if row := rowOf(t, res, check.SQLInjectionID, "GET /api/items"); row.Disposition != model.DispositionBlocked {
		t.Errorf("SQL injection under safe: %+v", row)
	}
	if f, ok := findingOf(res, check.ReflectedXSSID, "GET /search"); !ok || f.State != model.StateConfirmed {
		t.Error("the inert XSS marker did not run under safe")
	}
}

// Credentialed CORS is confirmed only for a cookie session, the credential a
// browser attaches cross-origin by itself; with a header credential the same
// response is suspected, at low severity.
func TestS4_CredentialedCORSNeedsAnAmbientCredential(t *testing.T) {
	app := injectionApp{cors: true}
	bearer, _ := runInjectionAs(t, app.handler(), model.ProfileStandard, false)
	if f, ok := findingOf(bearer, check.CORSCredentialedID, "GET /api/me"); !ok ||
		f.State != model.StateSuspected || f.Severity != model.SeverityLow {
		t.Errorf("bearer identity: %+v %v; want suspected, low", f.State, ok)
	}
	cookie, _ := runInjectionAs(t, app.handler(), model.ProfileStandard, true)
	if f, ok := findingOf(cookie, check.CORSCredentialedID, "GET /api/me"); !ok || f.State != model.StateConfirmed {
		t.Errorf("cookie session: %+v %v; want confirmed", f.State, ok)
	}
	secure, _ := runInjectionAs(t, injectionApp{}.handler(), model.ProfileStandard, true)
	if _, ok := findingOf(secure, check.CORSCredentialedID, "GET /api/me"); ok {
		t.Error("an allow-listed CORS policy was reported")
	}
}

// With an identity configured and unusable, a route behind sign-in is
// blocked, never probed anonymously and reported clean.
func TestS4_UnusableIdentityBlocksRatherThanProbingAnonymously(t *testing.T) {
	res, seen := runInjectionWithoutToken(t)
	if row := rowOf(t, res, check.StackTraceID, "GET /api/report"); row.Disposition != model.DispositionBlocked {
		t.Errorf("stack-trace row = %+v, want blocked", row)
	}
	for _, req := range seen {
		if strings.Contains(req, "sulayi") {
			t.Errorf("a payload was sent without the identity: %s", req)
		}
	}
}

// A quote encoded before the tag leaves it inside an attribute value, so the
// reflection is suspected, not confirmed.
func TestS4_ReflectionInsideAQuotedAttributeIsOnlySuspected(t *testing.T) {
	res, _ := runInjection(t, injectionApp{xssInAttribute: true}.handler(), model.ProfileStandard)
	f, ok := findingOf(res, check.ReflectedXSSID, "GET /search")
	if !ok || f.State != model.StateSuspected {
		t.Fatalf("finding = %+v, %v; want suspected", f.State, ok)
	}
}

// Under safe, SQL injection was not run, so the report does not say it was
// assessed in part.
func TestS4_ABlockedCheckDoesNotCountAsAssessed(t *testing.T) {
	res, _ := runInjection(t, injectionApp{}.handler(), model.ProfileSafe)
	var plain, qualified bool
	for _, c := range res.ClassesNotAssessed {
		switch {
		case c == "CWE-89 SQL injection":
			plain = true
		case strings.HasPrefix(c, "CWE-89 "):
			qualified = true
		}
	}
	if !plain || qualified {
		t.Errorf("classes not assessed = %v; want CWE-89 listed plainly", res.ClassesNotAssessed)
	}
}

// A debug page lists the server's secrets. The stored evidence keeps the stack
// frames that prove the finding and nothing else from that response.
func TestS4_StackTraceEvidenceKeepsFramesNotSecrets(t *testing.T) {
	var stored []model.Exchange
	injectionSink = func(ex model.Exchange) (string, error) {
		stored = append(stored, ex)
		return fmt.Sprintf("ref-%d", len(stored)), nil
	}
	t.Cleanup(func() { injectionSink = nil })
	res, _ := runInjection(t, injectionApp{stack: true}.handler(), model.ProfileStandard)
	if _, ok := findingOf(res, check.StackTraceID, "GET /api/report"); !ok {
		t.Fatal("the stack trace was not found")
	}
	var frames bool
	for _, ex := range stored {
		if ex.Response == nil {
			continue
		}
		if strings.Contains(string(ex.Response.Body), "hunter22-db-secret") &&
			strings.Contains(ex.Request.URL, "year=1sulayi") {
			t.Errorf("the stored evidence for %s carries the debug page's secret", ex.Request.URL)
		}
		if strings.Contains(string(ex.Response.Body), "report.js:12:9") {
			frames = true
		}
	}
	if !frames {
		t.Error("the stack frames that prove the finding were not kept")
	}
}
