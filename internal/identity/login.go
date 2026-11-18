package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/jsonpointer"
	"github.com/jaylordibe/sulayi/internal/redact"
)

// SchemeLogin signs in through the application's own login request and uses
// the session it issues: a bearer token read from the response, or the
// session cookies it sets.
const SchemeLogin Scheme = "login"

// MaxReauthentications bounds how many times one identity may sign in again in
// a run. Login endpoints are rate limited and lock accounts; a flow that keeps
// failing must stop and say so rather than keep trying.
const MaxReauthentications = 3

// Login describes how to sign in as an identity.
type Login struct {
	// Method defaults to POST. GET is refused: credentials do not belong in a
	// URL, where every log and intermediary would record them.
	Method string
	// Path is resolved against the target. It is a path, never a URL, so a
	// login can only ever go to the target's own origin.
	Path string
	// Form sends application/x-www-form-urlencoded instead of JSON.
	Form bool
	// Fields are the body fields, each read from a credential source or from
	// the preflight response.
	Fields []LoginField
	// Preflight is an optional read-only request made first, for applications
	// that issue a CSRF token or cookie before accepting a login.
	Preflight *Preflight
	// Session says what the login issues.
	Session Session
	// CSRF copies a cookie the application set into a request header.
	CSRF *CSRF
}

// LoginField is one body field.
type LoginField struct {
	Name string
	// Source reads the value from the environment, a --env file or a file.
	Source CredentialSource
	// FromPreflight reads it from the preflight response by JSON pointer.
	FromPreflight string
}

// Preflight is a read-only request sent before the login.
type Preflight struct {
	Method string
	Path   string
}

// Session says what the login response issues.
type Session struct {
	// Bearer is a JSON pointer to a token in the login response, sent as
	// Authorization: Bearer.
	Bearer string
	// Cookies uses the cookies the preflight and login responses set.
	Cookies bool
}

// CSRF names a cookie whose value is sent in a header.
type CSRF struct {
	Cookie string
	Header string
}

// validateLogin checks a login flow's shape.
func validateLogin(path string, l *Login) []string {
	var problems []string
	if l == nil {
		return []string{path + ".login is required for the login type"}
	}
	method := strings.ToUpper(strings.TrimSpace(l.Method))
	switch method {
	case "", "POST", "PUT", "PATCH":
	default:
		problems = append(problems, fmt.Sprintf("%s.login.method %q must be POST, PUT or PATCH; a login "+
			"sent with GET would put the credentials in the URL", path, l.Method))
	}
	problems = append(problems, validatePath(path+".login.path", l.Path)...)
	if len(l.Fields) == 0 {
		problems = append(problems, path+".login.body must name at least one field")
	}
	seen := map[string]bool{}
	for _, f := range l.Fields {
		fp := fmt.Sprintf("%s.login.body.%s", path, f.Name)
		if f.Name == "" {
			problems = append(problems, path+".login.body has a field with no name")
			continue
		}
		if seen[f.Name] {
			problems = append(problems, fp+" is defined twice")
		}
		seen[f.Name] = true
		switch {
		case f.FromPreflight != "" && (f.Source.Env != "" || f.Source.File != ""):
			problems = append(problems, fp+": set exactly one of env, file or fromPreflight")
		case f.FromPreflight != "":
			if l.Preflight == nil {
				problems = append(problems, fp+".fromPreflight needs login.preflight to be configured")
			}
			if !strings.HasPrefix(f.FromPreflight, "/") {
				problems = append(problems, fp+".fromPreflight must be a JSON pointer beginning with /")
			}
		default:
			problems = append(problems, f.Source.Validate(fp)...)
		}
	}
	if l.Preflight != nil {
		switch strings.ToUpper(strings.TrimSpace(l.Preflight.Method)) {
		case "", "GET", "HEAD":
		default:
			problems = append(problems, fmt.Sprintf("%s.login.preflight.method %q must be GET or HEAD; a "+
				"preflight only fetches a token or cookie", path, l.Preflight.Method))
		}
		problems = append(problems, validatePath(path+".login.preflight.path", l.Preflight.Path)...)
	}
	switch {
	case l.Session.Bearer != "" && l.Session.Cookies:
		problems = append(problems, path+".login.session: set exactly one of bearer or cookies")
	case l.Session.Bearer == "" && !l.Session.Cookies:
		problems = append(problems, path+".login.session: set bearer (a JSON pointer to the token) or cookies: true")
	case l.Session.Bearer != "" && !strings.HasPrefix(l.Session.Bearer, "/"):
		problems = append(problems, path+".login.session.bearer must be a JSON pointer beginning with /")
	}
	if l.CSRF != nil {
		if !l.Session.Cookies {
			problems = append(problems, path+".login.csrf applies only to a cookie session")
		}
		if l.CSRF.Cookie == "" || l.CSRF.Header == "" {
			problems = append(problems, path+".login.csrf needs both cookie and header")
		}
		if l.CSRF.Header != "" && (!tokenPattern.MatchString(l.CSRF.Header) ||
			forbiddenHeaders[strings.ToLower(l.CSRF.Header)]) {
			problems = append(problems, fmt.Sprintf("%s.login.csrf.header %q is not a header that may "+
				"carry a token", path, l.CSRF.Header))
		}
	}
	return problems
}

// validatePath requires a path on the target: absolute, with no scheme, no
// host and no protocol-relative prefix that a URL resolver would treat as one.
func validatePath(field, p string) []string {
	switch {
	case p == "":
		return []string{field + " is required"}
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "://"):
		return []string{fmt.Sprintf("%s %q must be a path on the target beginning with a single /", field, p)}
	case strings.ContainsAny(p, "\r\n\x00#"):
		return []string{field + " may not contain control characters or a fragment"}
	}
	return nil
}

// LoginRequests returns the method and URL of an identity's login request, and
// the body fields it may carry, for registration with the safety guard. The
// preflight is read-only and needs no exception.
func (i Identity) LoginRequest(baseURL string) (method, rawURL string, fields []string, ok bool) {
	if i.Auth.Scheme != SchemeLogin || i.Auth.Login == nil {
		return "", "", nil, false
	}
	l := i.Auth.Login
	method = strings.ToUpper(strings.TrimSpace(l.Method))
	if method == "" {
		method = http.MethodPost
	}
	for _, f := range l.Fields {
		fields = append(fields, f.Name)
	}
	sort.Strings(fields)
	return method, joinPath(baseURL, l.Path), fields, true
}

// CredentialEnvNames lists every environment name the identity reads.
func (i Identity) CredentialEnvNames() []string {
	var out []string
	if i.Auth.Credential.Env != "" {
		out = append(out, i.Auth.Credential.Env)
	}
	if i.Auth.Login != nil {
		for _, f := range i.Auth.Login.Fields {
			if f.Source.Env != "" {
				out = append(out, f.Source.Env)
			}
		}
	}
	return out
}

func joinPath(baseURL, path string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

// session is what a login established.
type session struct {
	bearer  string
	cookies map[string]string
	csrf    string
}

// headers renders the session for a request. The cookie order is sorted so
// that two requests from one session are byte-identical.
func (s session) headers(l *Login) map[string][]string {
	h := map[string][]string{}
	if s.bearer != "" {
		h["Authorization"] = []string{"Bearer " + s.bearer}
	}
	if len(s.cookies) > 0 {
		names := make([]string, 0, len(s.cookies))
		for n := range s.cookies {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, n+"="+s.cookies[n])
		}
		h["Cookie"] = []string{strings.Join(parts, "; ")}
	}
	if l != nil && l.CSRF != nil && s.csrf != "" {
		h[l.CSRF.Header] = []string{s.csrf}
	}
	return h
}

// errLogin is a login failure. Its text names the request and the reason and
// never a value: not the credentials sent, not what the target returned.
type errLogin struct{ msg string }

func (e *errLogin) Error() string { return e.msg }

func loginErr(format string, args ...any) error { return &errLogin{msg: fmt.Sprintf(format, args...)} }

// signIn runs the preflight and the login, and returns the session.
//
// Every secret involved — each credential field, each preflight value, the
// token and each cookie — is registered with the redactor before the request
// that could reflect it, or before any later request is captured.
func signIn(ctx context.Context, c *httpx.Client, red *redact.Redactor, id Identity, baseURL string,
	lookup Lookup) (session, error) {
	l := id.Auth.Login
	cookies := map[string]string{}
	var preflightBody []byte

	if l.Preflight != nil {
		method := strings.ToUpper(strings.TrimSpace(l.Preflight.Method))
		if method == "" {
			method = http.MethodGet
		}
		resp, err := c.Authenticate(ctx, httpx.Request{
			Method: method, URL: joinPath(baseURL, l.Preflight.Path),
			Header:   map[string][]string{"Accept": {"application/json, */*"}},
			Identity: id.ID, BoundOrigin: baseURL,
		})
		if err != nil {
			return session{}, loginErr("the login preflight %s %s failed: %v", method, l.Preflight.Path, err)
		}
		if resp.Status < 200 || resp.Status > 299 {
			return session{}, loginErr("the login preflight %s %s returned %d", method, l.Preflight.Path, resp.Status)
		}
		collectCookies(cookies, resp.SetCookies, red)
		preflightBody = resp.Body
	}

	values := map[string]string{}
	for _, f := range l.Fields {
		if f.FromPreflight != "" {
			v, ok := jsonpointer.String(preflightBody, f.FromPreflight)
			if !ok || v == "" {
				return session{}, loginErr("the login preflight response has no value at %s for field %s",
					f.FromPreflight, f.Name)
			}
			red.Register(v, redact.Placeholder)
			values[f.Name] = v
			continue
		}
		s, err := f.Source.ResolveWith(lookup)
		if err != nil {
			return session{}, loginErr("login field %s: %v", f.Name, err)
		}
		red.Register(s.Expose(), redact.Placeholder)
		values[f.Name] = s.Expose()
	}

	body, contentType, err := encodeLogin(l, values)
	if err != nil {
		return session{}, loginErr("the login body could not be encoded: %v", err)
	}
	method, loginURL, _, _ := id.LoginRequest(baseURL)
	header := map[string][]string{"Content-Type": {contentType}, "Accept": {"application/json, */*"}}
	pre := session{cookies: cookies}
	if l.CSRF != nil {
		pre.csrf = csrfValue(cookies, l.CSRF.Cookie, red)
	}
	for k, v := range pre.headers(l) {
		header[k] = v
	}

	resp, err := c.Authenticate(ctx, httpx.Request{
		Method: method, URL: loginURL, Header: header, Body: body,
		Identity: id.ID, BoundOrigin: baseURL,
	})
	if err != nil {
		return session{}, loginErr("the login %s %s failed: %v", method, l.Path, err)
	}
	// A login is successful when it issues a session, not when it avoids a 401:
	// several applications answer bad credentials with 400 or 422. A bearer
	// token is read from a 2xx body. A cookie session may also arrive on a
	// redirect, as form logins usually answer; the redirect is never followed,
	// and the login response itself must set a cookie. Whether the session
	// works is then the liveness canary's to establish, not the status's.
	ok := resp.Status >= 200 && resp.Status <= 299
	if l.Session.Cookies && resp.Status >= 300 && resp.Status <= 399 {
		ok = true
	}
	if !ok {
		return session{}, loginErr("the login %s %s returned %d, so no session was issued", method, l.Path,
			resp.Status)
	}
	if resp.Truncated {
		return session{}, loginErr("the login response was larger than the client reads, so the session " +
			"could not be read from it")
	}
	issued := len(resp.SetCookies) > 0
	collectCookies(cookies, resp.SetCookies, red)

	out := session{cookies: map[string]string{}}
	switch {
	case l.Session.Bearer != "":
		tok, ok := jsonpointer.String(resp.Body, l.Session.Bearer)
		if !ok || strings.TrimSpace(tok) == "" {
			return session{}, loginErr("the login %s %s succeeded with %d but its response has no token at %s",
				method, l.Path, resp.Status, l.Session.Bearer)
		}
		red.Register(tok, redact.Placeholder)
		red.Register("Bearer "+tok, redact.Placeholder)
		out.bearer = tok
	case l.Session.Cookies:
		if !issued || len(cookies) == 0 {
			return session{}, loginErr("the login %s %s answered %d but set no cookie, so no session was "+
				"issued", method, l.Path, resp.Status)
		}
		out.cookies = cookies
		if l.CSRF != nil {
			out.csrf = csrfValue(cookies, l.CSRF.Cookie, red)
			if out.csrf == "" {
				return session{}, loginErr("the application set no %s cookie, so the %s header cannot be sent",
					l.CSRF.Cookie, l.CSRF.Header)
			}
		}
	}
	return out, nil
}

// collectCookies records each Set-Cookie's name and value, ignoring its
// attributes. Domain and Path cannot widen where a cookie goes: every request
// an identity sends is bound to its target's origin.
func collectCookies(into map[string]string, setCookies []string, red *redact.Redactor) {
	for _, sc := range setCookies {
		ck, err := http.ParseSetCookie(sc)
		if err != nil || ck.Name == "" {
			continue
		}
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(into, ck.Name)
			continue
		}
		red.Register(ck.Value, redact.Placeholder)
		into[ck.Name] = ck.Value
	}
}

// csrfValue reads the CSRF cookie. Frameworks that issue one URL-encode it,
// and expect the header to carry the decoded value.
func csrfValue(cookies map[string]string, name string, red *redact.Redactor) string {
	v, ok := cookies[name]
	if !ok {
		return ""
	}
	if dec, err := url.QueryUnescape(v); err == nil && dec != v {
		red.Register(dec, redact.Placeholder)
		return dec
	}
	return v
}

// encodeLogin renders the login body deterministically, in field-name order.
func encodeLogin(l *Login, values map[string]string) ([]byte, string, error) {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	if l.Form {
		form := url.Values{}
		for _, n := range names {
			form.Set(n, values[n])
		}
		return []byte(form.Encode()), "application/x-www-form-urlencoded", nil
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(n)
		if err != nil {
			return nil, "", err
		}
		v, err := json.Marshal(values[n])
		if err != nil {
			return nil, "", err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return []byte(b.String()), "application/json", nil
}
