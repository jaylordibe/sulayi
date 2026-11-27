package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/payload"
)

// ErrRefused reports that the safety guard refused a request before anything
// was sent.
type ErrRefused struct {
	Method string
	Target string
	Reason string
}

func (e *ErrRefused) Error() string {
	return fmt.Sprintf("httpx: refused by safety policy: %s %s: %s", e.Method, e.Target, e.Reason)
}

// Guard decides, from the request itself, whether a request may change state
// under the effective profile.
//
// It sits inside Do so that no caller can send a state-changing request around
// it, and it never consults a caller's description of what it is sending: a
// check that says its write is harmless is making a claim, and this is where
// claims are not accepted.
//
//   - A request is state-changing when its method is not read-only, or when it
//     matches an operation the operator named as state-changing (GET /logout).
//   - safe refuses every state-changing request.
//   - standard permits a state-changing request only when it is an exact
//     registered fixture request: the same method, the same URL (path and
//     query), and a JSON object body whose fields are all fields that fixture
//     was registered to change. DELETE is never permitted.
//   - standard also permits a record Sulayi creates and its removal: one exact
//     POST and, once that record exists, one exact DELETE of it, each consumed
//     on first use (ADR-0022). No other DELETE is permitted.
//   - aggressive permits every state-changing request. Scope still applies.
//
// Grants are registered before the assessment executes and then sealed, so
// nothing running during the assessment can widen them.
type Guard struct {
	profile model.Profile

	mu     sync.Mutex
	sealed bool
	grants map[string]map[string]struct{} // "METHOD canonical-url" -> permitted body fields
	rules  []stateChangingRule
	// auth are the exact authentication requests permitted in every profile:
	// an identity's configured login and preflight, and nothing else.
	auth map[string]map[string]struct{}
	// once are one-shot grants for a record Sulayi creates and deletes:
	// the exact body each permits, consumed by the first request that matches.
	once map[string][]byte
}

type stateChangingRule struct {
	method   string
	template string
}

// NewGuard returns a guard for the effective profile.
//
// stateChanging are operator-supplied operation ids ("GET /logout"). Each is
// parsed into a method and a path template here, so a request is recognised
// from its URL alone rather than by which check sent it.
func NewGuard(profile model.Profile, stateChanging []string) (*Guard, error) {
	if !profile.Valid() {
		return nil, fmt.Errorf("httpx: invalid profile %q", profile)
	}
	g := &Guard{profile: profile, grants: map[string]map[string]struct{}{},
		auth: map[string]map[string]struct{}{}, once: map[string][]byte{}}
	for _, id := range stateChanging {
		if err := g.AddStateChangingTemplate(id); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// Profile returns the profile the guard enforces.
func (g *Guard) Profile() model.Profile { return g.profile }

// AddStateChangingTemplate adds an operation, given as "METHOD /path/{param}",
// whose requests are state-changing whatever their method. It is used to add
// the application-absolute spelling of an operation the operator named in the
// specification's spelling.
func (g *Guard) AddStateChangingTemplate(id string) error {
	method, template, ok := strings.Cut(strings.TrimSpace(id), " ")
	template = strings.TrimSpace(template)
	if !ok || method == "" || !strings.HasPrefix(template, "/") {
		return fmt.Errorf("httpx: state-changing operation %q is not of the form \"METHOD /path\"", id)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return errors.New("httpx: the safety guard is sealed")
	}
	g.rules = append(g.rules, stateChangingRule{method: strings.ToUpper(method), template: template})
	return nil
}

// Grant registers one exact fixture request that standard may send.
//
// fields are the body fields the fixture is registered to change; a body
// carrying any other field is refused. A grant for DELETE is rejected rather
// than recorded, because standard never deletes.
func (g *Guard) Grant(method, rawURL string, fields []string) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "DELETE" {
		return errors.New("httpx: the standard profile never permits DELETE")
	}
	if len(fields) == 0 {
		return errors.New("httpx: a grant must name the fields it permits changing")
	}
	key, err := grantKey(method, rawURL)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return errors.New("httpx: the safety guard is sealed")
	}
	set := g.grants[key]
	if set == nil {
		set = map[string]struct{}{}
		g.grants[key] = set
	}
	for _, f := range fields {
		set[f] = struct{}{}
	}
	return nil
}

// GrantCreate registers the one POST that creates a declared record: this URL
// and exactly this body, permitted once.
func (g *Guard) GrantCreate(rawURL string, body []byte) error {
	if len(body) == 0 {
		return errors.New("httpx: a record creation must carry a body")
	}
	return g.grantOnce(http.MethodPost, rawURL, body)
}

// GrantCleanup registers the one DELETE that removes a record this run
// created: this exact URL with no body, permitted once. It is the only DELETE
// the standard profile ever sends, and the caller registers it only for the
// address of a record whose creation it observed succeed.
func (g *Guard) GrantCleanup(rawURL string) error {
	return g.grantOnce(http.MethodDelete, rawURL, nil)
}

func (g *Guard) grantOnce(method, rawURL string, body []byte) error {
	key, err := grantKey(method, rawURL)
	if err != nil {
		return err
	}
	// Aggressive permits every state-changing request and never consults
	// these grants, so recording one would only leave it unconsumed.
	if g.profile == model.ProfileAggressive {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return errors.New("httpx: the safety guard is sealed")
	}
	if _, dup := g.once[key]; dup {
		return fmt.Errorf("httpx: %s %s is already granted once", method, rawURL)
	}
	g.once[key] = append([]byte{}, body...)
	return nil
}

// takeOnce consumes a one-shot grant matching the request exactly.
func (g *Guard) takeOnce(method, rawURL string, body []byte) bool {
	key, err := grantKey(method, rawURL)
	if err != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	want, ok := g.once[key]
	if !ok || !bytes.Equal(want, body) {
		return false
	}
	delete(g.once, key)
	return true
}

// AllowAuthentication registers one identity's configured authentication
// request — its login, or a preflight that fetches a CSRF token — as permitted
// under every profile, including safe.
//
// It is the one exception to "safe sends nothing state-changing", and it is
// narrow on purpose: the exact method and URL, a body carrying only the fields
// the configuration names, and only for a request sent through Authenticate,
// which no check can reach. A check posting the identical request through Do is
// still refused. Scope, origin binding, the budget, pacing and the request log
// all apply as usual.
func (g *Guard) AllowAuthentication(method, rawURL string, fields []string) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "DELETE" {
		return errors.New("httpx: an authentication request may not be a DELETE")
	}
	key, err := grantKey(method, rawURL)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return errors.New("httpx: the safety guard is sealed")
	}
	set := g.auth[key]
	if set == nil {
		set = map[string]struct{}{}
		g.auth[key] = set
	}
	for _, f := range fields {
		set[f] = struct{}{}
	}
	return nil
}

// Seal stops further grants and rules from being added.
func (g *Guard) Seal() {
	g.mu.Lock()
	g.sealed = true
	g.mu.Unlock()
}

// StateChanging reports whether a request is state-changing.
func (g *Guard) StateChanging(method, rawURL string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if !model.IsSafeMethod(method) {
		return true
	}
	if g == nil {
		// No guard means no operator rules: only the method decides.
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		// A URL that cannot be parsed cannot be shown not to match a rule.
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.rules {
		if r.method == method && model.PathMatchesTemplate(r.template, u.EscapedPath()) {
			return true
		}
	}
	return false
}

// check decides whether a request may be sent. A nil guard behaves as the
// safe profile with no grants, so a client built without one fails closed.
// authentication is true only for a request sent through Authenticate.
func (g *Guard) check(method, rawURL string, body []byte, authentication bool) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	refuse := func(reason string) error {
		return &ErrRefused{Method: method, Target: rawURL, Reason: reason}
	}

	var stateChanging bool
	profile := model.ProfileSafe
	if g == nil {
		stateChanging = !model.IsSafeMethod(method)
	} else {
		stateChanging = g.StateChanging(method, rawURL)
		profile = g.profile
	}
	if !stateChanging {
		return nil
	}

	if authentication && g != nil {
		if key, err := grantKey(method, rawURL); err == nil {
			g.mu.Lock()
			fields, ok := g.auth[key]
			g.mu.Unlock()
			if ok {
				if err := authBodyWithin(body, fields); err != nil {
					return refuse(err.Error())
				}
				return nil
			}
		}
	}

	switch profile {
	case model.ProfileAggressive:
		return nil
	case model.ProfileStandard:
		if g.takeOnce(method, rawURL, body) {
			return nil
		}
		if method == "DELETE" {
			return refuse("the standard profile never sends DELETE")
		}
		key, err := grantKey(method, rawURL)
		if err != nil {
			return refuse("the target could not be verified: " + err.Error())
		}
		g.mu.Lock()
		fields, ok := g.grants[key]
		g.mu.Unlock()
		if !ok {
			return refuse("state-changing request is not an exact request against a fixture " +
				"registered as disposable; the standard profile permits no other")
		}
		if err := bodyWithin(body, fields); err != nil {
			return refuse(err.Error())
		}
		return nil
	default:
		return refuse(fmt.Sprintf("state-changing request under the %s profile", profile))
	}
}

// checkPayload refuses a request carrying a catalogued payload whose impact
// class the profile does not permit (ADR-0023). The payload is recognised in the
// request itself, never taken from the sender's description of it. Inert
// payloads go anywhere; evaluating and query-altering ones only in a read
// (GET or HEAD) and never under safe. A nil guard behaves as safe.
func (g *Guard) checkPayload(method, rawURL string, header map[string][]string, body []byte) error {
	p, ok := payload.Find(rawURL, header, body)
	if !ok {
		return nil
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	profile := model.ProfileSafe
	if g != nil {
		profile = g.profile
	}
	refuse := func(reason string) error {
		return &ErrRefused{Method: method, Target: rawURL, Reason: reason}
	}
	if profile == model.ProfileSafe {
		return refuse(fmt.Sprintf("payload %s is %s, which the safe profile does not send", p.ID, p.Class))
	}
	if method != http.MethodGet && method != http.MethodHead {
		return refuse(fmt.Sprintf("payload %s is %s, which is sent only in a read (GET or HEAD)", p.ID, p.Class))
	}
	return nil
}

// grantKey canonicalises a request target for exact comparison: scheme and host
// lowercased, the default port made explicit, the escaped path and the raw
// query kept exactly. Anything ambiguous is an error rather than a guess.
func grantKey(method, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("unparseable URL: %w", err)
	}
	if u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return "", errors.New("URL carries a fragment, credentials or an opaque part")
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	for _, seg := range strings.Split(path, "/") {
		if s := strings.ToLower(seg); s == "." || s == ".." || strings.Contains(s, "%2e") || strings.Contains(s, "%2f") {
			return "", errors.New("URL path carries a dot or encoded separator segment")
		}
	}
	host := net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	return method + " " + scheme + "://" + host + path + "?" + u.RawQuery, nil
}

// bodyWithin requires a JSON object whose every top-level field is permitted.
// An empty body is refused: a state-changing request with no body can still
// trigger an action, and what it changes cannot be verified.
func bodyWithin(body []byte, permitted map[string]struct{}) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		return errors.New("the request has no body, so what it changes cannot be verified")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return errors.New("the body is not a JSON object, so the fields it changes cannot be verified")
	}
	var extra []string
	for k := range obj {
		if _, ok := permitted[k]; !ok {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("the body changes field(s) %s that the fixture was not registered to change",
			strings.Join(extra, ", "))
	}
	return nil
}

// authBodyWithin requires an authentication body to carry only the configured
// fields, as a JSON object or as a URL-encoded form.
func authBodyWithin(body []byte, permitted map[string]struct{}) error {
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	if err := bodyWithin(body, permitted); err == nil {
		return nil
	} else if json.Valid(body) {
		return err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return errors.New("the authentication body is neither a JSON object nor a form, so its fields cannot be verified")
	}
	var extra []string
	for k := range form {
		if _, ok := permitted[k]; !ok {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("the authentication body carries field(s) %s that are not configured",
			strings.Join(extra, ", "))
	}
	return nil
}
