package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/jaylordibe/sulayi/internal/model"
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
	g := &Guard{profile: profile, grants: map[string]map[string]struct{}{}}
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
func (g *Guard) check(method, rawURL string, body []byte) error {
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

	switch profile {
	case model.ProfileAggressive:
		return nil
	case model.ProfileStandard:
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
