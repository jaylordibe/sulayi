package discovery

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/scope"
)

// maxObservedQueryNames bounds the query parameter names one observed
// operation keeps.
const maxObservedQueryNames = 16

// queryName is the shape of a query parameter name worth injecting into. A
// name outside it is more likely data than a parameter.
var queryName = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]]{1,64}$`)

// verdict is what became of one observed request.
type verdict int

const (
	observedKept verdict = iota
	observedOffOrigin
	observedAsset
	observedSkipped
	observedSensitive
)

// observed is a request a front end was seen making, reduced to what
// discovery keeps: its method, its path under the target's base path, and the
// names of its query parameters. Values are never kept.
type observed struct {
	method string
	path   string
	query  []string
}

// observer turns requests a front end made — recorded in a HAR, or made in
// Sulayi's browser — into operations. Both sources go through it, so an
// operation means the same thing whichever one saw it.
type observer struct {
	origin   scope.Origin
	basePath string
	baseURL  string
}

func newObserver(baseURL string) (observer, error) {
	origin, err := scope.ParseOrigin(baseURL)
	if err != nil {
		return observer{}, err
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return observer{}, err
	}
	return observer{origin: origin, basePath: strings.TrimRight(base.Path, "/"), baseURL: baseURL}, nil
}

// observe classifies one request. Only same-origin requests under the base
// path are kept; static assets, paths with dot segments and paths carrying a
// token-like segment are not.
func (o observer) observe(method, rawURL string) (observed, verdict) {
	method = strings.ToUpper(strings.TrimSpace(method))
	u, err := url.Parse(rawURL)
	if err != nil || !harMethods[method] {
		return observed{}, observedSkipped
	}
	origin, err := scope.OriginOf(u)
	if err != nil || origin != o.origin {
		return observed{}, observedOffOrigin
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	if o.basePath != "" {
		if p != o.basePath && !strings.HasPrefix(p, o.basePath+"/") {
			return observed{}, observedOffOrigin
		}
		p = strings.TrimPrefix(p, o.basePath)
		if p == "" {
			p = "/"
		}
	}
	if assetExtensions[strings.ToLower(path.Ext(p))] {
		return observed{}, observedAsset
	}
	if hasDotSegment(p) {
		return observed{}, observedSkipped
	}
	if sensitivePath(p) {
		return observed{}, observedSensitive
	}
	return observed{method: method, path: p, query: queryNames(u.RawQuery)}, observedKept
}

// queryNames returns the distinct, well-formed parameter names in a raw query.
// A name that looks like a token is dropped with its value, and so is a bare
// key: in "?Q7xK2pL9aZ" the key is the value — often a one-time code — not the
// name of a parameter.
func queryNames(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, pair := range strings.Split(raw, "&") {
		k, v, hasValue := strings.Cut(pair, "=")
		if !hasValue || (v != "" && strings.Trim(v, "=") == "") {
			// No "=", or only base64 padding after the key ("dGVzdA=="): the
			// key is a value. An empty value ("q=") is a parameter sent empty.
			continue
		}
		if name, err := url.QueryUnescape(k); err == nil {
			seen[name] = true
		}
	}
	var out []string
	for name := range seen {
		if !queryName.MatchString(name) || (tokenSegment.MatchString(name) && strings.ContainsAny(name, "0123456789")) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) > maxObservedQueryNames {
		out = out[:maxObservedQueryNames]
	}
	return out
}

// operation builds the operation for an observation.
func (o observer) operation(ob observed, src model.Source) model.Operation {
	op := model.Operation{
		ID: model.OperationID(ob.method, ob.path), Method: ob.method, PathTemplate: ob.path,
		BaseURL: o.baseURL, Sources: []model.Source{src},
	}
	addQueryParams(&op, ob.query)
	return op
}

// addQueryParams adds query parameters an operation does not already declare.
// An observed parameter is never required: the front end was seen sending it,
// which says nothing about whether the route needs it.
func addQueryParams(op *model.Operation, names []string) {
	for _, name := range names {
		declared := false
		for _, p := range op.Parameters {
			if p.In == "query" && p.Name == name {
				declared = true
				break
			}
		}
		if !declared {
			op.Parameters = append(op.Parameters, model.Parameter{Name: name, In: "query"})
		}
	}
}

// queryParamNames returns the names of an operation's query parameters.
func queryParamNames(op model.Operation) []string {
	var out []string
	for _, p := range op.Parameters {
		if p.In == "query" {
			out = append(out, p.Name)
		}
	}
	return out
}
