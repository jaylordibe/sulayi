package discovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/scope"
)

// Crawl defaults. They are deliberately small: the crawler finds routes for
// the checks to assess, it does not mirror a site.
const (
	DefaultCrawlPages = 50
	DefaultCrawlDepth = 3
	// MaxCrawlOperations bounds what one crawl contributes.
	MaxCrawlOperations = 500
	maxAnchorsPerPage  = 200
)

// Page is what a crawl fetch returned. Body is read only for HTML.
type Page struct {
	Status      int
	ContentType string
	Location    string
	Body        []byte
}

// Fetch performs one crawl request: a GET of a same-origin URL, sent by the
// caller through the scope-enforcing client — anonymously, or as an identity.
// Stop reports that the crawl must end: the budget or deadline is spent.
type Fetch func(ctx context.Context, rawURL string) (page Page, stop bool, err error)

// CrawlOptions configures one crawl.
type CrawlOptions struct {
	// Target is the base URL; only its origin, under its path, is crawled.
	Target string
	// Actor names who the crawl runs as, for provenance: anonymous or an
	// identity id.
	Actor    string
	Fetch    Fetch
	MaxPages int
	MaxDepth int
	// Skip reports a path that must never be requested: a sign-out route, a
	// configured state-changing route, an excluded operation.
	Skip func(path string) bool
}

// CrawlResult is what one crawl found and what it could not do.
type CrawlResult struct {
	Actor      string
	Operations []model.Operation
	Pages      int
	// Responses counts requests the target answered at all. Zero means the
	// target could not be reached as this actor.
	Responses int
	OffOrigin int
	Skipped   int
	Forms     int
	// Fallback reports that the target answers unknown paths like a real page,
	// as single-page applications do; such responses never count as routes.
	Fallback    bool
	Incomplete  bool
	Limitations []string
}

type fingerprint struct {
	status int
	ctype  string
	hash   string
}

func fingerprintOf(p Page) fingerprint {
	sum := sha256.Sum256(p.Body)
	return fingerprint{status: p.Status, ctype: mediaType(p.ContentType), hash: hex.EncodeToString(sum[:])}
}

func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// Crawl walks the target's own pages, breadth first, with GET only.
//
// It is the smallest crawler that finds routes without a specification, and
// its limits are the design: one origin, under the target's base path; GET
// only, through the caller's scope-enforcing fetch; links followed to a fixed
// depth and page count; forms recorded with the method they declare and never
// submitted; no script executed; redirects off-origin recorded, never
// followed. A path the caller says to skip — sign-out, a configured
// state-changing route, an excluded operation — is never requested.
//
// A route it finds is an operation because HTML establishes the method: a link
// is navigated with GET, and a form declares its own. A path seen anywhere
// without a method is not turned into a request.
func Crawl(ctx context.Context, opts CrawlOptions) CrawlResult {
	res := CrawlResult{Actor: opts.Actor}
	if opts.MaxPages <= 0 {
		opts.MaxPages = DefaultCrawlPages
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultCrawlDepth
	}
	origin, err := scope.ParseOrigin(opts.Target)
	if err != nil {
		res.Limitations = append(res.Limitations, "the target's origin could not be established, so nothing was crawled")
		return res
	}
	base, _ := url.Parse(opts.Target)
	basePath := strings.TrimRight(base.Path, "/")
	root := basePath + "/"

	// The not-found fingerprint: what this target returns for a path that
	// cannot exist. A page answering the same is the target's fallback, not a
	// route.
	var fallback *fingerprint
	if probe, stop, err := opts.Fetch(ctx, originURL(origin, root+"sulayi-crawl-"+nonce())); err == nil && !stop {
		res.Responses++
		if probe.Status >= 200 && probe.Status < 300 {
			fp := fingerprintOf(probe)
			fallback = &fp
			res.Fallback = true
		}
	} else if stop {
		res.Incomplete = true
		res.Limitations = append(res.Limitations, "the crawl stopped before it began: the request budget or "+
			"deadline was reached")
		return res
	}

	type item struct {
		path  string
		depth int
	}
	queue := []item{{root, 0}}
	queued := map[string]bool{root: true}
	ops := map[string]model.Operation{}
	add := func(method, p, how string) {
		if len(ops) >= MaxCrawlOperations {
			res.Incomplete = true
			return
		}
		id := model.OperationID(method, strings.TrimPrefix(p, basePath))
		if _, ok := ops[id]; ok {
			return
		}
		ops[id] = model.Operation{
			ID: id, Method: method, PathTemplate: strings.TrimPrefix(p, basePath), BaseURL: opts.Target,
			Sources: []model.Source{{Kind: model.SourceCrawl, Ref: "crawl " + opts.Actor + " " + how}},
		}
	}
	// within normalises a link to a same-origin path under the base path, or
	// reports that it is not one.
	within := func(pageURL, ref string) (string, bool) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "#") {
			return "", false
		}
		pu, err := url.Parse(pageURL)
		if err != nil {
			return "", false
		}
		u, err := pu.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", false
		}
		o, err := scope.OriginOf(u)
		if err != nil || o != origin {
			res.OffOrigin++
			return "", false
		}
		p := path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
		if basePath != "" && p != basePath && !strings.HasPrefix(p, basePath+"/") {
			res.OffOrigin++
			return "", false
		}
		if strings.HasSuffix(u.Path, "/") && p != "/" {
			p += "/"
		}
		return p, true
	}

	for len(queue) > 0 {
		if res.Pages >= opts.MaxPages {
			res.Incomplete = true
			res.Limitations = append(res.Limitations, fmt.Sprintf("the crawl as %s reached its %d-page limit "+
				"with %d page(s) still queued", opts.Actor, opts.MaxPages, len(queue)))
			break
		}
		it := queue[0]
		queue = queue[1:]
		if opts.Skip != nil && opts.Skip(it.path) {
			res.Skipped++
			continue
		}
		pageURL := originURL(origin, it.path)
		page, stop, err := opts.Fetch(ctx, pageURL)
		if stop {
			res.Incomplete = true
			res.Limitations = append(res.Limitations, fmt.Sprintf("the crawl as %s stopped: the request "+
				"budget or deadline was reached", opts.Actor))
			break
		}
		res.Pages++
		if err != nil {
			continue
		}
		res.Responses++

		isFallback := fallback != nil && fingerprintOf(page) == *fallback
		switch {
		case page.Status >= 300 && page.Status < 400:
			if p, ok := within(pageURL, page.Location); ok && !queued[p] && it.depth < opts.MaxDepth {
				queued[p] = true
				queue = append(queue, item{p, it.depth + 1})
			}
			continue
		case page.Status == 404 || page.Status == 410 || page.Status >= 500:
			continue
		case !isFallback && it.path != root:
			// A route that answered — 2xx, or a refusal that shows it exists.
			add("GET", it.path, "page")
		}

		if mediaType(page.ContentType) != "text/html" || it.depth >= opts.MaxDepth {
			continue
		}
		for _, a := range elementAttrs(page.Body, "a", "href") {
			p, ok := within(pageURL, a["href"])
			if !ok || queued[p] {
				continue
			}
			queued[p] = true
			queue = append(queue, item{p, it.depth + 1})
		}
		for _, f := range elementAttrs(page.Body, "form", "action", "method") {
			action := f["action"]
			if action == "" {
				action = pageURL
			}
			p, ok := within(pageURL, action)
			if !ok {
				continue
			}
			method := strings.ToUpper(strings.TrimSpace(f["method"]))
			if method == "" {
				method = "GET"
			}
			if method != "GET" && method != "POST" {
				// HTML forms submit only GET and POST; anything else is a
				// framework convention (a hidden _method field) and not a
				// method HTML establishes.
				continue
			}
			res.Forms++
			if opts.Skip != nil && opts.Skip(p) {
				res.Skipped++
				continue
			}
			add(method, p, "form")
		}
	}

	for _, op := range ops {
		res.Operations = append(res.Operations, op)
	}
	model.SortOperations(res.Operations)
	sort.Strings(res.Limitations)
	return res
}

func originURL(o scope.Origin, p string) string {
	return o.String() + p
}

func nonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// elementAttrs returns the named attributes of every <tag> element, using the
// same tolerant scanner as ScriptSources.
func elementAttrs(body []byte, tag string, names ...string) []map[string]string {
	s := string(body)
	open := "<" + tag
	var out []map[string]string
	i, n := 0, len(s)
	for i < n && len(out) < maxAnchorsPerPage {
		j := indexFoldASCII(s[i:], open)
		if j < 0 {
			break
		}
		i += j + len(open)
		if i < n {
			if c := s[i]; c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '>' && c != '/' {
				continue
			}
		}
		end := tagEnd(s, i)
		if end < 0 {
			break
		}
		attrs := map[string]string{}
		for _, name := range names {
			attrs[name] = attrValue(s[i:end], name)
		}
		out = append(out, attrs)
		i = end + 1
	}
	return out
}
