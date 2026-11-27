package discovery

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/scope"
)

// Browser defaults. A page is a full application load, so the numbers are
// smaller than the crawler's.
const (
	DefaultBrowserPages       = 20
	DefaultBrowserDepth       = 3
	DefaultBrowserMaxRequests = 300
	// MaxBrowserOperations bounds what one actor's browsing contributes.
	MaxBrowserOperations = 1000
)

// Recorder collects the requests Sulayi's browser saw a page make, as one
// actor. The relay that sends them on the page's behalf records each one,
// sent or refused: a state-changing request the relay refused to send is
// still a request the front end makes, with the method it uses.
//
// It is safe for concurrent use; a page relays several requests at once.
type Recorder struct {
	obs   observer
	actor string

	mu    sync.Mutex
	ops   map[string]*model.Operation
	order []string
	// documents holds what the target answered when a route was loaded as a
	// page; data marks routes a page also requested as data, or a rendered
	// form declared, which makes them routes whatever their page looked like.
	documents map[string]fingerprint
	data      map[string]bool
	offOrigin int
	assets    int
	sensitive int
	seen      int
	truncated bool
}

// NewRecorder returns a recorder for one actor browsing target.
func NewRecorder(target, actor string) (*Recorder, error) {
	obs, err := newObserver(target)
	if err != nil {
		return nil, err
	}
	return &Recorder{
		obs: obs, actor: actor,
		ops: map[string]*model.Operation{}, documents: map[string]fingerprint{}, data: map[string]bool{},
	}, nil
}

// Exchange is one relayed request as the recorder sees it. Status is zero for
// a request that was refused or failed before any response.
type Exchange struct {
	Method       string
	URL          string
	ResourceType string
	Status       int
	ContentType  string
	Body         []byte
}

// Record notes one request a page made.
//
// A document — a page load — is a route only if it answered as one: not
// missing, not a server error, and not the application's fallback page. A
// redirect is an answer: the route exists, and where it sends the browser is
// relayed and judged as a request of its own. Those are decided once browsing ends, when the fallback is
// known. Every other request is evidence of a route by being made at all, as
// in a recording.
func (r *Recorder) Record(ex Exchange) {
	ob, v := r.obs.observe(ex.Method, ex.URL)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen++
	switch v {
	case observedOffOrigin:
		r.offOrigin++
		return
	case observedAsset:
		r.assets++
		return
	case observedSensitive:
		r.sensitive++
		return
	case observedSkipped:
		return
	}
	id := model.OperationID(ob.method, ob.path)
	if ex.ResourceType == "Document" {
		switch {
		case ex.Status == 0, ex.Status == 404, ex.Status == 410, ex.Status >= 500:
			// Nothing about a route the page could not load is kept from the
			// load itself; another request may still establish it.
			return
		}
		r.documents[id] = fingerprintOf(Page{Status: ex.Status, ContentType: ex.ContentType, Body: ex.Body})
	} else {
		r.data[id] = true
	}
	if op, ok := r.ops[id]; ok {
		addQueryParams(op, ob.query)
		return
	}
	if len(r.ops) >= MaxBrowserOperations {
		r.truncated = true
		return
	}
	op := r.obs.operation(ob, model.Source{Kind: model.SourceBrowser, Ref: "browser " + r.actor + " request"})
	r.ops[id] = &op
	r.order = append(r.order, id)
}

// documentFingerprint returns what the target answered when the page loaded
// rawURL, if it was recorded.
func (r *Recorder) documentFingerprint(rawURL string) (fingerprint, bool) {
	ob, v := r.obs.observe("GET", rawURL)
	if v != observedKept {
		return fingerprint{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fp, ok := r.documents[model.OperationID(ob.method, ob.path)]
	return fp, ok
}

// Visit loads one page in the browser and reports what rendered. Stop reports
// that browsing must end: a budget or the deadline is spent.
type Visit func(ctx context.Context, rawURL string) (links []string, forms []RenderedForm, stop bool, err error)

// RenderedForm is a form in a rendered page.
type RenderedForm struct {
	Action string
	Method string
}

// BrowseOptions configures one actor's browsing.
type BrowseOptions struct {
	Target   string
	Actor    string
	Visit    Visit
	Recorder *Recorder
	MaxPages int
	MaxDepth int
	// Skip reports a path that must never be loaded: a sign-out route, a
	// configured state-changing route, an excluded operation. A client-side
	// route (#/logout) is checked as a path too.
	Skip func(path string) bool
	// Settle, when set, is called once browsing ends and before what was
	// recorded becomes operations, so requests still in flight are counted.
	Settle func()
}

// BrowseResult is what one actor's browsing found.
type BrowseResult struct {
	Actor      string
	Operations []model.Operation
	Pages      int
	// Requests counts the requests the pages made, of every kind.
	Requests int
	// Loaded counts pages that rendered at all. Zero means the target could
	// not be browsed as this actor, and the result says so.
	Loaded int
	// Failed counts pages that did not load or could not be read.
	Failed    int
	OffOrigin int
	Skipped   int
	Forms     int
	// Fallback reports that the target answers unknown paths with a page, as
	// single-page applications do; such loads never count as routes.
	Fallback    bool
	Incomplete  bool
	Limitations []string
}

// Browse loads the target's pages in a browser, breadth first from the root,
// following the links that rendered — including client-side routes — to a
// fixed depth and page count. It never clicks, types or submits: what it learns
// is what the front end requests on its own as each page loads, and the
// methods its rendered forms declare.
//
// Every request a page makes is sent, or refused, by the caller's relay, which
// records it in opts.Recorder; Browse turns those records into operations.
func Browse(ctx context.Context, opts BrowseOptions) BrowseResult {
	res := BrowseResult{Actor: opts.Actor}
	if opts.MaxPages <= 0 {
		opts.MaxPages = DefaultBrowserPages
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultBrowserDepth
	}
	origin, err := scope.ParseOrigin(opts.Target)
	if err != nil || opts.Recorder == nil {
		res.Limitations = append(res.Limitations, "the target's origin could not be established, so nothing "+
			"was browsed")
		return res
	}
	base, _ := url.Parse(opts.Target)
	basePath := strings.TrimRight(base.Path, "/")
	root := originURL(origin, basePath+"/")

	// What the target serves for a path that cannot exist. A page load that
	// answers the same is the application's fallback, not a route.
	probe := originURL(origin, basePath+"/sulayi-browse-"+nonce())
	_, _, stop, perr := opts.Visit(ctx, probe)
	if stop {
		res.Incomplete = true
		res.Limitations = append(res.Limitations, fmt.Sprintf("browsing as %s stopped before it began: the "+
			"request budget or deadline was reached", opts.Actor))
		return res.finish(opts.Recorder, nil, probe, opts.Settle)
	}
	var fallback *fingerprint
	if perr == nil {
		if fp, ok := opts.Recorder.documentFingerprint(probe); ok && fp.status >= 200 && fp.status < 300 {
			fallback = &fp
			res.Fallback = true
		}
	}

	// within normalises a rendered URL to one on the target, under its base
	// path, or reports that it is not one. A fragment is kept only when it is a
	// client-side route (#/… or #!/…), and returned as route so Skip can judge
	// it; any other fragment names a place in a page, not a page.
	within := func(raw string) (link, p, route string, ok bool) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", "", "", false
		}
		o, err := scope.OriginOf(u)
		if err != nil || o != origin {
			res.OffOrigin++
			return "", "", "", false
		}
		p = path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
		if basePath != "" && p != basePath && !strings.HasPrefix(p, basePath+"/") {
			res.OffOrigin++
			return "", "", "", false
		}
		if strings.HasSuffix(u.Path, "/") && p != "/" {
			p += "/"
		}
		switch {
		case strings.HasPrefix(u.Fragment, "/"):
			route = path.Clean(u.Fragment)
		case strings.HasPrefix(u.Fragment, "!/"):
			route = path.Clean(u.Fragment[1:])
		default:
			u.Fragment = ""
		}
		u.Path, u.RawPath = p, ""
		return u.String(), strings.TrimPrefix(p, basePath), route, true
	}
	skipped := func(p, route string) bool {
		return opts.Skip != nil && (opts.Skip(p) || (route != "" && opts.Skip(route)))
	}

	type item struct {
		url   string
		path  string
		route string
		depth int
	}
	queue := []item{{root, "/", "", 0}}
	queued := map[string]bool{root: true}
	for len(queue) > 0 {
		if res.Pages >= opts.MaxPages {
			res.Incomplete = true
			res.Limitations = append(res.Limitations, fmt.Sprintf("browsing as %s reached its %d-page limit "+
				"with %d page(s) still queued", opts.Actor, opts.MaxPages, len(queue)))
			break
		}
		it := queue[0]
		queue = queue[1:]
		if skipped(it.path, it.route) {
			res.Skipped++
			continue
		}
		links, forms, stop, err := opts.Visit(ctx, it.url)
		if stop {
			res.Incomplete = true
			res.Limitations = append(res.Limitations, fmt.Sprintf("browsing as %s stopped: the request "+
				"budget or deadline was reached", opts.Actor))
			break
		}
		res.Pages++
		if err != nil {
			res.Failed++
			continue
		}
		res.Loaded++
		for _, f := range forms {
			action := f.Action
			if action == "" {
				action = it.url
			}
			_, p, _, ok := within(action)
			if !ok {
				continue
			}
			method := strings.ToUpper(strings.TrimSpace(f.Method))
			if method != "GET" && method != "POST" {
				// HTML forms submit only GET and POST, as in the crawler.
				continue
			}
			res.Forms++
			if opts.Skip != nil && opts.Skip(p) {
				res.Skipped++
				continue
			}
			opts.Recorder.addForm(method, p)
		}
		if it.depth >= opts.MaxDepth {
			continue
		}
		for _, l := range links {
			u, p, route, ok := within(l)
			if !ok || queued[u] {
				continue
			}
			queued[u] = true
			queue = append(queue, item{u, p, route, it.depth + 1})
		}
	}
	return res.finish(opts.Recorder, fallback, probe, opts.Settle)
}

// addForm records a rendered form's declared method and action.
func (r *Recorder) addForm(method, p string) {
	ob := observed{method: method, path: p}
	id := model.OperationID(method, p)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[id] = true
	if _, ok := r.ops[id]; ok {
		return
	}
	if len(r.ops) >= MaxBrowserOperations {
		r.truncated = true
		return
	}
	op := r.obs.operation(ob, model.Source{Kind: model.SourceBrowser, Ref: "browser " + r.actor + " form"})
	r.ops[id] = &op
	r.order = append(r.order, id)
}

// finish turns the recorder's observations into the result's operations,
// leaving out page loads that were the application's fallback, and the probe
// that established it with everything requested under its path.
func (res BrowseResult) finish(r *Recorder, fallback *fingerprint, probe string, settle func()) BrowseResult {
	if settle != nil {
		settle()
	}
	switch {
	case res.Pages > 0 && res.Loaded == 0:
		res.Incomplete = true
		res.Limitations = append(res.Limitations, fmt.Sprintf("browsing as %s loaded none of the %d page(s) "+
			"it tried, so it found nothing it could have", res.Actor, res.Pages))
	case res.Failed > 0:
		res.Limitations = append(res.Limitations, fmt.Sprintf("browsing as %s could not load %d of %d page(s)",
			res.Actor, res.Failed, res.Pages))
	}
	// The probe's path is one Sulayi made up. A page loaded there may request
	// paths relative to it — a chat client polling <probe>/socket.io/ — and
	// none of them is a route of the application, nor the same from one run to
	// the next.
	probePath := ""
	if ob, v := r.obs.observe("GET", probe); v == observedKept {
		probePath = ob.path
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.order {
		op := r.ops[id]
		if probePath != "" && (op.PathTemplate == probePath || strings.HasPrefix(op.PathTemplate, probePath+"/")) {
			continue
		}
		if !r.data[id] {
			// Loaded only as a page: a route only if it was not the fallback.
			if fp := r.documents[id]; fallback != nil && fp == *fallback {
				continue
			}
		}
		res.Operations = append(res.Operations, *r.ops[id])
	}
	res.Requests = r.seen
	res.OffOrigin += r.offOrigin
	if r.truncated {
		res.Incomplete = true
		res.Limitations = append(res.Limitations, fmt.Sprintf("browsing as %s found more than %d routes; "+
			"the rest were not kept", res.Actor, MaxBrowserOperations))
	}
	model.SortOperations(res.Operations)
	sort.Strings(res.Limitations)
	return res
}
