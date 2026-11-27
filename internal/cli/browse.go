package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaylordibe/sulayi/internal/browser"
	"github.com/jaylordibe/sulayi/internal/config"
	"github.com/jaylordibe/sulayi/internal/discovery"
	"github.com/jaylordibe/sulayi/internal/engine"
	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
)

// Browser limits that are not configuration.
const (
	// browserPageTimeout bounds one page load, including the wait for the
	// page to go quiet.
	browserPageTimeout = 15 * time.Second
	// browserCacheBytes bounds the static assets kept per actor, so moving
	// between pages does not spend the budget reloading the same bundle.
	browserCacheBytes = 64 << 20
	// browserRepeats bounds how often one actor sends the same method and
	// path, whatever the query. A route already seen is not discovered again
	// by asking a fourth time, and a page that polls — a chat or live-update
	// feature whose stream is refused — would otherwise spend the whole budget.
	browserRepeats = 3
)

// browserForwardedHeaders are the only request headers a page's own request
// contributes. Credentials come from the actor alone — the anonymous caller
// sends none, an identity sends its own — so a page can neither add one nor
// replace one, and the user agent stays Sulayi's.
var browserForwardedHeaders = []string{"Accept", "Accept-Language", "X-Requested-With"}

// browserDroppedResponseHeaders describe the connection the relay made, not
// the response the page receives.
var browserDroppedResponseHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Content-Length": true,
	"Content-Encoding": true, "Upgrade": true, "Proxy-Authenticate": true, "Trailer": true,
}

// browserActor is one caller the browser runs as.
type browserActor struct {
	name  string
	relay func(ctx context.Context, method, u string, h map[string][]string) (httpx.RelayResponse, error)
}

// runBrowser loads the target in a headless browser as the anonymous caller
// and as each usable identity, and adds what the pages requested to the
// surface (ADR-0026). It reports a browser that could not run rather than
// failing the assessment: the other sources still ran.
func runBrowser(ctx context.Context, cfg config.Config, exe string, client *httpx.Client, guard *httpx.Guard,
	identities *identity.Set, surface *engine.Surface, stderr io.Writer) {
	b, err := browser.Launch(ctx, exe)
	if err != nil {
		surface.BrowserProblem = err.Error()
		fmt.Fprintf(stderr, "sulayi: browser: did not run: %v\n", err)
		return
	}
	defer func() {
		if err := b.Close(); err != nil {
			fmt.Fprintf(stderr, "sulayi: browser: warning: %v; it holds what the target stored in the "+
				"browser and should be deleted\n", err)
		}
	}()

	actors := []browserActor{{model.AnonymousIdentity().ID,
		func(ctx context.Context, method, u string, h map[string][]string) (httpx.RelayResponse, error) {
			return client.Relay(ctx, httpx.Request{Method: method, URL: u, Header: h})
		}}}
	for _, ctl := range identities.Controls() {
		if ok, _, _ := ctl.Usable(); !ok {
			continue
		}
		actors = append(actors, browserActor{ctl.ID(), ctl.Relay})
	}

	pages, depth, requests := cfg.BrowserLimits()
	perActor := requests / len(actors)
	if perActor < 1 {
		perActor = 1
	}
	skip := func(p string) bool {
		u := strings.TrimRight(cfg.Target.BaseURL, "/") + p
		return model.LooksLikeAuthRoute(p) || guard.StateChanging(http.MethodGet, u) ||
			model.Operation{Method: http.MethodGet, PathTemplate: p}.MatchesAnyID(cfg.Assessment.ExcludeOperations)
	}

	for _, a := range actors {
		if ctx.Err() != nil {
			break
		}
		rec, err := discovery.NewRecorder(cfg.Target.BaseURL, a.name)
		if err != nil {
			surface.BrowserProblem = err.Error()
			return
		}
		relay := newBrowserRelay(a, rec, perActor)
		relay.target, relay.skip = cfg.Target.BaseURL, skip
		page, err := b.NewPage(ctx, relay.relay)
		if err != nil {
			surface.BrowserProblem = err.Error()
			fmt.Fprintf(stderr, "sulayi: browser: did not run as %s: %v\n", a.name, err)
			return
		}
		res := discovery.Browse(ctx, discovery.BrowseOptions{
			Target: cfg.Target.BaseURL, Actor: a.name, Recorder: rec, MaxPages: pages, MaxDepth: depth, Skip: skip,
			// Closing the tab waits for every request it still had in
			// flight, so those are recorded before they become operations.
			Settle: page.Close,
			Visit: func(ctx context.Context, u string) ([]string, []discovery.RenderedForm, bool, error) {
				r, err := page.Visit(ctx, u, browserPageTimeout)
				stop := relay.stopped.Load() || ctx.Err() != nil
				if err != nil {
					return nil, nil, stop, err
				}
				forms := make([]discovery.RenderedForm, 0, len(r.Forms))
				for _, f := range r.Forms {
					forms = append(forms, discovery.RenderedForm{Action: f.Action, Method: f.Method})
				}
				return r.Links, forms, stop, nil
			},
		})
		var added int
		surface.Operations, added, _ = discovery.MergeOperations(surface.Operations, res.Operations)
		surface.BrowserAdded += added
		surface.Browsing = append(surface.Browsing, res)
	}

	var found int
	for _, r := range surface.Browsing {
		found += len(r.Operations)
	}
	fmt.Fprintf(stderr, "sulayi: browser: %d route(s) found as %d actor(s), %d new to the surface\n",
		found, len(surface.Browsing), surface.BrowserAdded)
}

// browserRelay sends one actor's page requests through Sulayi's client.
type browserRelay struct {
	actor   browserActor
	rec     *discovery.Recorder
	limit   int64
	sent    atomic.Int64
	stopped atomic.Bool

	// target and skip refuse a page's own requests to the routes browsing
	// never loads — sign-out and authentication, a GET the operator listed as
	// state-changing, an excluded operation — so a page cannot end or rotate
	// the session of the identity it runs as.
	target string
	skip   func(path string) bool

	mu         sync.Mutex
	cache      map[string]browser.Response
	cacheBytes int
	repeats    map[string]int
}

func newBrowserRelay(a browserActor, rec *discovery.Recorder, limit int) *browserRelay {
	return &browserRelay{actor: a, rec: rec, limit: int64(limit), cache: map[string]browser.Response{},
		repeats: map[string]int{}}
}

var (
	errBrowserBudget = errors.New("the browser's request budget is spent")
	errNotFetched    = errors.New("images, fonts and media are not fetched")
	errRepeated      = errors.New("this route was already requested as often as browsing sends one")
	errSkipped       = errors.New("a sign-out, authentication, state-changing or excluded route is never " +
		"requested by the browser")
)

// cacheable reports a request whose response can be reused for this actor: a
// GET of the same URL. A single-page application asks for its bundle and its
// configuration on every page load, and asking again teaches discovery nothing.
func cacheable(r browser.Request) bool {
	return r.Method == http.MethodGet
}

// unfetched reports a request that is recorded and never sent. Nothing a page
// does depends on its pictures, fonts or media loading, and a catalogue page
// requests dozens: sending them would spend the budget on nothing discovery
// uses.
func unfetched(r browser.Request) bool {
	switch r.ResourceType {
	case "Image", "Font", "Media":
		return true
	}
	return false
}

// skipped reports a request, on the target, to a route browsing never loads.
func (br *browserRelay) skipped(rawURL string) bool {
	if br.skip == nil {
		return false
	}
	u, err := url.Parse(rawURL)
	base, berr := url.Parse(br.target)
	if err != nil || berr != nil || !strings.EqualFold(u.Host, base.Host) || u.Scheme != base.Scheme {
		// Another origin is refused by scope, and logged there.
		return false
	}
	p := strings.TrimPrefix(u.Path, strings.TrimRight(base.Path, "/"))
	if p == "" {
		p = "/"
	}
	return br.skip(p)
}

func (br *browserRelay) relay(ctx context.Context, r browser.Request) (browser.Response, error) {
	ex := discovery.Exchange{Method: r.Method, URL: r.URL, ResourceType: r.ResourceType}
	defer func() { br.rec.Record(ex) }()

	if unfetched(r) {
		return browser.Response{}, errNotFetched
	}
	if br.skipped(r.URL) {
		return browser.Response{}, errSkipped
	}
	if cacheable(r) {
		br.mu.Lock()
		resp, ok := br.cache[r.URL]
		br.mu.Unlock()
		if ok {
			// The cached response is what the target answered, so a page
			// load served from it is judged — fallback or route — exactly as
			// the first one was.
			ex.Status, ex.Body = resp.Status, resp.Body
			for _, h := range resp.Header {
				if strings.EqualFold(h[0], "Content-Type") {
					ex.ContentType = h[1]
				}
			}
			return resp, nil
		}
	}
	route := r.Method + " " + r.URL
	if u, err := url.Parse(r.URL); err == nil {
		route = r.Method + " " + u.Scheme + "://" + u.Host + u.EscapedPath()
	}
	br.mu.Lock()
	n := br.repeats[route]
	if n < browserRepeats {
		br.repeats[route] = n + 1
	}
	br.mu.Unlock()
	if n >= browserRepeats {
		return browser.Response{}, errRepeated
	}
	if br.sent.Add(1) > br.limit {
		br.stopped.Store(true)
		return browser.Response{}, errBrowserBudget
	}

	header := map[string][]string{}
	for _, name := range browserForwardedHeaders {
		for k, v := range r.Header {
			if strings.EqualFold(k, name) && v != "" {
				header[name] = []string{v}
			}
		}
	}
	got, err := br.actor.relay(ctx, r.Method, r.URL, header)
	if err != nil {
		var (
			spent   *httpx.ErrBudgetExceeded
			refused *httpx.ErrRefused
			scope   *httpx.ErrOutOfScope
		)
		switch {
		case errors.As(err, &spent) || ctx.Err() != nil:
			br.stopped.Store(true)
		case errors.As(err, &refused) || errors.As(err, &scope):
			// Nothing reached the target, so nothing is spent: a page that
			// keeps asking for another host does not use up the budget its
			// own requests need.
			br.sent.Add(-1)
		}
		return browser.Response{}, err
	}
	resp := browser.Response{Status: got.Status, Body: got.Body}
	for k, vs := range got.Header {
		if browserDroppedResponseHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			resp.Header = append(resp.Header, [2]string{k, v})
		}
	}
	ex.Status, ex.ContentType, ex.Body = got.Status, got.Header.Get("Content-Type"), got.Body

	if cacheable(r) && got.Status == http.StatusOK {
		br.mu.Lock()
		if _, ok := br.cache[r.URL]; !ok && br.cacheBytes+len(got.Body) <= browserCacheBytes {
			br.cache[r.URL] = resp
			br.cacheBytes += len(got.Body)
		}
		br.mu.Unlock()
	}
	return resp, nil
}
