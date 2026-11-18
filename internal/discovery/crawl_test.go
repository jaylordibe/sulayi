package discovery

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

// site is an in-memory target: path -> page. It records every URL fetched, so
// a test can assert what was never requested.
type site struct {
	mu      sync.Mutex
	pages   map[string]Page
	fetched []string
	// fallback answers unknown paths like a single-page application.
	fallback *Page
	limit    int
}

func html(body string) Page {
	return Page{Status: 200, ContentType: "text/html; charset=utf-8", Body: []byte(body)}
}

func (s *site) fetch(_ context.Context, rawURL string) (Page, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limit > 0 && len(s.fetched) >= s.limit {
		return Page{}, true, nil
	}
	s.fetched = append(s.fetched, rawURL)
	p := strings.TrimPrefix(rawURL, "http://app.test")
	if pg, ok := s.pages[p]; ok {
		return pg, false, nil
	}
	if s.fallback != nil {
		return *s.fallback, false, nil
	}
	return Page{Status: 404}, false, nil
}

func (s *site) wasFetched(p string) bool {
	for _, f := range s.fetched {
		if strings.TrimPrefix(f, "http://app.test") == p {
			return true
		}
	}
	return false
}

func ids(ops []model.Operation) string {
	var out []string
	for _, o := range ops {
		out = append(out, o.ID)
	}
	return strings.Join(out, ",")
}

func crawlOpts(s *site) CrawlOptions {
	return CrawlOptions{
		Target: "http://app.test", Actor: "anonymous", Fetch: s.fetch, MaxPages: 50, MaxDepth: 3,
		Skip: func(p string) bool { return model.LooksLikeAuthRoute(p) },
	}
}

// The crawler finds routes by links and records forms by their own method. It
// fetches GET only, never submits a form, never leaves the origin and never
// requests a sign-out route.
func TestCrawlStaysOnOriginAndNeverSubmitsOrSignsOut(t *testing.T) {
	s := &site{pages: map[string]Page{
		"/": html(`<a href="/orders">Orders</a> <a href="https://evil.test/x">x</a>
		  <a href="//app.test.evil.test/y">y</a> <a href="/logout">Sign out</a>
		  <a href="mailto:a@b.test">mail</a> <a href="#top">top</a>
		  <form action="/orders/new" method="post"><input></form>
		  <form action="/search"></form>`),
		"/orders":   html(`<a href="/orders/1">One</a> <a href="../profile">Profile</a>`),
		"/orders/1": {Status: 403, ContentType: "application/json"},
		"/profile":  html(`profile`),
	}}
	res := Crawl(context.Background(), crawlOpts(s))

	if got := ids(res.Operations); !sameSet(got, "GET /orders,GET /orders/1,GET /profile,POST /orders/new,GET /search") {
		t.Errorf("operations = %s", got)
	}
	for _, never := range []string{"/logout", "/orders/new", "/search"} {
		if s.wasFetched(never) {
			t.Errorf("%s was requested", never)
		}
	}
	for _, f := range s.fetched {
		if !strings.HasPrefix(f, "http://app.test/") {
			t.Errorf("an off-origin URL was requested: %s", f)
		}
	}
	if res.OffOrigin < 2 || res.Skipped < 1 || res.Forms != 2 {
		t.Errorf("accounting = %+v", res)
	}
	for _, op := range res.Operations {
		if op.Security != nil || len(op.Sources) != 1 || op.Sources[0].Kind != model.SourceCrawl {
			t.Errorf("%s: security %v, sources %+v", op.ID, op.Security, op.Sources)
		}
	}
}

func sameSet(a, b string) bool {
	as, bs := strings.Split(a, ","), strings.Split(b, ",")
	if len(as) != len(bs) {
		return false
	}
	m := map[string]int{}
	for _, x := range as {
		m[x]++
	}
	for _, x := range bs {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// A single-page application answers every path with the same shell. None of
// those answers is a route, however many links point at them.
func TestCrawlIgnoresTheSPAFallback(t *testing.T) {
	shell := html(`<div id="app"></div><a href="/dashboard">Dashboard</a><a href="/settings">Settings</a>`)
	s := &site{pages: map[string]Page{"/": shell}, fallback: &shell}
	res := Crawl(context.Background(), crawlOpts(s))
	if !res.Fallback {
		t.Error("the fallback was not detected")
	}
	if len(res.Operations) != 0 {
		t.Errorf("fallback responses became operations: %s", ids(res.Operations))
	}
}

// Same-origin redirects are followed as links; off-origin ones are recorded.
func TestCrawlFollowsOnlySameOriginRedirects(t *testing.T) {
	s := &site{pages: map[string]Page{
		"/":       html(`<a href="/go">go</a><a href="/away">away</a>`),
		"/go":     {Status: 302, Location: "/landed"},
		"/away":   {Status: 302, Location: "https://evil.test/"},
		"/landed": html(`landed`),
	}}
	res := Crawl(context.Background(), crawlOpts(s))
	if !s.wasFetched("/landed") {
		t.Error("a same-origin redirect was not followed")
	}
	for _, f := range s.fetched {
		if strings.Contains(f, "evil.test") {
			t.Errorf("an off-origin redirect was followed: %s", f)
		}
	}
	if !strings.Contains(ids(res.Operations), "GET /landed") {
		t.Errorf("operations = %s", ids(res.Operations))
	}
}

// Page and depth limits stop the crawl, and the result says so.
func TestCrawlLimitsAreReported(t *testing.T) {
	pages := map[string]Page{}
	var links strings.Builder
	for i := 0; i < 30; i++ {
		links.WriteString(`<a href="/p` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `">x</a>`)
	}
	pages["/"] = html(links.String())
	for i := 0; i < 30; i++ {
		pages["/p"+string(rune('a'+i%26))+string(rune('a'+i/26))] = html(`<a href="/deeper">d</a>`)
	}
	s := &site{pages: pages}
	opts := crawlOpts(s)
	opts.MaxPages = 10
	res := Crawl(context.Background(), opts)
	if !res.Incomplete || res.Pages != 10 || !strings.Contains(strings.Join(res.Limitations, " "), "10-page limit") {
		t.Errorf("page limit: incomplete=%v pages=%d limitations=%v", res.Incomplete, res.Pages, res.Limitations)
	}

	s2 := &site{pages: map[string]Page{
		"/":  html(`<a href="/a">a</a>`),
		"/a": html(`<a href="/b">b</a>`),
		"/b": html(`<a href="/c">c</a>`),
		"/c": html(`c`),
	}}
	opts2 := crawlOpts(s2)
	opts2.MaxDepth = 2
	Crawl(context.Background(), opts2)
	if s2.wasFetched("/c") {
		t.Error("the crawl went deeper than its depth limit")
	}
}

// A spent budget stops the crawl at once and marks it incomplete.
func TestCrawlStopsWhenTheBudgetIsSpent(t *testing.T) {
	s := &site{pages: map[string]Page{"/": html(`<a href="/a">a</a><a href="/b">b</a>`), "/a": html(``)}, limit: 2}
	res := Crawl(context.Background(), crawlOpts(s))
	if !res.Incomplete || !strings.Contains(strings.Join(res.Limitations, " "), "budget") {
		t.Errorf("incomplete=%v limitations=%v", res.Incomplete, res.Limitations)
	}
	if len(s.fetched) > 2 {
		t.Errorf("fetched %d after the budget was spent", len(s.fetched))
	}
}

// A base path confines the crawl to the application's subtree.
func TestCrawlStaysUnderTheBasePath(t *testing.T) {
	s := &site{pages: map[string]Page{
		"/app/":       html(`<a href="/app/orders">o</a><a href="/other">x</a>`),
		"/app/orders": html(`o`),
	}}
	opts := crawlOpts(s)
	opts.Target = "http://app.test/app"
	res := Crawl(context.Background(), opts)
	if s.wasFetched("/other") {
		t.Error("a path outside the base path was requested")
	}
	if len(res.Operations) != 1 || res.Operations[0].AbsolutePath() != "/app/orders" {
		t.Errorf("operations = %+v", res.Operations)
	}
}
