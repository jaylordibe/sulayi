package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

// fakeSite stands in for a browser loading a single-page application: every
// unknown path loads the same index page, and each page "makes" the requests
// listed for it, which the fake relays straight into the recorder.
type fakeSite struct {
	origin   string
	rec      *Recorder
	index    string
	pages    map[string]fakePage
	visited  []string
	stopAt   int
	visitErr map[string]error
}

type fakePage struct {
	status   int
	body     string
	requests []Exchange
	links    []string
	forms    []RenderedForm
}

func (s *fakeSite) visit(_ context.Context, rawURL string) ([]string, []RenderedForm, bool, error) {
	s.visited = append(s.visited, rawURL)
	if s.stopAt > 0 && len(s.visited) > s.stopAt {
		return nil, nil, true, nil
	}
	key := strings.TrimPrefix(rawURL, s.origin)
	p, ok := s.pages[key]
	if !ok {
		p = fakePage{status: 200, body: s.index}
	}
	s.rec.Record(Exchange{Method: "GET", URL: rawURL, ResourceType: "Document", Status: p.status,
		ContentType: "text/html", Body: []byte(p.body)})
	for _, r := range p.requests {
		s.rec.Record(r)
	}
	if err := s.visitErr[key]; err != nil {
		return nil, nil, false, err
	}
	return p.links, p.forms, false, nil
}

func newFakeSite(t *testing.T, origin, actor string) *fakeSite {
	t.Helper()
	rec, err := NewRecorder(origin, actor)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSite{origin: origin, rec: rec, index: "<app-root></app-root>", pages: map[string]fakePage{}}
}

func opIDs(ops []model.Operation) map[string]model.Operation {
	out := map[string]model.Operation{}
	for _, o := range ops {
		out[o.ID] = o
	}
	return out
}

func TestBrowseKeepsWhatTheFrontEndRequestsAndNotTheFallback(t *testing.T) {
	const o = "http://app.test"
	s := newFakeSite(t, o, "anonymous")
	s.pages["/"] = fakePage{status: 200, body: "<app-root></app-root>",
		links: []string{o + "/#/search", o + "/#/about", "https://elsewhere.test/x", o + "/redirect?to=https://github.com"},
		requests: []Exchange{
			{Method: "GET", URL: o + "/rest/products/search?q=", ResourceType: "XHR", Status: 200},
			{Method: "GET", URL: o + "/main.js", ResourceType: "Script", Status: 200},
			{Method: "GET", URL: "https://fonts.elsewhere.test/f.woff2", ResourceType: "Font"},
			{Method: "POST", URL: o + "/api/BasketItems", ResourceType: "XHR"}, // refused: status 0
		}}
	s.pages["/#/search"] = fakePage{status: 200, body: "<app-root></app-root>",
		forms: []RenderedForm{{Action: o + "/search", Method: "get"}, {Action: o + "/x", Method: "dialog"}}}
	s.pages["/redirect?to=https://github.com"] = fakePage{status: 302}

	res := Browse(context.Background(), BrowseOptions{Target: o, Actor: "anonymous", Visit: s.visit, Recorder: s.rec})
	ops := opIDs(res.Operations)

	search, ok := ops["GET /rest/products/search"]
	if !ok {
		t.Fatalf("the data request is not an operation: %v", res.Operations)
	}
	if len(search.Parameters) != 1 || search.Parameters[0].Name != "q" || search.Parameters[0].In != "query" ||
		search.Parameters[0].Required {
		t.Errorf("parameters = %+v, want the optional query parameter q", search.Parameters)
	}
	if _, ok := ops["POST /api/BasketItems"]; !ok {
		t.Error("a request the relay refused to send is still a route the front end uses, with its method")
	}
	if _, ok := ops["GET /search"]; !ok {
		t.Error("a rendered GET form is a route")
	}
	if _, ok := ops["GET /"]; ok {
		t.Error("a page load identical to the fallback was counted as a route")
	}
	for id := range ops {
		if strings.Contains(id, "sulayi-browse-") || strings.Contains(id, "main.js") || strings.Contains(id, "DIALOG") {
			t.Errorf("unexpected operation %s", id)
		}
	}
	if r, ok := ops["GET /redirect"]; !ok || len(r.Parameters) != 1 || r.Parameters[0].Name != "to" {
		t.Errorf("a linked route that answered with a redirect is a route, with its parameter: %+v", r)
	}
	if !res.Fallback {
		t.Error("the fallback was not detected")
	}
	if res.OffOrigin < 2 {
		t.Errorf("off-origin = %d, want the link and the font", res.OffOrigin)
	}
	var hashRoute bool
	for _, v := range s.visited {
		hashRoute = hashRoute || strings.HasSuffix(v, "/#/about")
	}
	if !hashRoute {
		t.Errorf("client-side routes were not followed: %v", s.visited)
	}
}

func TestBrowseNeverLoadsASkippedPath(t *testing.T) {
	const o = "http://app.test"
	s := newFakeSite(t, o, "alice")
	s.pages["/"] = fakePage{status: 200, body: "home", links: []string{o + "/logout", o + "/account"}}
	res := Browse(context.Background(), BrowseOptions{Target: o, Actor: "alice", Visit: s.visit, Recorder: s.rec,
		Skip: func(p string) bool { return p == "/logout" }})
	for _, v := range s.visited {
		if strings.HasSuffix(v, "/logout") {
			t.Fatal("a skipped path was loaded")
		}
	}
	if res.Skipped != 1 {
		t.Errorf("skipped = %d", res.Skipped)
	}
}

func TestBrowseStopsAtItsLimitsAndSaysSo(t *testing.T) {
	const o = "http://app.test"
	s := newFakeSite(t, o, "anonymous")
	var links []string
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		links = append(links, o+p)
	}
	s.pages["/"] = fakePage{status: 200, body: "home", links: links}
	res := Browse(context.Background(), BrowseOptions{Target: o, Actor: "anonymous", Visit: s.visit,
		Recorder: s.rec, MaxPages: 2})
	if !res.Incomplete || res.Pages != 2 || len(res.Limitations) == 0 {
		t.Errorf("pages=%d incomplete=%v limitations=%v", res.Pages, res.Incomplete, res.Limitations)
	}

	s2 := newFakeSite(t, o, "anonymous")
	s2.pages["/"] = fakePage{status: 200, body: "home", links: links}
	s2.stopAt = 2
	res = Browse(context.Background(), BrowseOptions{Target: o, Actor: "anonymous", Visit: s2.visit, Recorder: s2.rec})
	if !res.Incomplete || !strings.Contains(strings.Join(res.Limitations, " "), "budget") {
		t.Errorf("a spent budget was not reported: %+v", res)
	}
}

func TestObservedQueryNamesKeepNoValues(t *testing.T) {
	got := queryNames("q=apple&token=SECRET&page=2&eyJhbGciOiJIUzI1NiJ9abcdefghijklmnopqrstuvwxyz0123=1&bad%20name=1" +
		"&Q7xK2pL9aZ&dGVzdA==")
	want := "page,q,token"
	if strings.Join(got, ",") != want {
		t.Errorf("names = %v, want %s", got, want)
	}
}

func TestARecordingNowCarriesQueryNames(t *testing.T) {
	har := []byte(`{"log":{"entries":[
	 {"request":{"method":"GET","url":"http://app.test/rest/products/search?q=SECRET-VALUE"}},
	 {"request":{"method":"GET","url":"http://app.test/rest/products/search?sort=asc"}}]}}`)
	res, err := ParseHAR(har, "http://app.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Operations) != 1 {
		t.Fatalf("operations = %+v", res.Operations)
	}
	var names []string
	for _, p := range res.Operations[0].Parameters {
		names = append(names, p.In+":"+p.Name)
	}
	if strings.Join(names, ",") != "query:q,query:sort" {
		t.Errorf("parameters = %v", names)
	}
	if strings.Contains(strings.Join(names, ","), "SECRET") {
		t.Error("a query value was kept")
	}
}

func TestMergeAddsObservedQueryNamesToAKnownRoute(t *testing.T) {
	existing := []model.Operation{{ID: "GET /items", Method: "GET", PathTemplate: "/items",
		Parameters: []model.Parameter{{Name: "q", In: "query", Required: true}}}}
	found := []model.Operation{{ID: "GET /items", Method: "GET", PathTemplate: "/items",
		Parameters: []model.Parameter{{Name: "q", In: "query"}, {Name: "page", In: "query"}}}}
	out, added, corroborated := MergeOperations(existing, found)
	if added != 0 || corroborated != 1 {
		t.Fatalf("added=%d corroborated=%d", added, corroborated)
	}
	if len(out[0].Parameters) != 2 || !out[0].Parameters[0].Required {
		t.Errorf("parameters = %+v; a declared parameter must keep its declaration", out[0].Parameters)
	}
}

// A client-side route is judged by Skip as a path: #/logout is a sign-out.
func TestBrowseNeverLoadsASkippedClientSideRoute(t *testing.T) {
	const o = "http://app.test"
	s := newFakeSite(t, o, "alice")
	s.pages["/"] = fakePage{status: 200, body: "home", links: []string{o + "/#/logout", o + "/#!/logout", o + "/#/about"}}
	var asked []string
	res := Browse(context.Background(), BrowseOptions{Target: o, Actor: "alice", Visit: s.visit, Recorder: s.rec,
		Skip: func(p string) bool { asked = append(asked, p); return p == "/logout" }})
	for _, v := range s.visited {
		if strings.Contains(v, "logout") {
			t.Fatalf("a skipped client-side route was loaded: %v", s.visited)
		}
	}
	if res.Skipped != 2 {
		t.Errorf("skipped = %d, want both spellings of #/logout (asked %v)", res.Skipped, asked)
	}
}

// A browse in which no page loaded is not a clean result.
func TestBrowseThatLoadedNothingSaysSo(t *testing.T) {
	const o = "http://app.test"
	s := newFakeSite(t, o, "anonymous")
	s.visitErr = map[string]error{"/": errors.New("the browser tab crashed")}
	settled := false
	res := Browse(context.Background(), BrowseOptions{Target: o, Actor: "anonymous", Visit: s.visit, Recorder: s.rec,
		Settle: func() { settled = true }})
	if !res.Incomplete || res.Loaded != 0 || res.Failed != 1 || len(res.Limitations) == 0 {
		t.Errorf("result = %+v, want incomplete with a limitation", res)
	}
	if !settled {
		t.Error("Settle was not called before the result was built")
	}
}
