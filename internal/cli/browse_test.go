package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jaylordibe/sulayi/internal/browser"
	"github.com/jaylordibe/sulayi/internal/discovery"
	"github.com/jaylordibe/sulayi/internal/httpx"
)

func requireBrowser(t *testing.T) {
	t.Helper()
	if _, err := browser.Find(os.Getenv("SULAYI_BROWSER")); err != nil {
		if os.Getenv("SULAYI_REQUIRE_BROWSER") == "1" {
			t.Fatalf("SULAYI_REQUIRE_BROWSER=1 and no browser was found: %v", err)
		}
		t.Skipf("no browser: %v", err)
	}
}

// spa is a single-page application with no specification and nothing a
// crawler can see: its API exists only in what its script requests.
type spa struct {
	mu   sync.Mutex
	seen []string
}

func (a *spa) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.seen = append(a.seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		a.mu.Unlock()
		switch {
		case r.URL.Path == "/api/products":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"id":1}]`)
		case r.URL.Path == "/api/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<!doctype html><div id=app></div><script>
fetch('/api/products?q=apple');
fetch('/api/orders', {method: 'POST', body: '{}'});
const a = document.createElement('a'); a.href = '#/admin'; document.getElementById('app').appendChild(a);
</script>`)
		}
	})
}

func (a *spa) count(prefix string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, s := range a.seen {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func TestBrowserFindsASinglePageApplicationsAPIAndNeverWrites(t *testing.T) {
	requireBrowser(t)
	app := &spa{}
	srv := httptest.NewServer(app.handler())
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	// A dedicated, short temporary directory, so the check below sees only
	// this run's browser profile. Short, because Chrome on Linux puts a Unix
	// socket under it, and a socket path may not exceed about 100 bytes.
	tmp, err := os.MkdirTemp("", "sb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	if runtime.GOOS != "windows" {
		t.Setenv("TMPDIR", tmp)
	}
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + srv.URL + "\n  disposable: true\n" +
		"assessment:\n  profile: aggressive\n" +
		"discovery:\n  probeWellKnownPaths: false\n  surface: {enabled: false}\n  crawl: {enabled: false}\n" +
		"  browser: {enabled: true, executable: \"" + filepath.ToSlash(mustFind(t)) + "\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// aggressive is deliberate: it is the profile that would otherwise permit a
	// state-changing request, and the browser must still never send one.
	code, out, errOut := run(t, "attack", "--yes")
	if code == ExitUsage || code == ExitInternal {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if n := app.count("POST "); n != 0 {
		t.Fatalf("the target received %d POST(s); the browser must never write", n)
	}
	var injected bool
	app.mu.Lock()
	for _, s := range app.seen {
		injected = injected || (strings.HasPrefix(s, "GET /api/products?") && strings.Contains(s, "q=") &&
			!strings.HasSuffix(s, "q=apple"))
	}
	app.mu.Unlock()
	if !injected {
		t.Errorf("the observed query parameter q was not injected into: %v\n%s", app.seen, errOut)
	}

	reports, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "report.json"))
	if len(reports) != 1 {
		t.Fatalf("reports = %d\n%s", len(reports), errOut)
	}
	raw, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Surface struct {
			Sources struct {
				Browser *struct {
					Problem string `json:"problem"`
					Actors  []struct {
						Actor      string `json:"actor"`
						Operations int    `json:"operations"`
					} `json:"actors"`
				} `json:"browser"`
			} `json:"sources"`
		} `json:"surface"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	br := doc.Surface.Sources.Browser
	if br == nil || br.Problem != "" || len(br.Actors) != 1 || br.Actors[0].Operations < 2 {
		t.Fatalf("browser account = %+v\n%s", br, errOut)
	}

	logs, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "requests.jsonl"))
	if len(logs) != 1 {
		t.Fatal("no request log")
	}
	log, _ := os.ReadFile(logs[0])
	if !strings.Contains(string(log), `"POST"`) || !strings.Contains(string(log), "the browser only reads") {
		t.Errorf("the refused POST is not in the request log:\n%s", log)
	}
	if runtime.GOOS != "windows" {
		left, _ := filepath.Glob(filepath.Join(tmp, "sulayi-browser-*"))
		if len(left) != 0 {
			t.Errorf("browser profile(s) left behind: %v", left)
		}
	}
}

func TestAnEnabledBrowserThatIsMissingIsAUsageError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://127.0.0.1:1\n" +
		"discovery:\n  browser: {enabled: true, executable: \"" + filepath.ToSlash(filepath.Join(dir, "no-such-chrome")) + "\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "attack")
	if code != ExitUsage || !strings.Contains(errOut, "discovery.browser.executable") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if logs, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "requests.jsonl")); len(logs) > 0 {
		if b, _ := os.ReadFile(logs[0]); len(b) > 0 {
			t.Errorf("requests were sent before the missing browser was reported:\n%s", b)
		}
	}
}

func mustFind(t *testing.T) string {
	t.Helper()
	exe, err := browser.Find(os.Getenv("SULAYI_BROWSER"))
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// A page contributes no credential and no identity of its own: whatever it
// sends, only the allowlisted headers reach the actor's relay, which adds the
// actor's own credential.
func TestAPageCannotForwardItsOwnCredentials(t *testing.T) {
	var got map[string][]string
	actor := browserActor{name: "alice", relay: func(_ context.Context, _, _ string, h map[string][]string) (httpx.RelayResponse, error) {
		got = h
		return httpx.RelayResponse{Status: 200, Header: http.Header{"Content-Length": {"2"}, "X-Ok": {"1"}}}, nil
	}}
	rec, err := discovery.NewRecorder("http://app.test", "alice")
	if err != nil {
		t.Fatal(err)
	}
	r := newBrowserRelay(actor, rec, 10)
	resp, err := r.relay(context.Background(), browser.Request{Method: "GET", URL: "http://app.test/api/me",
		ResourceType: "XHR", Header: map[string]string{
			"Authorization": "Bearer PAGE-TOKEN", "cookie": "sid=PAGE", "User-Agent": "HeadlessChrome",
			"Accept": "application/json", "x-requested-with": "XMLHttpRequest", "X-Api-Key": "PAGE-KEY",
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["Accept"][0] != "application/json" || got["X-Requested-With"][0] != "XMLHttpRequest" {
		t.Errorf("forwarded headers = %v, want only Accept and X-Requested-With", got)
	}
	for _, h := range resp.Header {
		if strings.EqualFold(h[0], "Content-Length") {
			t.Error("a connection header was relayed to the page")
		}
	}
}

func TestTheBrowserBudgetStopsBrowsingAndRefusalsCostNothing(t *testing.T) {
	sent := 0
	actor := browserActor{name: "anonymous", relay: func(_ context.Context, _, u string, _ map[string][]string) (httpx.RelayResponse, error) {
		if strings.Contains(u, "elsewhere") {
			return httpx.RelayResponse{}, &httpx.ErrOutOfScope{Target: u, Reason: "test"}
		}
		sent++
		return httpx.RelayResponse{Status: 200}, nil
	}}
	rec, _ := discovery.NewRecorder("http://app.test", "anonymous")
	r := newBrowserRelay(actor, rec, 2)
	for i := 0; i < 5; i++ {
		_, _ = r.relay(context.Background(), browser.Request{Method: "GET",
			URL: "http://elsewhere.test/x" + string(rune('a'+i))})
	}
	for i := 0; i < 3; i++ {
		_, _ = r.relay(context.Background(), browser.Request{Method: "GET",
			URL: "http://app.test/api/x" + string(rune('a'+i))})
	}
	if sent != 2 || !r.stopped.Load() {
		t.Errorf("sent = %d, stopped = %v; want the budget of 2 spent only on requests that were sent", sent, r.stopped.Load())
	}
}

// A page that polls, or reloads the same data on every page, does not spend
// the budget: an exact repeat is served from the first response, and one route
// is sent at most browserRepeats times whatever its query.
func TestRepeatedAndPollingRequestsAreNotResent(t *testing.T) {
	sent := map[string]int{}
	actor := browserActor{name: "anonymous", relay: func(_ context.Context, _, u string, _ map[string][]string) (httpx.RelayResponse, error) {
		sent[u]++
		return httpx.RelayResponse{Status: 200, Body: []byte("{}")}, nil
	}}
	rec, _ := discovery.NewRecorder("http://app.test", "anonymous")
	r := newBrowserRelay(actor, rec, 100)
	for i := 0; i < 5; i++ {
		if _, err := r.relay(context.Background(), browser.Request{Method: "GET", URL: "http://app.test/api/config", ResourceType: "XHR"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		_, _ = r.relay(context.Background(), browser.Request{Method: "GET",
			URL: "http://app.test/socket.io/?t=" + string(rune('a'+i)), ResourceType: "XHR"})
	}
	if sent["http://app.test/api/config"] != 1 {
		t.Errorf("an exact repeat was sent %d times", sent["http://app.test/api/config"])
	}
	var polls int
	for u, n := range sent {
		if strings.Contains(u, "socket.io") {
			polls += n
		}
	}
	if polls != browserRepeats {
		t.Errorf("a polled route was sent %d times, want %d", polls, browserRepeats)
	}
}

// A page's own request to a route browsing never loads is refused before it
// reaches the actor's relay: a page cannot sign its identity out.
func TestAPageCannotSignItsIdentityOut(t *testing.T) {
	var sent []string
	actor := browserActor{name: "alice", relay: func(_ context.Context, _, u string, _ map[string][]string) (httpx.RelayResponse, error) {
		sent = append(sent, u)
		return httpx.RelayResponse{Status: 200}, nil
	}}
	rec, _ := discovery.NewRecorder("http://app.test/app", "alice")
	r := newBrowserRelay(actor, rec, 10)
	r.target = "http://app.test/app"
	r.skip = func(p string) bool { return p == "/api/logout" }
	_, err := r.relay(context.Background(), browser.Request{Method: "GET", URL: "http://app.test/app/api/logout", ResourceType: "XHR"})
	if !errors.Is(err, errSkipped) || len(sent) != 0 {
		t.Fatalf("err = %v, sent = %v; the sign-out must never be sent", err, sent)
	}
	if _, err := r.relay(context.Background(), browser.Request{Method: "GET", URL: "http://app.test/app/api/me", ResourceType: "XHR"}); err != nil || len(sent) != 1 {
		t.Fatalf("an ordinary request was not relayed: %v %v", err, sent)
	}
}

// A page load served from the cache is judged as the first one was: the
// fallback stays the fallback.
func TestACachedPageLoadKeepsItsFingerprint(t *testing.T) {
	actor := browserActor{name: "anonymous", relay: func(_ context.Context, _, _ string, _ map[string][]string) (httpx.RelayResponse, error) {
		return httpx.RelayResponse{Status: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: []byte("<app-root>")}, nil
	}}
	rec, _ := discovery.NewRecorder("http://app.test", "anonymous")
	r := newBrowserRelay(actor, rec, 10)
	for _, u := range []string{"http://app.test/sulayi-browse-x", "http://app.test/", "http://app.test/"} {
		if _, err := r.relay(context.Background(), browser.Request{Method: "GET", URL: u, ResourceType: "Document"}); err != nil {
			t.Fatal(err)
		}
	}
	res := discovery.Browse(context.Background(), discovery.BrowseOptions{Target: "http://app.test", Actor: "anonymous",
		Recorder: rec, MaxPages: 1, Visit: func(ctx context.Context, u string) ([]string, []discovery.RenderedForm, bool, error) {
			_, err := r.relay(ctx, browser.Request{Method: "GET", URL: u, ResourceType: "Document"})
			return nil, nil, false, err
		}})
	for _, op := range res.Operations {
		if op.ID == "GET /" {
			t.Fatal("a cached load of the fallback page was counted as a route")
		}
	}
}
