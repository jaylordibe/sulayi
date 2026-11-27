package browser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chrome returns the browser to test with. Without one the tests skip — except
// where SULAYI_REQUIRE_BROWSER=1, as in CI, where a missing browser is a
// failure: these tests must never pass by not running.
func chrome(t *testing.T) string {
	t.Helper()
	exe, err := Find(os.Getenv("SULAYI_BROWSER"))
	if err != nil {
		if os.Getenv("SULAYI_REQUIRE_BROWSER") == "1" {
			t.Fatalf("SULAYI_REQUIRE_BROWSER=1 and no browser was found: %v", err)
		}
		t.Skipf("no browser: %v", err)
	}
	return exe
}

// canary is a listener that must never be contacted. Every connection to it is
// a request that escaped Sulayi's relay.
type canary struct {
	ln    net.Listener
	conns atomic.Int64
}

func newCanary(t *testing.T) *canary {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &canary{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.conns.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *canary) addr() string { return c.ln.Addr().String() }

// relayTo relays only requests to target's origin, with a plain client, and
// fails everything else — standing in for Sulayi's scope-enforcing client.
type relayLog struct {
	mu   sync.Mutex
	seen []Request
}

func (l *relayLog) relayTo(target string) Relay {
	return func(ctx context.Context, r Request) (Response, error) {
		l.mu.Lock()
		l.seen = append(l.seen, r)
		l.mu.Unlock()
		if !strings.HasPrefix(r.URL, target+"/") || r.Method != http.MethodGet {
			return Response{}, fmt.Errorf("refused")
		}
		req, _ := http.NewRequestWithContext(ctx, r.Method, r.URL, nil)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return Response{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		out := Response{Status: resp.StatusCode, Body: body}
		for k, vs := range resp.Header {
			for _, v := range vs {
				out.Header = append(out.Header, [2]string{k, v})
			}
		}
		return out, nil
	}
}

func (l *relayLog) has(method, substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.seen {
		if r.Method == method && strings.Contains(r.URL, substr) {
			return true
		}
	}
	return false
}

// hostilePage tries every route out of the browser that Sulayi's relay does
// not see, each pointed at the canary: by IP literal and by host name, by
// fetch, image, script, WebSocket, EventSource, beacon, iframe, pop-up,
// service worker and a final top-level navigation.
func hostilePage(canary string) string {
	ws := strings.Replace(canary, "127.0.0.1", "localhost", 1)
	return `<!doctype html><html><body>
<a href="/linked">linked</a>
<script>
const c = 'http://` + canary + `';
const named = 'http://canary.invalid:` + strings.Split(canary, ":")[1] + `';
fetch('/api/items?q=1&page=2');
fetch('/go-elsewhere').catch(() => {});
fetch('/api/items', {method: 'POST', body: '{"a":1}'}).catch(() => {});
fetch(c + '/fetch').catch(() => {});
fetch(named + '/fetch').catch(() => {});
fetch('http://` + ws + `/fetch-localhost').catch(() => {});
new Image().src = c + '/img';
const s = document.createElement('script'); s.src = c + '/script.js'; document.body.appendChild(s);
try { new WebSocket('ws://` + canary + `/ws'); } catch (e) {}
try { new WebSocket('ws://` + ws + `/ws'); } catch (e) {}
try { new EventSource(c + '/sse'); } catch (e) {}
try { navigator.sendBeacon(c + '/beacon', 'x'); } catch (e) {}
const f = document.createElement('iframe'); f.src = c + '/frame'; document.body.appendChild(f);
try { window.open(c + '/popup'); } catch (e) {}
if (navigator.serviceWorker) navigator.serviceWorker.register('/sw.js').catch(() => {});
try { const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:` + canary + `'}]});
  pc.createDataChannel('x'); pc.createOffer().then(o => pc.setLocalDescription(o)); } catch (e) {}
setTimeout(() => { location.href = c + '/navigate'; }, 2500);
</script></body></html>`
}

func TestThePageHasNoNetworkOutsideTheRelay(t *testing.T) {
	exe := chrome(t)
	can := newCanary(t)

	// Sanity: the canary counts what reaches it.
	if conn, err := net.Dial("tcp", can.addr()); err == nil {
		_ = conn.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for can.conns.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if can.conns.Load() != 1 {
		t.Fatalf("the canary did not count a direct connection")
	}
	can.conns.Store(0)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, hostilePage(can.addr()))
	})
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = io.WriteString(w, "self.addEventListener('install', () => fetch('http://"+can.addr()+"/sw'));")
	})
	// A same-origin redirect to the canary: the next hop must go through the
	// relay too, never straight from the browser.
	mux.HandleFunc("/go-elsewhere", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+can.addr()+"/redirected", http.StatusFound)
	})
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "[]")
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b, err := Launch(ctx, exe)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() { _ = b.Close() }()

	var log relayLog
	page, err := b.NewPage(ctx, log.relayTo(target.URL))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := page.Visit(ctx, target.URL+"/", 10*time.Second)
	if err != nil {
		t.Fatalf("visit: %v", err)
	}
	// Give anything delayed — the navigation, the service worker — time to try.
	time.Sleep(4 * time.Second)
	page.Close()

	if n := can.conns.Load(); n != 0 {
		t.Fatalf("%d connection(s) reached the canary outside the relay", n)
	}
	if !log.has("GET", can.addr()+"/redirected") {
		t.Error("the redirect's next hop was not seen by the relay")
	}
	if !log.has("GET", can.addr()+"/navigate") {
		t.Error("the top-level navigation to the canary was not seen by the relay")
	}
	if !log.has("GET", "/api/items?q=1&page=2") {
		t.Errorf("the page's data request was not relayed: %+v", log.seen)
	}
	if !log.has("POST", "/api/items") {
		t.Errorf("the page's POST was not seen by the relay")
	}
	if !log.has("GET", can.addr()+"/fetch") {
		t.Errorf("the off-origin fetch did not pass through the relay, where scope refuses it")
	}
	var linked bool
	for _, l := range rendered.Links {
		linked = linked || strings.HasSuffix(l, "/linked")
	}
	if !linked {
		t.Errorf("rendered links = %v, want /linked", rendered.Links)
	}
}

func TestCloseLeavesNoProcessOrProfile(t *testing.T) {
	exe := chrome(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := Launch(ctx, exe)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	profile := b.Profile()
	if _, err := os.Stat(profile); err != nil {
		t.Fatalf("profile missing while running: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Errorf("profile %s still exists after Close", profile)
	}
	select {
	case <-b.exited:
	default:
		t.Error("the browser process is still running after Close")
	}
}

func TestCancellingAVisitStopsIt(t *testing.T) {
	exe := chrome(t)
	// A page whose data request never answers: the visit must still end.
	hang := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-hang
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<script>fetch('/slow')</script>`)
	}))
	defer target.Close()
	defer close(hang) // before Close, which waits for the hung handler

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := Launch(ctx, exe)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() { _ = b.Close() }()
	var log relayLog
	page, err := b.NewPage(ctx, log.relayTo(target.URL))
	if err != nil {
		t.Fatal(err)
	}
	visitCtx, visitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer visitCancel()
	start := time.Now()
	_, _ = page.Visit(visitCtx, target.URL+"/", 10*time.Second)
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("a cancelled visit took %s", d)
	}
	done := make(chan struct{})
	go func() { page.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("closing a page with a hung relay did not return")
	}
}
