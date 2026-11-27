package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Request is one request a page made, paused before it left the browser.
// Its body is deliberately not carried: Sulayi's relay sends only reads.
type Request struct {
	Method string
	URL    string
	// Header is what the page would have sent. The relay decides what of it,
	// if anything, is forwarded.
	Header map[string]string
	// ResourceType is the browser's classification: Document, XHR, Fetch,
	// Script, Image and so on.
	ResourceType string
}

// Response is what the relay obtained, handed back to the page.
type Response struct {
	Status int
	Header [][2]string
	Body   []byte
}

// Relay performs a paused request on the page's behalf. An error means the
// request is failed in the page, exactly as if the network had refused it.
type Relay func(ctx context.Context, r Request) (Response, error)

// Limits on one page visit.
const (
	// maxConcurrentRelays bounds how many of a page's requests are relayed at
	// once, about what a browser itself opens to one origin.
	maxConcurrentRelays = 6
	// A page is settled once no more than idleRequests of its requests have
	// been in flight for quietPeriod: Puppeteer's networkidle2. Requiring none
	// would never settle a page that holds a long poll or a stream open, as
	// chat and live-update features do.
	quietPeriod  = 500 * time.Millisecond
	idleRequests = 2
	// maxRendered bounds the links and forms read from one rendered page.
	maxRendered = 500
	// closeTimeout bounds closing a tab before the browser is killed instead.
	closeTimeout = 10 * time.Second
)

// Page is one tab in its own browser context: cookies, storage and cache are
// not shared with any other Page.
type Page struct {
	b       *Browser
	ctxID   string
	session string
	relay   Relay
	events  <-chan event

	mu       sync.Mutex
	inflight int
	// busy is the last time more than idleRequests were in flight.
	busy time.Time
	// loaded holds the loaders whose document has fired its load event, and
	// loadSignal is closed and replaced whenever one does. Matching by loader
	// means a load event left over from a navigation that timed out cannot end
	// the wait of the next one.
	loaded     map[string]bool
	loadSignal chan struct{}
	crashed    bool

	sem       chan struct{}
	wg        sync.WaitGroup
	stop      context.CancelFunc
	run       context.Context
	done      chan struct{}
	closeOnce sync.Once
}

// NewPage opens a tab in a fresh browser context whose every request goes to
// relay.
func (b *Browser) NewPage(ctx context.Context, relay Relay) (*Page, error) {
	var bc struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := b.conn.call(ctx, "", "Target.createBrowserContext",
		map[string]any{"disposeOnDetach": true}, &bc); err != nil {
		return nil, fmt.Errorf("cannot create a browser context: %w", err)
	}
	if err := b.conn.call(ctx, "", "Browser.setDownloadBehavior",
		map[string]any{"behavior": "deny", "browserContextId": bc.BrowserContextID}, nil); err != nil {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = b.conn.call(dctx, "", "Target.disposeBrowserContext",
			map[string]any{"browserContextId": bc.BrowserContextID}, nil)
		cancel()
		return nil, fmt.Errorf("cannot deny downloads: %w", err)
	}
	var tgt struct {
		TargetID string `json:"targetId"`
	}
	dispose := func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.conn.call(dctx, "", "Target.disposeBrowserContext",
			map[string]any{"browserContextId": bc.BrowserContextID}, nil)
	}
	if err := b.conn.call(ctx, "", "Target.createTarget",
		map[string]any{"url": "about:blank", "browserContextId": bc.BrowserContextID}, &tgt); err != nil {
		dispose()
		return nil, fmt.Errorf("cannot open a tab: %w", err)
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := b.conn.call(ctx, "", "Target.attachToTarget",
		map[string]any{"targetId": tgt.TargetID, "flatten": true}, &att); err != nil {
		dispose()
		return nil, fmt.Errorf("cannot attach to the tab: %w", err)
	}
	run, stop := context.WithCancel(context.Background())
	p := &Page{
		b: b, ctxID: bc.BrowserContextID, session: att.SessionID, relay: relay,
		events: b.conn.subscribe(att.SessionID),
		loaded: map[string]bool{}, loadSignal: make(chan struct{}),
		sem: make(chan struct{}, maxConcurrentRelays),
		run: run, stop: stop, done: make(chan struct{}),
	}
	go p.loop()
	// Interception is enabled before anything is loaded, so no request the
	// page makes can precede it.
	if err := b.conn.call(ctx, p.session, "Fetch.enable",
		map[string]any{"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}}, nil); err != nil {
		p.Close()
		return nil, fmt.Errorf("cannot intercept the tab's requests: %w", err)
	}
	if err := b.conn.call(ctx, p.session, "Page.enable", struct{}{}, nil); err != nil {
		p.Close()
		return nil, fmt.Errorf("cannot observe the tab: %w", err)
	}
	if err := b.conn.call(ctx, p.session, "Page.setLifecycleEventsEnabled",
		map[string]any{"enabled": true}, nil); err != nil {
		p.Close()
		return nil, fmt.Errorf("cannot observe the tab's loading: %w", err)
	}
	return p, nil
}

func (p *Page) loop() {
	defer close(p.done)
	for ev := range p.events {
		switch ev.Method {
		case "Fetch.requestPaused":
			var rp struct {
				RequestID    string `json:"requestId"`
				ResourceType string `json:"resourceType"`
				Request      struct {
					URL     string            `json:"url"`
					Method  string            `json:"method"`
					Headers map[string]string `json:"headers"`
				} `json:"request"`
			}
			if err := json.Unmarshal(ev.Params, &rp); err != nil || rp.RequestID == "" {
				continue
			}
			p.begin()
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer p.end()
				p.handle(rp.RequestID, Request{
					Method: strings.ToUpper(rp.Request.Method), URL: rp.Request.URL,
					Header: rp.Request.Headers, ResourceType: rp.ResourceType,
				})
			}()
		case "Page.lifecycleEvent":
			var lc struct {
				LoaderID string `json:"loaderId"`
				Name     string `json:"name"`
			}
			if json.Unmarshal(ev.Params, &lc) != nil || lc.Name != "load" || lc.LoaderID == "" {
				continue
			}
			p.mu.Lock()
			if len(p.loaded) < 10000 {
				p.loaded[lc.LoaderID] = true
			}
			close(p.loadSignal)
			p.loadSignal = make(chan struct{})
			p.mu.Unlock()
		case "Page.javascriptDialogOpening":
			go func() {
				_ = p.b.conn.call(p.run, p.session, "Page.handleJavaScriptDialog",
					map[string]any{"accept": false}, nil)
			}()
		case "Inspector.targetCrashed":
			p.mu.Lock()
			p.crashed = true
			p.mu.Unlock()
		}
	}
}

func (p *Page) begin() {
	p.mu.Lock()
	p.inflight++
	if p.inflight > idleRequests {
		p.busy = time.Now()
	}
	p.mu.Unlock()
}

func (p *Page) end() {
	p.mu.Lock()
	if p.inflight > idleRequests {
		p.busy = time.Now()
	}
	p.inflight--
	p.mu.Unlock()
}

// handle relays one paused request and completes it in the page.
func (p *Page) handle(id string, r Request) {
	select {
	case p.sem <- struct{}{}:
	case <-p.run.Done():
		p.fail(id)
		return
	}
	resp, err := p.relay(p.run, r)
	<-p.sem
	if err != nil {
		p.fail(id)
		return
	}
	headers := make([]map[string]string, 0, len(resp.Header))
	for _, h := range resp.Header {
		headers = append(headers, map[string]string{"name": h[0], "value": h[1]})
	}
	status := resp.Status
	if status < 100 || status > 599 {
		p.fail(id)
		return
	}
	params := map[string]any{"requestId": id, "responseCode": status, "responseHeaders": headers}
	if len(resp.Body) > 0 {
		params["body"] = base64.StdEncoding.EncodeToString(resp.Body)
	}
	if err := p.b.conn.call(p.run, p.session, "Fetch.fulfillRequest", params, nil); err != nil {
		p.fail(id)
	}
}

func (p *Page) fail(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.b.conn.call(ctx, p.session, "Fetch.failRequest",
		map[string]any{"requestId": id, "errorReason": "BlockedByClient"}, nil)
}

// Rendered is what a page showed once it had loaded: the links and forms in
// its document, resolved to absolute URLs by the browser.
type Rendered struct {
	Links []string
	Forms []Form
}

// Form is one rendered form: where it submits and with which method.
type Form struct {
	Action string
	Method string
}

// ErrCrashed reports that the tab's renderer crashed.
var ErrCrashed = errors.New("the browser tab crashed")

// renderedScript reads the rendered document's links and forms. It runs in the
// page, so the page can make it return anything; the caller treats every value
// as untrusted and keeps only same-origin URLs.
var renderedScript = `(() => {
  const max = ` + strconv.Itoa(maxRendered) + `;
  const links = [], forms = [];
  for (const a of document.querySelectorAll('a[href], area[href]')) {
    if (links.length >= max) break;
    if (typeof a.href === 'string') links.push(a.href);
  }
  for (const f of document.querySelectorAll('form')) {
    if (forms.length >= max) break;
    forms.push({action: String(f.action || ''), method: String(f.getAttribute('method') || 'GET')});
  }
  return {links, forms};
})()`

// Visit loads rawURL and waits until the page has loaded and gone quiet, or
// timeout passes, then reads what rendered. A page that never goes quiet is
// read at the timeout: what it rendered by then is still evidence.
func (p *Page) Visit(ctx context.Context, rawURL string, timeout time.Duration) (Rendered, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	p.mu.Lock()
	p.busy = time.Now()
	p.mu.Unlock()

	var nav struct {
		LoaderID  string `json:"loaderId"`
		ErrorText string `json:"errorText"`
	}
	if err := p.b.conn.call(ctx, p.session, "Page.navigate", map[string]any{"url": rawURL}, &nav); err != nil {
		return Rendered{}, fmt.Errorf("navigation did not complete: %w", err)
	}
	if nav.ErrorText != "" {
		return Rendered{}, fmt.Errorf("navigation failed: %s", nav.ErrorText)
	}

	// A navigation within the same document — a client-side route such as
	// #/admin — has no loader and fires no load event; the page's router
	// handles it, and the wait below is for the requests that makes.
	for nav.LoaderID != "" && ctx.Err() == nil {
		p.mu.Lock()
		done, signal := p.loaded[nav.LoaderID], p.loadSignal
		p.mu.Unlock()
		if done {
			break
		}
		select {
		case <-signal:
		case <-ctx.Done():
		}
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for ctx.Err() == nil {
		p.mu.Lock()
		quiet := p.inflight <= idleRequests && time.Since(p.busy) >= quietPeriod
		crashed := p.crashed
		p.mu.Unlock()
		if crashed {
			return Rendered{}, ErrCrashed
		}
		if quiet {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
		}
	}

	// The read gets its own short deadline: the visit's may already be spent.
	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readCancel()
	var ev struct {
		Result struct {
			Value struct {
				Links []string `json:"links"`
				Forms []struct {
					Action string `json:"action"`
					Method string `json:"method"`
				} `json:"forms"`
			} `json:"value"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err := p.b.conn.call(readCtx, p.session, "Runtime.evaluate",
		map[string]any{"expression": renderedScript, "returnByValue": true}, &ev); err != nil {
		return Rendered{}, fmt.Errorf("cannot read the rendered page: %w", err)
	}
	var out Rendered
	for i, l := range ev.Result.Value.Links {
		if i >= maxRendered {
			break
		}
		out.Links = append(out.Links, l)
	}
	for i, f := range ev.Result.Value.Forms {
		if i >= maxRendered {
			break
		}
		out.Forms = append(out.Forms, Form{Action: f.Action, Method: f.Method})
	}
	return out, nil
}

// Close closes the tab and its browser context, failing anything still
// paused, and waits for every relay it started to return. If the browser has
// stopped reading its pipe, so that a reply to the page can never be written,
// the browser is killed rather than waited for. It is safe to call twice.
func (p *Page) Close() {
	p.closeOnce.Do(func() {
		p.stop()
		finished := make(chan struct{})
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = p.b.conn.call(ctx, "", "Target.disposeBrowserContext",
				map[string]any{"browserContextId": p.ctxID}, nil)
			p.b.conn.unsubscribe(p.session)
			<-p.done
			p.wg.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(closeTimeout):
			p.b.kill()
			<-finished
		}
	})
}
