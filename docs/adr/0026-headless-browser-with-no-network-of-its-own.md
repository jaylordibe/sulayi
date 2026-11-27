# ADR-0026: A headless browser finds a single-page application's API, and has no network of its own

- **Status:** Accepted
- **Date:** 2026-11-27
- **Supersedes in part:** [ADR-0021](0021-surface-without-a-specification.md) (its rejection of a
  headless browser, and its rule that a recording's query strings are dropped entirely)
- **Relates to:** [ADR-0019](0019-safety-enforced-at-the-http-client.md),
  [ADR-0025](0025-mvp-measurement-method.md)

## Context

The MVP measurement ([entry 2](../evaluation/mvp-measurement.md)) confirmed every assessed
defect crAPI's specification exposed and one of six on Juice Shop. Four of the five Juice Shop
misses were the surface, not the checks: a browser recording reduced to methods and paths gave
the injection checks no parameter to inject into, and routes the front end requests or links to
only once it has rendered were not in the recording at all. Most applications Sulayi exists for
are single-page applications without a specification, and asking every operator to record one
by hand is the weakest part of the product.

ADR-0021 rejected a headless browser because it is a large dependency and a runtime that
executes target code. Both remain true, and the second is the same problem that keeps Nuclei and
ZAP blocked (ADR-0019): a tool that opens its own connections is outside every control Sulayi
has. A browser is only acceptable if that is not the case.

## Decision

**Sulayi drives a locally installed Chrome or Chromium, and the browser has no network of its
own.**

- Every request a page makes — documents, scripts, data requests, images, redirects followed —
  is paused through the DevTools Fetch domain and sent, or refused, by Sulayi's own HTTP client
  through a new `Relay` path. Scope, origin binding, the safety guard, the budget, pacing,
  redirect handling and `requests.jsonl` apply exactly as to any other request.
- `Relay` refuses every state-changing request **in every profile**, `aggressive` included. The
  browser is discovery, and discovery never changes the target. What a page tried to send is
  still recorded as an observed operation with its real method; it is planned and gated later
  like any other.
- Whatever interception does not cover — WebSockets, service workers, pop-ups, prefetch, WebRTC,
  the browser's own background traffic — fails closed: no host name or address resolves, every
  connection is sent to a proxy the same rule makes unreachable, QUIC is off and WebRTC may not
  use UDP outside the proxy. The proxy's address is a listener Sulayi owns that refuses
  everything. A test points each of those routes at a canary listener and requires that it
  receives nothing; a control run without the flags showed the same page reaching it.
- A page's own credentials are never forwarded. Each actor's requests carry exactly that actor's
  credential, added by Sulayi; a page contributes only `Accept`, `Accept-Language` and
  `X-Requested-With`. Responses are relayed raw to the page and never stored as evidence.

**The protocol runs over `--remote-debugging-pipe`, implemented with the standard library.**
No debugging port is opened, so nothing else on the machine can drive the browser, and no
dependency is added: the half-dozen protocol methods Sulayi uses do not justify a generated
protocol tree and a WebSocket client (chromedp), or a library that downloads browsers by default
(rod). On Windows the pipe handles are inherited explicitly and named with
`--remote-debugging-io-pipes`.

**Sulayi never downloads a browser.** It runs `discovery.browser.executable` or the first
standard Chrome or Chromium installation; `sulayi doctor` says which. Chrome's sandbox stays on.
Each run gets a throwaway profile, deleted afterwards (a profile that cannot be deleted is
reported with its path); downloads are denied and dialogs dismissed; the browser's process group
is killed when the run ends or is cancelled.

**Off by default.** `discovery.browser.enabled: true` turns it on. Starting a browser that runs
the target's code should be the operator's choice; this matches ZAP's AJAX Spider, Katana's
`-headless` and Nuclei's headless templates. An enabled browser that cannot be found is a usage
error before any request is sent; one that fails to start is reported and the run continues on
its other sources.

**What it contributes.** It loads the root and follows rendered links — client-side routes
(`#/…`) included — breadth first, as the anonymous caller and as each signed-in identity, within
`maxPages` (20), `maxDepth` (3) and `maxRequests` (300, divided among the actors, and counted
against `assessment.maxRequests`). It never clicks, types or submits. Each request a page made
becomes an operation by the same rule as a recording; a page load counts as a route only if it
did not come back as the application's fallback page, a 404/410 or a server error, and a
redirect counts. Rendered forms are recorded with the method they declare, as by the crawler.
Moving between pages must not spend the budget on what was already learned: per actor, a GET
of a URL already fetched is answered from the first response, one method and path is sent at
most three times whatever its query (a page that polls would otherwise spend everything), and
images, fonts and media are recorded and never fetched. A page's own request to a route
browsing never loads — sign-out and authentication, a GET listed as state-changing, an
excluded operation — is refused like a link to it, client-side routes (`#/logout`) included,
so a page cannot end the session of the identity it runs as.

**Observed query parameter names are kept, from the browser and from recordings alike.** Both
go through one conversion: method, path, and the names of the query parameters, never their
values; a token-like name is dropped. ADR-0021 dropped query strings entirely, which left the
injection checks nothing to inject into on a recorded surface. A name proves the front end sends
the parameter; it is added, optional, to the operation, including one a specification already
describes.

## Alternatives considered

**Playwright.** No official Go binding, ~650 MB of browsers plus Node, and a narrow OS matrix
(see the ecosystem research). Rejected again for the same reasons.

**chromedp or rod.** Both are maintained and MIT-licensed, but both connect over a WebSocket to
a debugging port, and rod downloads a browser unless told not to. The pipe and the few methods
Sulayi needs are a few hundred lines of standard library; a dependency here would be a large
surface for a small use.

**Let the browser connect directly and filter with a proxy.** HTTPS would need interception
certificates, the proxy would be a second enforcement point beside `httpx`, and anything the
proxy does not see would bypass it. Relaying through the one client keeps one boundary.

**Click through the application.** It would reach more of it, and it is how a page is made to
change state. Not now: the browser only loads and observes.

**Make the front end believe it is signed in** by writing a token into the page's storage.
Where the token lives is application-specific. A single-page application that decides whether it
is signed in from a token in browser storage shows its signed-out screens to every actor; the
server still sees each actor's credential on every request. Recorded as a limitation.

## Consequences

- A single-page application with no specification and no recording has a surface.
- The browser is opt-in and needs a Chrome or Chromium on the machine; CI installs none, it uses
  the runners' own, and treats a missing one as a failure of the browser tests, not a skip.
- Runs that enable it take longer and spend part of the request budget on page loads.
- What it finds is bounded by what loads without interaction. Routes behind a click, a form
  submission or a signed-in screen the front end does not show remain unfound, and the report
  says coverage is relative to what the sources revealed.
- This does not unblock Nuclei or ZAP. Their traffic is their own; the browser's is Sulayi's.
