# ADR-0023: Injection and misconfiguration checks, each with a deterministic oracle and a payload class the client enforces

- **Status:** Accepted
- **Date:** 2026-11-26
- **Relates to:** [ADR-0003](0003-differentiator-oracle-and-coverage.md), [ADR-0019](0019-safety-enforced-at-the-http-client.md)

## Context

Sulayi tests authentication and authorization, and nothing a request's own
values can do to the application. A scanner that sends a payload list and
reports anything that looks unusual is what this project exists not to be: its
findings are a guess, and its payloads are whatever its authors thought
harmless. Two things are therefore required of every injection check: an oracle
that cannot fire by coincidence, and a payload whose impact the safety profile,
not the check, decides.

## Decision

**Six checks, each confirmed by an observation that cannot be produced by
accident.**

- **SQL injection, boolean-based.** The baseline is sent twice and must be
  identical. A true-condition variant must match it and a false-condition
  variant must differ from it, in the same quoting context. A second,
  independent pair must agree before the finding is confirmed; one pair alone
  is suspected. The payload text is removed from responses before comparison,
  so an application that echoes its input does not differ for that reason.
- **Reflected XSS.** A unique tag comes back unencoded in an HTML response,
  right after the quote breakout that put it there. Inside an element whose
  content is not parsed as markup (script, style, textarea, title and the
  like), in a comment, or after an encoded quote it is suspected, because
  whether it executes there depends on more than the response shows.
- **Server-side template injection.** Template expressions for the common
  engines compute 7×7919, and a second expression in the same syntax 7×7927;
  both products appear, and neither is in either baseline.
- **Open redirect.** The `Location` of a redirect names a host under the
  reserved `.invalid` top-level domain. Redirects are never followed and the
  host can never resolve.
- **CORS.** A route that requires authentication, requested as a signed-in
  identity with an `Origin` under `.invalid`, echoes that origin with
  `Access-Control-Allow-Credentials: true`. It is confirmed only when the
  identity signs in with a cookie session: a browser never attaches a bearer
  or API-key header to another origin's request, so for those it is suspected,
  at low severity.
- **Stack-trace disclosure.** A malformed value produces runtime stack frames
  (PHP, Node, Python, Java, .NET) that the baseline does not. A debug page
  often lists the server's secrets, so only the matched frames of that
  response are kept as evidence.

**Payloads go into query and path parameters of GET operations only.** Bodies
need request-body schemas, which the surface model does not carry, and under
`standard` they would be state-changing requests nobody declared. The report's
not-assessed list says so for SQL injection and XSS rather than implying
coverage.

**Every payload is in one closed catalogue with an impact class**: inert
(reflected only), evaluating (computed by a vulnerable template engine), or
query-altering (changes a vulnerable query's logic). The HTTP client finds any
non-inert catalogue payload in an outgoing request's path, query, headers or
body and refuses it under `safe`, and in anything but a GET or HEAD under every
profile. A check never states its own payload's class. Stacked queries,
destructive SQL and delays are not in the catalogue, so nothing can send them.
A boolean condition is still not harmless everywhere: a GET route whose
vulnerable statement writes would store the condition's value, which is one
reason query-altering payloads need `standard`.

**A path parameter is filled** from a fixture or created record that applies to
the operation; **a query parameter** from the fixed value `1`. Injected requests
are sent as the primary identity, so routes behind sign-in are reachable. When
an identity is configured and unusable, nothing is sent anonymously instead,
and a baseline answered 401 or 403 blocks the row: a payload's answer from a
route the caller cannot reach says nothing. A check that could put its payload
into no parameter reports the row untested rather than clean, and a weakness
class counts as assessed only when its check executed.

## Alternatives considered

**Time-based SQL injection.** Rejected for now: timing is noise on a shared
machine, and every probe adds deliberate load.

**Command injection, SSRF, blind injection.** Deferred. Confirming them needs a
callback to a listener the target can reach, which is an external service this
project does not require.

**Path traversal.** Deferred. Its proof is reading a file from the server.

**Error-based SQL injection as confirmation.** Rejected. A database error
message shows that input reached a query unescaped often enough to be worth a
suspected finding, and not that the query can be steered.

## Consequences

Easier: a confirmed injection finding states a reproducible observation, and the
payload behind it is one a reader can look up in the catalogue with its class.

Harder: each parameter costs several requests. The run's request budget and the
per-operation parameter bound apply, and work not reached is in the ledger.

Accepted: injection in request bodies, headers other than `Origin`, and
non-GET operations is not assessed, and the report says so.
