# ADR-0021: An application without a specification is assessed from what can be observed, against a declared policy

- **Status:** Accepted; superseded in part by [ADR-0026](0026-headless-browser-with-no-network-of-its-own.md)
  (the rejection of a headless browser, and dropping a recording's query strings entirely)
- **Date:** 2026-11-19
- **Supersedes in part:** [ADR-0016](0016-discovered-surface-is-not-an-operation.md) (its rule that discovery never fetches what it finds, for the crawler only)
- **Relates to:** [ADR-0019](0019-safety-enforced-at-the-http-client.md), [ADR-0020](0020-login-identities-and-credentials-files.md)

## Context

Without an OpenAPI document Sulayi stopped with "no OpenAPI document found".
Most applications built with Laravel, Next.js or Vue publish none, so for the
applications Sulayi exists to test, it could test nothing. Framework adapters
could not help: the specification was required before they ran.

ADR-0016's reasoning still holds and constrains the answer: an invented method
invents a request, and an invented expectation invents a finding. Both halves of
the problem — finding real requests, and knowing what should happen to them —
have to be solved without inventing either.

## Decision

**A specification is one source of surface, not a requirement.** The others:

- **Framework adapters**, which read the routing table and so establish method
  and authentication expectation. With no specification their routes are the
  surface.
- **A HAR** (`--har`): the requests the application's own front end made, which
  is how a single-page application's API is found without a browser. It is
  discovery input only — methods and paths are decoded and nothing else, nothing
  is replayed or stored, and its operations are gated like any other.
- **A bounded crawler**: GET only, same origin under the base path, a fixed depth
  and page count, run anonymously and as each signed-in identity, through the
  S0 client. Forms are recorded by the method they declare and never submitted;
  no script runs; sign-out and other risky routes are never requested; an SPA
  fallback is fingerprinted and never counted as a route.

None of them guesses a method. A path a source sees without one — a JavaScript
literal, a `robots.txt` line — stays an untested ledger row, as ADR-0016 says.

**The oracle is a declared access policy** (`access.protected` / `access.public`
path patterns), with the standing of a specification's security declaration: it
states what should happen and can make a finding confirmable, but only through the
existing authenticated-control verification. Where it contradicts the
specification or an adapter, the expectation is withdrawn and the disagreement
reported.

**Where nothing is declared, two inferences, both capped at suspected:**
an adapter's expectation (it read source, which proves nothing about behaviour),
and a route reachable by link only while signed in. The second raises nothing at
all unless an anonymous caller receives what the signed-in one did.

The passive discovery sources keep ADR-0016's rule: they never fetch what they
find. The crawler is the one component that does, and only within the limits above.

## Alternatives considered

**A headless browser.** Rejected for now: it would find SPA routes the crawler
cannot, but it is a large dependency and a runtime that executes target code. A
HAR gets the same routes with neither.

**Infer protection from a route's name** (`/admin`, `/api/internal`). Rejected:
a name is a string, and ADR-0016 already says why.

**Replay HAR requests** to learn bodies and parameters. Rejected: a recording can
hold destructive requests and live credentials, and replaying it would make a
file the authority for what Sulayi sends.

**Comparison across identities with no policy, confirmable.** Rejected: public
pages legitimately look the same to everyone, so without a declared expectation a
match proves nothing.

## Consequences

- An application with no specification is assessable; with a policy, findings can
  be confirmed; without one, the best it can produce is a suspected finding, and it
  says so.
- The crawler adds traffic, bounded by its own limits and the run's budget.
- Coverage of a spec-less surface is relative to what the sources revealed, and
  the report says that instead of offering a completeness figure.
