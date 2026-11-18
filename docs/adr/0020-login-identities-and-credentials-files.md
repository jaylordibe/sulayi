# ADR-0020: Identities sign in through the application, from a credentials file that lends only what is used

- **Status:** Accepted
- **Date:** 2026-11-19
- **Relates to:** [ADR-0012](0012-authenticated-control-and-material-equivalence.md),
  [ADR-0019](0019-safety-enforced-at-the-http-client.md)

## Context

Until now an identity was a token the operator minted by hand and exported. That
is the main reason authenticated testing was rarely configured: it needs a login,
a copy and a paste per account, and the token expires mid-run.

Four facts constrained the design:

- The S0 guard refuses every state-changing request under `safe` and `standard`
  unless it is a registered disposable-fixture write. A login is a POST.
- Redaction masks JWTs in every captured body, so a token cannot be read from the
  exchange a normal request returns.
- The reference starters answer bad credentials with 400, not 401 (Laravel), and
  rate-limit sign-in (both).
- Results produced with a dead credential must be withdrawn, and the existing
  invalidation assumed an identity, once dead, stayed dead.

## Decision

**`--env <file>`** loads a credentials file explicitly — never `.env` or
`.env.example` on its own — with a small parser that does no command
substitution. `${NAME}` in an unquoted or double-quoted value expands to the
shell's NAME or one defined earlier in the file, as phpdotenv, python-dotenv and
Compose do; without it the Laravel starter's `SYSAD_EMAIL="sysad@${APP_DOMAIN}"`
was sent literally and rejected. A name used only for expansion is still not
readable as a credential. Only names `sulayi.yaml` references are kept; the rest are counted
and ignored. Values stay in memory and never enter the process environment. A
shell variable overrides the file. A file git tracks is refused; one no ignore
rule covers, or that others can read, is warned about. No error prints a value.

**`authentication.type: login`** signs in with the application's own login
request: a path on the target (never a URL), POST/PUT/PATCH, a JSON or form body
whose every field is a reference (`env`, `file`, or `fromPreflight` from an
optional GET/HEAD preflight). The session is a bearer token read by JSON pointer
from a 2xx response, or the cookies the login response sets, on a 2xx or an
unfollowed redirect. An optional CSRF cookie is sent back in a header.

**The login is the one exception to the safety profiles.** The exact method and
URL, carrying only the configured fields, is permitted under every profile —
but only through `Client.Authenticate`, whose marker is unexported. The same
request sent through `Do`, as checks send requests, is refused. Every other gate
applies. `Authenticate` returns the response raw, in memory only, and no exchange
to store; everything secret is registered with the redactor before the next
capture.

**Recovery is bounded and never replays.** A login identity signs in again only
when its liveness canary answers 401 or 419, at most three times a run, one at a
time per identity. The request that failed is not resent. Every interval in which
a session may have been dead is kept, including after recovery, and results whose
authenticated control ran inside one are withdrawn.

**`role`** is an optional label carried into the report. It grants nothing;
authorization testing across roles is later work.

Sign-out routes join login routes in the default sweep exclusion, because an
authenticated control request to one would end the session the run depends on.

## Alternatives considered

**Load every name in the file, or every `SULAYI_*` name.** Rejected: a prefix
still loads whatever the file happens to define. Reading only referenced names
makes passing the wrong file harmless.

**Export file values into the environment.** Rejected: that is how a secret
reaches a child process when an environment is later built carelessly.

**Refresh-token grants instead of signing in again.** Rejected for now: every
framework does refresh differently, and a fresh sign-in works the same way
everywhere. The cost is a few extra logins, which the bound limits.

**Replay the request that hit the expired session.** Rejected: a replayed write
is a duplicated write, and the request's original outcome is already recorded.

**Allow `value:` literals in the login body** (for `grant_type`, a client id).
Rejected: it would let a password be written into a committed file. No reference
application needs one; it can be added when one does, for non-secret constants.

**Validate cookie and CSRF flows against Sanctum or NextAuth.** Not done: neither
reference application uses them. They are covered by local fixtures and claimed
for nothing more.

## Consequences

- Authenticated testing needs a login path and a credentials file instead of
  hand-minted tokens, and keeps working when a token expires mid-run.
- Under `safe`, a login is now sent. It is the configured request and nothing
  else.
- Compatibility is claimed only where tested: bearer logins against the Laravel
  Passport and NestJS JWT starters, in the reference-applications workflow.
