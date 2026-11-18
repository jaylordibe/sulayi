# ADR-0019: Safety is enforced at the HTTP client, and tools that bypass it do not run

- **Status:** Accepted
- **Date:** 2026-11-19
- **Relates to:** [ADR-0008](0008-scope-is-the-authorization-boundary.md),
  [ADR-0013](0013-cross-owner-verification-semantics.md),
  [ADR-0015](0015-external-engine-boundary.md),
  [ADR-0018](0018-product-identity-sulayi.md)

## Context

Sulayi is to test applications the way an attacker would, autonomously, with a
default profile that changes test data. A security review of the code it
inherited found the safety boundary held for scope but not for impact:

- Profiles were checked only while planning. `httpx.Do`, through which every
  request passes, accepted any method under any profile, so a check that planned
  one thing and sent another would not have been stopped.
- Nothing handled an interrupt. Stopping a run killed the process and left child
  engines running, and a fixture written to but not yet restored stayed modified.
- There was no limit on total requests or duration, and no record of what was
  sent.
- Nuclei and ZAP open their own connections, outside every control Sulayi has —
  scope, address checks, redirects, rate, budget and log.

## Decision

**Three profiles, enforced from the request in `httpx.Do`.** `safe` refuses every
state-changing request. `standard`, the default, permits a state-changing request
only when it is an exact request registered by the planner for a fixture the
operator declared `disposable`: same method, same URL including query, a JSON body
changing only that fixture's configured fields, never `DELETE`. Registration is
sealed before execution. `aggressive` permits state-changing requests against any
in-scope target. A request is state-changing when its method is not read-only or
the operator lists it in `assessment.stateChangingOperations`. A client with no
guard behaves as `safe`.

**`aggressive` requires three things**: `target.disposable: true`, a confirmation
in which the operator types the target's exact origin (`--yes` replaces only the
prompt), and scope entries that each name one exact origin.

**Stopping is safe.** SIGINT/SIGTERM cancel the run; child process groups are
killed; anything after a write may have reached the target runs on a detached
context bounded to 30 seconds. Cleanup that fails or cannot be verified is
reported as `cleanupIncomplete`, never as success.

**Limits and accountability.** `maxRequests` (default 1,000) and
`maxDurationMinutes` (default 30), with a small, finite allowance for restoration.
Every `Do` call is written to `requests.jsonl`; if that write fails, no further
request is sent. A run that stops early still reports, says why, and exits 4.

**Credentials are bound to their target's origin**, not to scope.

**An engine that opens its own network connections does not run, in any
profile**, until a verified mechanism constrains its outbound destinations. The
integrations are kept; only their execution is blocked, and the lost coverage is
reported.

## Alternatives considered

**A check declares the impact of each request it sends.** Rejected: that is a
label, and the point of the guard is that a claim about a request is not
accepted. Impact is derived from the method, the operator's configuration and
the registered fixture requests.

**Authorize `standard` mutations by route or URL pattern.** Rejected: a pattern
matching one fixture matches every record behind the same route. Exact request,
exact fields.

**Infer which `GET` endpoints change state.** Rejected for S0 as unreliable;
the operator lists them. The limitation is documented in the threat model.

**Run Nuclei and ZAP under a documented exception, or build an egress proxy
now.** Rejected: an exception is a weaker boundary written down, and a proxy is a
new security component that cannot be validated against the real engines here.
Blocking loses coverage, and says so.

**`--yes` alone, or a `y/N` prompt, for `aggressive`.** Rejected: a flag is
copied between commands and environments, and `y` is answered by reflex.

## Consequences

- Default runs now change data, but only records the operator named as disposable,
  only through exact requests, and with every change logged and reversed or
  reported.
- Nuclei and ZAP coverage is gone until an egress control exists; runs that
  enable them say so in every summary.
- Pre-Sulayi profile names and `authorizeIntrusive` are refused with migration
  messages.
- An application whose read-only methods change state is protected only as far
  as the operator lists those operations.
