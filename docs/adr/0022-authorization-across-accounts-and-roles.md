# ADR-0022: Authorization across accounts and roles, from records Sulayi creates and a declared policy

- **Status:** Accepted
- **Date:** 2026-11-26
- **Amends:** [ADR-0013](0013-cross-owner-verification-semantics.md) (where ownership and its expectation come from), [ADR-0019](0019-safety-enforced-at-the-http-client.md) (the one DELETE the standard profile sends)
- **Relates to:** [ADR-0020](0020-login-identities-and-credentials-files.md), [ADR-0021](0021-surface-without-a-specification.md)

## Context

Cross-owner testing (ADR-0013) runs only against fixtures an operator writes by
hand: an identifier known to belong to one identity, and a per-fixture
`crossOwnerAccess`. On both reference starters the seeded accounts own almost
nothing, and neither starter can produce a second account of the same role
without reading a verification email outside the application. An operator would
have to sign in, create a record, copy its identifier into `sulayi.yaml`, and
remember to delete it. Nobody does that, so object-level authorization goes
untested.

Role is a label that is only reported (ADR-0020). Nothing compares what two
roles can reach, so a route an administrator alone should call is never tested
as anyone else.

Three standing rules shape the answer:

- **Ownership is never inferred** (`internal/resource/resource.go`). An
  identifier that appeared in a list response is not owned by the caller:
  administrators see everyone's records and workspace members see shared ones.
- **The expectation is declared, never defaulted** (ADR-0013). Assuming every
  record is private reports every deliberately shared one as a vulnerability.
- **Standard never sends DELETE**, and every state-changing request it permits
  is registered before the guard is sealed (ADR-0019).

## Decision

**An owned record is one Sulayi created as that identity, or the identity
itself.** `records[]` declares a creation recipe: the collection path, a JSON
body whose values are literals, the identity's own id, or a value random per
run, the JSON pointer of the new record's id in the response, and the path that
deletes it. Sulayi creates one record per recipe as each listed identity after
sign-in and before planning. The creator is the owner, as a fact the run
established, not an inference. An identity's own id is read from its liveness
canary response through a declared pointer (`liveness.self`). Identifiers are
never taken from list responses, crawls or adapters.

**The expectation is declared per path, not per fixture.** `access.owned`
names the path patterns whose records belong to their creator, with the roles
that may reach other identities' records by design (`reachableBy`).
`access.roles` names the path patterns only certain roles may call (`allow`).
A path with no declaration gets no conclusion. It is not reported as suspected,
because an undeclared expectation is exactly the default ADR-0013 rejected.

**A created record feeds the existing cross-owner read check unchanged:** owner
control, non-owner probe, owner re-check, and confirmation only through material
equivalence and resource identity. Identities whose role is in `reachableBy` are
not probed, since their access is expected. Cross-owner writes against created
records are not part of this decision.

**A cross-role probe is read-only.** For a GET whose path matches an
`access.roles` rule, each live identity whose role is not allowed is compared
with a live identity whose role is. The allowed identity must succeed, or there
is no baseline and the unit is blocked. A refusal is a verified denial. A
success materially equivalent to the allowed identity's response is confirmed;
any other success is suspected, because a narrower answer may be legitimate
scoping. State-changing administrative routes are never probed across roles:
they include resetting another account's password and deleting users.

**The standard profile may create declared records and delete exactly those.**
The guard gains a one-shot grant kind: an exact method, URL and body, consumed
on first use. The creation POST is granted that way just before it is sent.
When it succeeds, the DELETE of the URL built from the returned id is granted
the same way, before the guard is sealed. The id is validated like any fixture
value and the URL re-checked for origin and base path; an id that fails is
never addressed and the record is reported as not removed. Every other DELETE
in standard is still refused. Safe creates nothing; the declared recipes are
reported as not created.

**Cleanup is verified and reported.** At the end of the run, including after an
interrupt or an exhausted budget, each created record is deleted as its creator
on a context that ignores cancellation and draws on the cleanup allowance. It
counts as removed only when the creator's GET of it no longer succeeds. Every
record is listed in the report with whether it was removed. One not removed is
also run-level cleanup state, because somebody's data is still there.

## Alternatives considered

**Harvest identifiers from list responses.** Rejected. A list shows what the
caller can see, not what it owns, and every administrator and shared record
becomes a false positive. The roadmap's "identifiers from each account's own
responses" is met by the creation response and the identity's own record.

**Synthesise creation bodies from the specification's schema.** Deferred.
Unique constraints, cross-field rules and fields that must equal the caller's
own id (NestJS device tokens) make schema-generated bodies fail validation or
create the wrong thing. A declared recipe is a few lines and is exact, which is
also what the guard's exact-request grant needs.

**Create only under aggressive.** Rejected. The default profile would have no
cross-account coverage at all. Deleting a record the run itself created, as its
creator, is the least destructive cleanup there is. Leaving test data in a
developer's application is worse for them than this narrow DELETE.

**Grant the cleanup DELETE after the guard is sealed.** Unnecessary. Records
are created before planning, so the URL is known before the seal and the rule
that nothing widens the guard during execution stands.

**A second same-role account through the mail catcher.** Rejected for now.
Reading an inbox outside the application is environment provisioning, which the
roadmap leaves for later.

## Consequences

Easier: on the reference starters, cross-account and cross-role tests run from
a few lines of policy and one recipe per record type, with no identifier
written by hand. A confirmed finding still means what ADR-0013 says it means.

Harder: the run now changes the target under the default profile. That change
is bounded to records the operator declared, counted against the budget, and
undone and verified, or reported by URL when it could not be. An application
whose delete is soft keeps a row its API reports as gone; the report says
removed through the application's API, which is the most that can be observed.

Accepted: with one account per role, cross-account coverage is between
identities of different roles, so a role in `reachableBy` reduces it to one
direction. A second account of the same role still has to be configured by
hand.
