# ADR-0024: A finding is verified by re-running its recipe as a new, linked run

- **Status:** Accepted
- **Date:** 2026-11-26
- **Relates to:** [ADR-0006](0006-finding-lifecycle.md), [ADR-0007](0007-run-directory-persistence.md)

## Context

A developer who fixes a finding wants to know whether the fix worked without
re-running the whole assessment. ADR-0006 already settles what that answer is:
"remediated" and "verified fixed" are conclusions from comparing two
assessments, never a state of a finding inside one run. What was missing is
something to re-run. A finding's reproduction was prose, and the operation it
was found on existed only in the specification or the crawl of that day.

## Decision

**Every finding Sulayi produces carries a recipe** in `report.json`
(`sulayi.report/v1alpha2`): the check, the operation exactly as it was assessed
(method, path, base path, parameters, declared expectation and where it came
from), the identities involved by id, and the fixture or created-record type it
was addressed through. A recipe carries no credential, no evidence and no
response. An imported engine observation has none and cannot be re-run.

**`sulayi verify <finding>` re-runs the recipe through the ordinary assessment
pipeline, narrowed to it**: the surface is the recipe's one operation, the
checks its one check, the fixture or record type its one resource. Nothing is
discovered, crawled or read from the earlier run but the recipe. Credentials,
scope, profile, budgets and the declared ownership and role rules are the
configuration's now, and every identity signs in afresh. A created record is
created again from its type's recipe, as its owner, and removed afterwards.

**The result is a new run linked to the original** (`verification` in its
report) with one of three verdicts:

- **reproduced** — the same check found it again on that operation (exit 1);
- **fixed** — the unit executed and produced nothing (exit 0);
- **inconclusive** — anything that kept the unit from executing: an identity
  that cannot sign in, a fixture no longer declared, a profile too low, a
  blocked request (exit 3). Inconclusive is never read as fixed.

The whole check is re-run on the operation, not only the parameter or payload
that fired: a fix that moves the defect to a sibling parameter reproduces.

**A finding is named by a short ref**, the first 12 hex digits of the SHA-256 of
its id, which `sulayi report` prints. Verify searches runs newest first, ordered
by each run's recorded creation time; a ref that matches two different findings
is refused rather than guessed.

**A recipe is input, not authority.** A report is a file anyone can edit. A
recipe whose path is not a plain path is refused, and every request it causes
goes through the same scope, guard, payload classes and budget as `attack`.

## Alternatives considered

**Replay the stored requests.** Rejected. Replaying a request replays its
credential and its moment: a session that has since expired would make a fixed
defect look reproduced, or a reproduced one look fixed, and a stored request
can carry a secret.

**Store the specification with the run and rediscover.** Rejected: discovery
would re-decide the surface, and the finding's operation could disappear or
change for reasons that have nothing to do with the fix.

**Verify only the parameter that fired.** Rejected: a second code path for
every check, and an answer to a narrower question than the one a developer asks.

## Consequences

Easier: "is it fixed?" has a cheap, honest, scriptable answer, and the answer
is itself a run with its own evidence.

Harder: the recipe is a contract. Its fields join the report schema, and a
check's identity or an operation's spelling changing between versions makes an
old recipe unusable, which verify reports as a usage error rather than a verdict.

Accepted: a recipe rebuilds the operation as it was. If the application has
since moved the route, a check could find nothing at the old address for that
reason alone. So before a verdict of fixed, verify sends one GET to the
operation as the identity whose success was the baseline (the owner, or the
allowed role, so a fix that hides a record from others with a 404 is not
mistaken for a move): a 404 or 410, or an answer identical to a path that
cannot exist (a catch-all), makes the verdict inconclusive. An operation check
on a state-changing method cannot be asked that way without changing state, so
its verdict is never fixed, only reproduced or inconclusive.

An operation check names no fixture in its recipe. Its re-run keeps the
configured fixtures and the record types that address the operation, so a
route with an id is addressed the way it was the first time.
