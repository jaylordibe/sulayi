# ADR-0025: The MVP is measured against pinned vulnerable applications and published as measured

- **Status:** Accepted
- **Date:** 2026-11-27
- **Relates to:** [ADR-0003](0003-differentiator-oracle-and-coverage.md), [ADR-0010](0010-coverage-is-a-ledger.md)

## Context

The roadmap ends the MVP with a measurement: false positives first, then
confirmed detections, coverage, reproducibility, time, and requests outside
scope, which must be zero. It also states the failure condition plainly: a
false-positive rate high enough that a developer would switch the checks off
means the verification approach has failed, and is to be reported as such, not
tuned until the number looks better. A measurement that can be quietly adjusted
after its results are seen proves nothing.

## Decision

**Targets.** OWASP Juice Shop and OWASP crAPI, OWASP's reference deliberately
vulnerable web application and API; the two reference starters, which are meant
to be secure, are the false-positive control.

**Pinned.** Juice Shop at v20.4.0 and crAPI at v1.1.6, source by commit and
images by digest. crAPI publishes version tags for one of its images only, and
its v1.1.6 compose file runs `latest`, so each image is pinned to the digest
`latest` carried for that release. (The reference starters track their latest
on purpose; that workflow detects drift, this one measures.)

**Ground truth first.** `evals/mvp/<target>.expected.yaml` lists each
deliberately shipped vulnerability with the checks that would report it, the
operation, and where in the target's source it is, read from the source at the
pinned commit because the projects' challenge lists rarely name endpoints. An
entry in a class Sulayi does not test is listed with `assessed: false` and its
reason, so the measurement states what it did not look at. These files were
written and committed before any measurement run.

**Configured as an operator would.** Each target gets the configuration its
documentation and seed data support: its seeded accounts, declared fixtures
and role rules. Juice Shop has no specification of its API, so its surface is a
browser recording made once against the pinned version and reduced to methods
and URLs before it was committed; what such a surface cannot carry (query and
path parameters, routes the front end never requested) is stated against each
expected entry rather than worked around. An identifier an operator would read
from their own account (crAPI's order) is read the same way by the workflow.

**Measured by the tool, not by hand.** `evals/mvp/measure` reads each run's
report and request log. A finding matching an expected entry is a true
positive; one on a known-correct route, or on a control target, is a false
positive; anything else is unlisted and triaged by a person, and the triage is
published with it. Detection is confirmed findings over assessed entries, and
each missed entry says whether the check ran on its operation or never reached
it. Coverage is executed over planned work from the ledger. Three runs per
target must produce identical ledgers and findings. Requests outside scope are
counted from the request log, and any fails the measurement.

**Published as measured.** The first results go into
`docs/evaluation/mvp-measurement.md` unchanged. Anything they prompt is fixed
afterwards and measured again as a separate, dated entry; the first entry is
not edited.

## Alternatives considered

**OWASP Benchmark.** It is the standard for scoring true- and false-positive
rates, but it is a Java servlet suite whose test cases are mostly in request
bodies, which Sulayi does not test yet. It would measure the gap, not the tool.

**Writing the ground truth from the projects' challenge lists alone.**
Rejected: they describe the challenge, not the endpoint, and an expected file
that guesses endpoints would score guesses.

**An OpenAPI document written for Juice Shop.** Rejected for this measurement:
it would describe a surface no operator of a single-page application has, and
measure the document rather than the tool.

## Consequences

The measurement is reproducible by anyone from the workflow and the committed
files. It is also honest about scope: entries Sulayi does not test are counted,
named and explained, so a detection rate cannot read as more than it is.
