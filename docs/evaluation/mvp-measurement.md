# MVP measurement

Results of the measurement defined in
[ADR-0025](../adr/0025-mvp-measurement-method.md), published as measured. Each
entry is dated and is never edited afterwards; what an entry prompts is fixed
and measured again as a new entry below it.

## Entry 1 — 2026-11-26, commit `22161cd`

Runs: [MVP measurement 45872166157](https://github.com/jaylordibe/sulayi/actions/runs/45872166157)
and [reference applications 45872205588](https://github.com/jaylordibe/sulayi/actions/runs/45872205588).
Juice Shop v20.4.0 and crAPI v1.1.6 at the pinned digests, three runs each under
the default profile; each reference starter once.

### Summary

**Neither vulnerable target was measured.** Both runs stopped on defects in
Sulayi before any check reached an expected entry, so this entry measures those
defects rather than detection. Detection is 0 of 10 assessed entries, all
unreached; no finding was reported anywhere, so there is no false positive and
nothing to triage. No request left scope on any target.

| Target | Findings | Detection | Coverage | Reproducible | Time per run | Outside scope |
|---|---|---|---|---|---|---|
| Juice Shop | — (no report) | not measured | not measured | — | ~1s, stopped in discovery | 0 |
| crAPI | 0 | 0 of 4 (all unreached) | 0 of 314 | yes, 3 runs | 1s | 0 |
| nestjs-api starter (control) | 0 | — | 68 of 604 | 1 run | 73s | 0 |
| laravel-api starter (control) | 0 | — | 34 of 331 | 1 run | 9s | 0 |

False positives: none, on any target. With no findings at all, that number says
nothing yet about the verification approach; it says only that nothing was
reported wrongly.

### Juice Shop: discovery stopped on the single-page application's fallback

Sulayi probes well-known specification paths before using the browser
recording. Juice Shop serves its single-page application's `index.html`, with
status 200, for every unknown path, so `/openapi.json` returned an HTML page.
Sulayi treated that as a specification that failed to parse and stopped the run
("a document was served at a well-known path but could not be parsed"), although
the operator had supplied a recording. No report was written, and the scorer
failed on the missing report. Every request was in scope (9 per run).

This is a defect: an HTML page at a well-known path is a single-page
application's fallback, not a malformed specification, and must be treated as
absence.

### crAPI: the specification's server host replaced the target's

crAPI's specification declares `servers: [{url: http://localhost:8888}]`; the
target was given as `http://127.0.0.1:8888`. Sulayi kept the document's absolute
server URL as the base for every operation, so each operation request went to
`localhost:8888`. The client refused all of them before sending: out of scope
for anonymous requests, and a credential bound to a different origin for
signed-in ones. Sign-in, liveness and crawling, which use the target URL,
succeeded. Every expected entry was blocked:

| Expected | Outcome | Cause |
|---|---|---|
| crapi-bola-vehicle-location | unreached | owner control refused: credential bound to the target's origin |
| crapi-bola-order | unreached | owner control refused: credential bound to the target's origin |
| crapi-unauthenticated-order | unreached | catch-all baseline refused: `localhost` not in scope |
| crapi-bfla-users-all | unreached | allowed identity's request refused: credential bound to the target's origin |

The ten entries in classes Sulayi does not test are listed in the run's
measurement with their reasons.

This is a defect, and the code contradicts its own comment ("preferring the
target origin the operator supplied over a server entry the document
controls"). The safety layer worked as designed: it refused every request to
the other host, so the defect cost the measurement but sent nothing outside the
authorized scope.

### Reference starters

Both ran clean: no findings, no request outside scope, no record left behind.

### Provenance

crAPI was scored against `evals/mvp/crapi.expected.yaml` with SHA-256
`36513d88fef6e5159a91895e5de84d83142aec7a8c0366b06805046dff4ba1c3`. The
measurements, reports and request logs are the runs' artifacts.

## Entry 2 — 2026-11-27, commit `117d79d`

Runs: [MVP measurement 45952555588](https://github.com/jaylordibe/sulayi/actions/runs/45952555588)
and [reference applications 45952559544](https://github.com/jaylordibe/sulayi/actions/runs/45952559544).
Same pinned versions, digests, configurations and ground truth as entry 1; the
two discovery defects entry 1 found are fixed (`2570779`), and so is a third
found while preparing this entry (below).

### Summary

**Both vulnerable targets were measured. Every finding is a true positive: no
false positive on any target.** Sulayi confirmed 5 of the 10 assessed expected
entries — all four on crAPI and one of six on Juice Shop. Every target gave
identical ledgers and findings across its runs, no request left scope, and no
record was left behind.

| Target | Findings | Detection | Coverage | Reproducible | Time per run | Outside scope |
|---|---|---|---|---|---|---|
| Juice Shop | 2, both true | 1 of 6 | 2 of 155 | yes, 3 runs | 1s | 0 |
| crAPI | 5, all true | 4 of 4 | 65 of 316 | yes, 3 runs | 32s | 0 |
| nestjs-api starter (control) | 0 | — | 73 of 620 | 1 run | 74s | 0 |
| laravel-api starter (control) | 0 | — | 34 of 331 | 1 run | 9s | 0 |

False positives: 0 of 7 findings, with none unlisted awaiting triage. Seven
findings is a small sample; the number says the verification approach
reported nothing wrongly here, not that its false-positive rate is known to be
low in general.

### crAPI: every assessed entry confirmed

| Expected | Outcome | Check |
|---|---|---|
| crapi-bola-vehicle-location | confirmed | cross-owner-resource-read |
| crapi-bola-order | confirmed | cross-owner-resource-read |
| crapi-unauthenticated-order | confirmed | declared-auth-not-enforced |
| crapi-bfla-users-all | confirmed | cross-role-read (as both non-admin accounts) |

The ten entries in classes Sulayi does not test are listed in the run's
measurement with their reasons, unchanged from entry 1.

### Juice Shop: the one reachable boundary confirmed, the rest unreached

`js-bfla-authentication-details` was confirmed as both customer accounts: an
ordinary customer reads every user's record, including password hashes and
TOTP secrets.

The other five assessed entries were unreached, and none of them for a defect
in a check:

| Expected | Outcome | Cause |
|---|---|---|
| js-sqli-product-search | unreached | the recorded request carries no query parameter to inject into |
| js-stack-trace | unreached | no recorded GET operation carries a parameter to inject into |
| js-open-redirect | unreached | the redirect route is not in the recording |
| js-bfla-users | unreached | `/api/Users` is not in the recording |
| js-bola-basket | unreached | `GET /rest/basket/1` is in the surface, but the configuration declares no record recipe or ownership rule for it |

These are limits of the operator's inputs — a recording reduced to methods and
URLs, and a configuration that declares no basket ownership — measured as they
were written before any run. They are not changed here: adjusting the inputs
until the number improves is what ADR-0025 forbids. Whether Sulayi should
reach these entries from a fuller recording is a question for "Later".

### A reporting defect found while preparing this entry

A local run at `2570779` reported Juice Shop's two confirmed cross-role
findings under "This assessment executed no checks. It establishes nothing"
and exited 3. Cross-role work was recorded in its own ledger dimension, which
was never counted as assessment work. Fixed in `117d79d`; this entry's runs
report `executed: 2` and exit 1. The starters did not show it because other
checks ran on them.

### Verify on a real target

Outside the measured runs, `sulayi verify` re-ran crAPI findings
`crapi-bola-order` and `crapi-bfla-users-all` from their recipes against a
local crAPI at the same pins: both reproduced.

### Provenance

Juice Shop was scored against `evals/mvp/juice-shop.expected.yaml` with SHA-256
`b13d83399905aa063343618962aae91ac13e9e37e06e9f8474e4ed3e5ea4a009`, and crAPI
against `evals/mvp/crapi.expected.yaml` with SHA-256
`36513d88fef6e5159a91895e5de84d83142aec7a8c0366b06805046dff4ba1c3`. The
measurements, reports and request logs are the runs' artifacts.

## Entry 3 — 2026-11-27, commit `ed0c858`

Run: [MVP measurement 45997366779](https://github.com/jaylordibe/sulayi/actions/runs/45997366779).
Same pinned versions, digests and ground truth as entries 1 and 2. One input
changed, and it is the capability under test: Juice Shop's configuration
enables the headless browser
([ADR-0026](../adr/0026-headless-browser-with-no-network-of-its-own.md)), beside
the same recording. crAPI's configuration is unchanged. The reference starters
were not re-run: nothing they exercise changed, and the browser is not enabled
for them.

### Summary

**No false positive on either target, and no request left scope. Juice Shop was
not reproducible across its runs — a defect in the browser, found by this
entry and described below.** Detection is unchanged at 5 of 10 assessed
entries; on Juice Shop the browser brought three entries that entry 2 could not
reach into the assessment, and the checks found nothing in them.

| Target | Findings | Detection | Coverage | Reproducible | Time per run | Outside scope |
|---|---|---|---|---|---|---|
| Juice Shop | 2, both true | 1 of 6 | 45 of 232 (see below) | **no** — runs differ | 37s | 0 |
| crAPI | 5, all true | 4 of 4 | 65 of 316 | yes, 3 runs | 32s | 0 |

False positives: 0 of 7 findings, none unlisted awaiting triage.

### Juice Shop: three more entries reached, none confirmed

| Expected | Entry 2 | Entry 3 | Detail |
|---|---|---|---|
| js-bfla-authentication-details | confirmed | confirmed | as both customer accounts |
| js-sqli-product-search | unreached | missed | the browser observed `q`; the boolean check ran on it and found nothing |
| js-stack-trace | unreached | missed | executed on `GET /api/Challenges/`; nothing disclosed |
| js-open-redirect | unreached | missed | the browser followed the rendered `/redirect?to=…` link; the check ran on `to` and found nothing |
| js-bfla-users | unreached | unreached | `/api/Users` is requested only by the administration screen, which the front end does not show: it decides it is signed out because its token lives in browser storage |
| js-bola-basket | unreached | unreached | in the surface, with no ownership rule declared for it |

The three misses are what the ground truth anticipated when it was written:
product search places the input inside `LIKE '%…%'`, where a quoted boolean
condition is closed by the application's own `%`, and the redirect allowlist
is bypassed only by embedding an allowlisted URL, which the open-redirect check
does not attempt. Both are limits of the checks, not of the surface.

Each actor browsed 7 pages and failed to load 1: the rendered GitHub link
behind `/redirect`, which scope refused, as it should.

### The defect: the fallback probe's own requests became operations

Before browsing, the browser loads a path that cannot exist
(`/sulayi-browse-<random>`) to learn the application's fallback page. Juice
Shop's page, loaded there, starts its chat client, which polls
`/sulayi-browse-<random>/socket.io/`. Those requests were kept as operations:
one per actor, with a random path, so every run's ledger differed in 28 rows (4
operations × 7 checks), and 20 of the 45 executed rows above were checks run
against paths Sulayi made up. Nothing else in the ledgers differed.

Nothing under the probe's path is a route of the application. Fixed after this
entry: everything requested under it is left out
(`discovery.TestNothingUnderTheProbePathBecomesARoute`). The next entry
measures the fix.

### Provenance

Scored against the same expected files as entry 2 (Juice Shop SHA-256
`b13d83399905aa063343618962aae91ac13e9e37e06e9f8474e4ed3e5ea4a009`, crAPI
`36513d88fef6e5159a91895e5de84d83142aec7a8c0366b06805046dff4ba1c3`). The
measurements, reports and request logs are the run's artifacts.
