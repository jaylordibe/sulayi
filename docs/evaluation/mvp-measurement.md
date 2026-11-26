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
