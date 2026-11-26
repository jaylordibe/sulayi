# Threat model: Sulayi itself

This is security software that will deliberately connect to hostile applications, execute
third-party scanners, and store captured credentials and personal data. Its own attack
surface must be treated as seriously as the targets it assesses.

Scope: the `sulayi` CLI, its configuration, its adapters and engines, its evidence store
and its reports.

The status of each control is load-bearing, because claiming a control is implemented when
it is not would be the exact failure this project exists to prevent:

| Status | Meaning |
|---|---|
| **TESTED** | Implemented in this repository **and** covered by a test that demonstrates the control, named below. |
| **IMPLEMENTED** | Implemented, but not yet covered by a test that would catch its regression. |
| **DESIGNED** | The boundary exists; the capability it protects is not built yet. |
| **PLANNED** | Neither exists. |

Nothing here is marked TESTED without a test that fails if the control is removed.

---

## 1. Trust boundaries

```
        UNTRUSTED                          |  TRUSTED
------------------------------------------ | ---------------------------
 target HTTP responses, headers, bodies    |  sulayi.yaml (user-authored)
 HTML, JavaScript, redirects               |  the operator's intent
 OpenAPI / GraphQL documents               |  the local filesystem we own
 target source repositories                |
 external scanner output (ZAP/Nuclei/...)  |
 adapter probe output                      |
 database rows and audit logs read as      |
   evidence                                |
 scanner templates and rules               |
```

**Everything on the left is data, never instruction.** It is never interpolated into a
shell, never used to construct a filesystem path, never used to decide what to attack,
and — when AI is eventually introduced — never treated as a prompt.

The configuration file is trusted because the operator wrote it. It is nonetheless
validated strictly, because a trusted author still makes mistakes and because a
configuration file may arrive via a pull request.

---

## 2. Threats

### T-01 Scope escape — the scanner attacks something it was not authorized to attack

The single most serious threat. An assessment tool that wanders off-target is an attack
tool. Vectors: a redirect to another host; an absolute URL in an OpenAPI `servers` entry;
a `Location` header pointing at cloud metadata; a hostname resolving to a different
address on the second lookup (DNS rebinding); IPv6 and IPv4-mapped representations of the
same address; DNS names that resolve to loopback.

**Controls**

- Scope is an allowlist and is the *only* thing that grants permission to send a request.
  Scope entries carry scheme, host, port and optional path prefix, so a grant for
  `https://api.example.com` does not authorize `http://api.example.com:9200`.
  **TESTED** (`scope.TestHostAllowlistIsExact`, `TestPortIsPartOfScope`,
  `TestPathPrefixConfinesGrant`).
- The URL is evaluated **before any name resolution**, so an out-of-scope host generates no
  DNS traffic — resolving a host in order to reject it would itself be a callback to
  attacker-controlled infrastructure. **TESTED** (`httpx.TestOutOfScopeURLSendsNoPacket`,
  which fails if the resolver or the dialer is called at all).
- Every **resolved address** is evaluated at dial time and the connection is made to a
  literal checked IP, closing the TOCTOU window that makes DNS rebinding work. If *any*
  returned address is forbidden the whole dial is refused, because a rebinding target
  returns both a permitted and a forbidden address. **TESTED**
  (`httpx.TestRebindingResolverIsRefused`, `TestAnyForbiddenAddressRefusesTheDial`).
- Three transport defaults that would silently defeat the above are overridden:
  `Proxy` is nil (`ProxyFromEnvironment` would hand the dialer the proxy's address while
  the real target travels inside CONNECT), keep-alives are disabled (pooled connections
  skip the dialer entirely), and Happy Eyeballs is disabled (dual-stack racing can connect
  to an address that was not evaluated). **IMPLEMENTED** (`internal/httpx`).
- Redirects are **never followed automatically**; a redirect is captured as evidence and
  its target must pass scope evaluation as a fresh request. **TESTED**
  (`httpx.TestRedirectsAreNotFollowed`, which asserts the redirect target's request
  counter is zero).
- Hostnames are normalised — lowercased, trailing dot stripped, IDN converted to ASCII —
  before comparison. **TESTED** (`scope.TestHostAllowlistIsExact`).
- Private, loopback, link-local, unique-local, multicast and unspecified ranges are denied
  unless the operator opts in, which local assessment does deliberately rather than
  accidentally. **TESTED** (`scope.TestDefaultDeniesLoopback`).
- Out-of-scope hosts discovered during an assessment are **recorded, never contacted**.
  **TESTED** (`scope.TestOutOfScopeHostsAreRecordedNotContacted`).
- The convenience that enables private addressing for a loopback target parses the host as
  an **address**, never as a string prefix. A prefix test would treat an
  attacker-registrable name such as `127.0.0.1.nip.io` as loopback and silently permit
  private addressing for the whole run. **TESTED**
  (`cli.TestLoopbackDetectionUsesAddressesNotPrefixes`).
- A connection whose remote address cannot be verified is **refused**, not accepted.
  **IMPLEMENTED**.
- Callback/OAST behaviour requires explicit configuration. **DESIGNED**.

**Path prefixes (S0).** A scope entry's `pathPrefix` confines by whole segments —
`/api` grants `/api/x`, not `/apiv2` — and a path carrying a dot segment or an
encoded separator is never inside a prefix, raw or percent-encoded, because the
server normalises `/api/%2e%2e/admin` to `/admin`. **TESTED**
(`scope.TestPathPrefixCannotBeEscaped`).

### T-02 The scanner is used as an SSRF weapon

A hostile or careless target can attempt to make our privileged network position useful
to it — we may sit inside a VPN, a CI runner, or a cluster with access to metadata
endpoints.

**Controls.** Same as T-01, plus a deny list applied *after* IPv4-mapped unwrapping and
zone-identifier stripping, covering cloud metadata for AWS/Azure/GCP, Alibaba and Oracle;
link-local; and the transition ranges that embed IPv4 addresses and can therefore reach
metadata by another spelling — NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo
`2001::/32` — plus CGNAT and the unspecified addresses that route to loopback on Linux.
These stay denied **even when private addressing is enabled**, which is the normal
configuration for local assessment. **TESTED**
(`scope.TestMetadataDeniedEvenWithPrivateAllowed`, `TestIPv4MappedIPv6IsUnmapped`,
`TestTransitionRangesDenied`, `TestUnspecifiedAddressDenied`).

### T-03 Hostile responses exhaust or corrupt the scanner

An infinite body, a decompression bomb, a multi-gigabyte header set, a slow-loris trickle,
or a redirect cycle.

**Controls.** Bounded response reading with an explicit byte cap that never trusts
`Content-Length`, recording truncation so a report cannot imply the body was complete;
per-request timeouts honouring context cancellation; capped response header bytes.
**TESTED** (`httpx.TestBodyIsBounded` against a server that streams indefinitely,
`TestContextCancellationIsHonoured`).

Request pacing also protects the *target*: a scanner that trips a WAF sees every later
response as a denial and reports a falsely clean result. Pacing is enforced in the HTTP
client, not in the assessment loop — a single check issues several requests, so limiting
once per check exceeded the configured rate by that factor. **IMPLEMENTED**
(`internal/httpx`).

### T-04 Command injection through configuration or target-controlled data

Environment lifecycle commands, adapter probes and scanner invocations all execute
processes. A target-controlled string reaching a shell would be catastrophic.

**Controls**

- **No shell, ever.** Process execution will use explicit argument vectors
  (`exec.CommandContext` with `argv`), never a shell string. **DESIGNED** — Sulayi
  currently executes no subprocesses at all, which is why this is not marked implemented.
- YAML decoding is hardened against the non-shell execution paths: the decoder is never
  given `ReferenceFiles` or `ReferenceDirs`, which would let a configuration file pull
  anchor definitions from arbitrary filesystem paths, and input is size-capped because
  alias expansion is an exponential-blowup denial of service. **TESTED**
  (`config.TestOversizedInputIsRefused`, `TestUnknownFieldsAreRejected`).
- "No shell" is not the whole of "no untrusted execution or file access": see T-08 for the
  filesystem paths and T-05 for `$ref` resolution.
- Target-controlled data is **never** placed in an argument vector position that a tool
  interprets as a flag; values are passed via files or after `--` where the tool supports
  it.
- Environment lifecycle commands come only from configuration, are `argv` arrays rather
  than strings, and are **opt-in per run**. **DESIGNED**.

### T-05 Malicious scanner or adapter output

Scanner output is parsed by us. A hostile target can influence it (a reflected payload
becomes a finding title). Output may be enormous, malformed, or contain terminal escape
sequences that rewrite the operator's terminal.

**Controls.** For the untrusted input that Sulayi *does* parse today — OpenAPI documents,
which for one reference application are fetched from the target itself:

- **External `$ref` is refused outright**, not resolved. A hostile document containing
  `$ref: "file:///etc/passwd"` or `$ref: "http://169.254.169.254/..."` would otherwise
  produce arbitrary local file read and SSRF through the *parser*, entirely outside the
  scope-enforced HTTP client. Each refused reference is recorded as a coverage gap rather
  than silently dropped. **TESTED** (`openapi.TestExternalRefsAreRefusedAndRecorded`).
- Local pointer resolution is depth-bounded, defeating reference cycles. **IMPLEMENTED**.
- Document size is capped — but a size cap does **not** bound expansion cost. YAML alias
  expansion is exponential, so a 426-byte document of nested anchors expands to hundreds
  of millions of nodes and wedges the process indefinitely. Alias use is therefore
  counted and refused above a low threshold before the parser is invoked, the
  post-expansion size is checked, and conversion runs under a wall-clock bound. A
  legitimate specification uses `$ref`, not YAML anchors. **TESTED**
  (`openapi.TestOversizedDocumentIsRefused`, `openapi.TestYAMLAliasBombIsRefused`).
- The number of declared operations is capped, so one document cannot turn a bounded
  assessment into an unbounded one. **IMPLEMENTED**.
- Parser errors are **never propagated verbatim**: the YAML parser echoes a snippet of
  the offending document, control characters and ANSI escapes included, which would
  otherwise reach the operator's terminal through the CLI's error path.
  **IMPLEMENTED**.
- Swagger 2.0 is **refused** rather than half-parsed, because a partially understood
  document produces a confidently wrong attack surface. **TESTED**
  (`openapi.TestSwagger2IsRefused`).
- All target-controlled strings have C0/C1 control characters stripped and are
  length-bounded before they can reach a terminal or a report, so a hostile document
  cannot rewrite an operator's screen with ANSI escapes. **TESTED**
  (`openapi.TestControlCharactersAreStripped`).
- The JSON Schema validator used in tests is given no remote loader, so a remote `$ref`
  fails closed rather than reaching the network. **IMPLEMENTED**.

For scanner output specifically: **DESIGNED** (no engine integrations exist yet).

### T-06 Evidence contains secrets, credentials and personal data

The most likely real-world harm from this tool is not a broken scan — it is a captured
`Authorization` header committed to a repository or pasted into an issue.

**Controls**

- Redaction is applied **at capture time**, not at render time, so a secret never reaches
  disk. **TESTED** (`httpx.TestSensitiveHeadersAreRedactedInEvidence`).
- Sensitive headers are replaced entirely, case-insensitively. **TESTED**
  (`redact.TestSensitiveHeadersAreReplacedEntirely`).
- Credentials **learned at runtime** — a session cookie or refresh token the target issues
  mid-run — are added to the deny-list and redacted from every later capture. A static
  deny-list alone would miss exactly the credentials an assessment causes to exist.
  **TESTED** (`redact.TestRuntimeCredentialsAreLearned`,
  `TestBearerTokenValueIsLearnedWithoutScheme`).
- Registered secrets are matched in base64 and percent-encoded forms as well as raw.
  **TESTED** (`redact.TestEncodedFormsAreRedacted`).
- Credentials are learned from every substantial whitespace-delimited field of an
  authentication header, not by guessing where a scheme prefix ends. A fixed prefix
  heuristic misses long schemes such as `SharedAccessSignature`, leaving the token
  unregistered. **TESTED** (`redact.TestLongAuthSchemesAreLearned`).
- A truncated body discards a trailing margin, because redaction runs after capture and a
  secret straddling the cut would survive as a prefix that no longer matches any pattern —
  a JWT sliced mid-signature is still readable base64. **IMPLEMENTED** (`internal/httpx`).
- High-signal shapes (JWTs, vendor key prefixes, PEM private-key headers) are redacted
  without registration. **TESTED**
  (`redact.TestHighSignalPatternsRedactedWithoutRegistration`).
- URLs have userinfo and sensitive query parameters redacted, and **error strings have
  query strings stripped** — Go's `*url.Error` renders the full URL, so any transport
  failure would otherwise write `?api_key=…` into evidence. **TESTED**
  (`redact.TestErrorStringsHaveQueryStringsStripped`,
  `httpx.TestQuerySecretsRedactedInCapturedURL`).
- Fingerprints are **HMAC-SHA256 under a per-run key**, truncated, with the key stored in
  the run directory and never in a report. Values below a length threshold are not
  fingerprinted at all, because a bare hash of a PIN, a six-digit code or a numeric
  identifier is brute-forceable by anyone holding the report — and a stable keyless hash
  would correlate the same secret across reports and customers. **TESTED**
  (`redact.TestShortValuesAreNotFingerprinted`,
  `TestFingerprintIsStableWithinRunAndDiffersAcrossRuns`).
- Run directories are `0700`, files `0600`, on platforms that enforce them. **TESTED**
  (`store.TestRunDirectoryIsOwnerOnly`). On Windows `os.Chmod` only toggles a read-only
  attribute, so the CLI **warns** rather than implying a protection that does not exist.
- Configuration is not persisted into the run directory, so operator credentials cannot
  reach it. `.gitignore` excludes `.sulayi/`, and `meta.json` warns whoever finds the
  directory later. **TESTED** (`store.TestMetaIsWritten`).
- Un-redacted capture is not available. If it is ever added it must be per-run, explicit,
  and loudly recorded in the report. **PLANNED**.

**Errors (S0).** An error returned by the HTTP client is redacted before it
leaves, because callers put its text into ledger details and the report, and Go's
URL errors render the full request URL. Its meaning survives — refusals, budget
and cancellation are still detectable — but for a URL error the chain continues
from its cause, so the raw URL is not reachable by unwrapping either. **TESTED**
(`httpx.TestErrorsLeaveDoRedacted`).

**Cookies (S0).** From a `Set-Cookie` header only the cookie's own value is learned
as a secret, quoted or not; its attributes (domain, path, expiry) are not, because
learning them blanked the target's hostname out of every later exchange. Values
shorter than four characters are still not learned, deliberately: registering a
one-character value would redact that character everywhere. A session cookie that
short is a residual risk. **TESTED** (`redact.TestSetCookieLearnsOnlyTheCookieValue`).

### T-07 Report and evidence leakage

Reports are the artefact most likely to be shared, attached to a ticket, or uploaded to
CI. They inherit every secret the evidence holds.

**Controls.** Reports render already-redacted evidence; there is no un-redacted path.
Output paths are validated and confined, and emitted files are `0600`. JSON output escapes
HTML-significant characters. **IMPLEMENTED** for JSON and SARIF.

A future HTML report must escape all target-controlled content — an XSS in our own report,
delivered by the application we were assessing, would be a real vulnerability. **PLANNED**.

### T-08 Path traversal, symlinks and unsafe temporary files

Target-controlled names (an OpenAPI `operationId`, a scanner rule id, a hostname) must
never become a filesystem path.

**Controls.** Evidence is addressed by SHA-256 of its redacted content, never by a
target-supplied name. Run identifiers are validated against a strict character set rather
than trusted. Paths are cleaned and checked for containment lexically, the parent is created, and only
then is containment re-checked against the symlink-resolved parent — checking before
creating would skip the symlink gate entirely for any directory that does not yet exist.
A resolution failure is a refusal, not a pass. Writes go to
a temporary file that is `chmod`-ed before an atomic rename, so the destination never
exists with permissive modes and a reader never observes a partial file. **TESTED**
(`store.TestPathTraversalIsRefused`, `TestRunIDIsValidated`,
`TestSymlinkedParentIsRefused`, `TestWritesAreAtomic`,
`TestEvidenceIsContentAddressedAndIdempotent`).

### T-09 Compromised or hostile scanner templates and rules

Nuclei's `code` and `javascript` protocols execute arbitrary code **on the scanning
host**. Unsigned templates of other protocols still load with only a warning and can SSRF
from our network position.

**Controls (all DESIGNED — no scanner integration exists yet).** Never pass `-code`; pass
`-disable-unsigned-templates`; vendor, pin and checksum templates rather than
auto-updating; `-restrict-local-network-access` on and `-allow-local-file-access` off;
self-host or disable Interactsh, whose defaults leak target names to public `oast.*`
servers; override internet-scale rate defaults. Recorded here so the integration cannot be
written without them.

### T-10 Supply-chain compromise of our own dependencies

We are a security tool; a backdoored dependency is a supply-chain attack on everyone who
runs us.

**Controls.** Six direct dependencies, each justified in `docs/dependencies.md`, with an
ADR required to add another. `go.sum` and the Go checksum database. `govulncheck` in CI
per-change and weekly, reachability-based rather than version-matching. CI actions pinned
by commit SHA, not by tag. No documented workflow pipes a network response into a shell.
No engine is bundled and nothing is downloaded at runtime. **IMPLEMENTED**.

### T-11 Unsafe adapter and plugin execution

Adapters are out-of-process probes that may run inside the target's runtime, and a
repository under assessment is untrusted.

**Controls.** Adapters are opt-in per run, never auto-discovered from the target
repository, never executed merely because a repository contains a manifest, and are
invoked with explicit `argv`. Adapter output is parsed with the same hostility as scanner
output, is size-capped, and is schema-validated before it can influence a plan.
**DESIGNED**.

### T-12 Destructive or state-changing tests running accidentally

The framework sends requests that change data, and its default profile does.

**Controls.** Three strictly ordered profiles: `safe` < `standard` (default) <
`aggressive` ([ADR-0019](../adr/0019-safety-enforced-at-the-http-client.md)).

- **The decision is made in `httpx.Do`, from the request itself.** Every request
  passes through it, so no check can send a state-changing request around it, and
  it never accepts a check's description of what it is sending. A request is
  state-changing when its method is not read-only or when it matches an operation
  the operator listed in `assessment.stateChangingOperations` (`GET /logout`).
  **TESTED** (`httpx.TestSafeProfileRefusesEveryStateChangingRequest`,
  `httpx.TestConfiguredStateChangingTemplateMatchesConcretePaths`).
- **`standard` permits only exact registered fixture requests.** The planner
  registers, for each fixture declared `disposable`, the exact method and URL
  (path and query) it will send and the body fields that fixture may change, then
  seals the registry before anything executes. Another record, another query,
  another method, an unregistered field, an empty or non-JSON body, a dot or
  encoded-separator segment, and every `DELETE` are refused before anything is
  sent. **TESTED** (`httpx.TestStandardProfilePermitsOnlyExactRegisteredFixtureRequests`,
  `httpx.TestGrantsAreClosedAndNarrow`, `evals.TestS0_StandardProfileWritesOnlyADisposableFixture`,
  `evals.TestM2_MutationOfANonDisposableFixtureRequiresAggressive`).
- **A client with no guard fails closed** — it behaves as `safe`. **TESTED**
  (`httpx.TestNilGuardFailsClosed`).
- The planner applies the same rules first, so a refusal at the client is a
  backstop rather than the plan; work exceeding the profile is recorded as blocked
  with a reason. Impact is computed per **(check, operation)**, never per check.
  **TESTED** (`model.TestProfileGateFailsClosed`, `model.TestUnsafeMethodsRequireAggressive`,
  `engine.TestUnsafeMethodsAreBlockedBelowIntrusive`, `TestAuthRoutesAreExcludedByDefault`).
- **`aggressive` is authorized by three things, all required:** `target.disposable:
  true` in the configuration; an interactive confirmation in which the operator
  types the target's exact origin (or `--yes` where there is no terminal, which
  replaces only the prompt); and scope entries that each name one exact origin.
  Anything less stops the run before a request is sent. **TESTED**
  (`config.TestAggressiveProfileRequiresDisposableTarget`,
  `cli.TestAggressiveProfileIsRefusedUnlessFullyAuthorized`,
  `cli.TestAggressiveProfileRunsOnceConfirmed`).
- **The one exception: an identity's configured login.** It is permitted under
  every profile, including `safe`, and only as the exact method and URL in the
  configuration, carrying only the configured body fields, and only when sent
  through the HTTP client's dedicated authentication path — whose marker is
  unexported, so no check can claim it. The identical POST sent the way checks
  send requests is refused. Scope, origin binding, the budget, pacing and the
  request log all still apply. **TESTED** (`httpx.TestConfiguredLoginIsPermittedUnderSafe`,
  `httpx.TestAuthenticationExceptionIsNotABypass`,
  `httpx.TestAuthenticationRequestsStillPassEveryOtherGate`).
- Pre-Sulayi profile names and `authorizeIntrusive` are refused with a migration
  message, never translated. **TESTED** (`config.TestLegacyProfileNamesAreRefused`,
  `config.TestLegacyAuthorizeIntrusiveIsRefused`).

**Limitation.** A read-only method is assumed not to change state unless the
operator lists it. An application whose `GET` endpoints mutate data is protected
only as far as `stateChangingOperations` names them; nothing infers it.

### T-13 Concurrent assessments interfere

**Controls.** Each run owns a directory keyed by a time-ordered id with a random suffix,
so two runs started in the same second cannot collide. The coverage ledger, the redactor
and the scope policy's record of out-of-scope hosts are all mutex-guarded — the scope
policy is consulted from every assessment goroutine, so an unsynchronised map there is a
process-killing concurrent write rather than a data-quality problem. Evidence writes are
atomic and idempotent, and every output slice is sorted before rendering so concurrent
execution cannot change the bytes produced. **TESTED** under `-race`
(`scope.TestConcurrentCheckURLIsSafe`, `store.TestConcurrentEvidenceWritesAreSafe`,
`engine.TestResultOrderingIsDeterministic`, `redact.TestConcurrentUseIsSafe`).

### T-14 Prompt injection when AI is eventually introduced

Source comments, HTTP responses, OpenAPI descriptions, database values and scanner output
are all attacker-controlled and would all be candidate model input.

**Controls (PLANNED — no AI exists in this repository).** Target-controlled content is
passed as clearly delimited data, never as instruction. Model output may only *propose* a
hypothesis; it can never mark a finding confirmed. Every AI-derived fact carries
`inferred` provenance and requires deterministic verification before it can change a
finding's state. This constraint is enforced by the finding model itself (ADR-0006), not
by convention.

### T-15 False assurance — the framework's own most likely harm

A clean report that hides the fact that nothing meaningful was tested is the failure mode
most likely to hurt a real user, and the one this project was created to fix.

**Controls.**

- Every report opens with an `assurance` block whose statement is written to survive being
  quoted alone, and which states plainly that the run does not establish the target is
  secure. **TESTED** (`report.TestBuildCountsAndAssurance`).
- A run that executed **no** checks says it "establishes nothing", returns a distinct exit
  code (3, not 0), and reports `executionSuccessful: false` in SARIF. **TESTED**
  (`report.TestZeroExecutedChecksStatementIsUnambiguous`,
  `TestSARIFInvocationReflectsExecution`, `cli.TestAllBlockedRunDoesNotReportSuccess`).
- Every ledger row carries a machine-readable cause; consumers are told to treat an
  unrecognised cause as blocked rather than as success.
- The ledger discloses that its denominator is the **specification**, so undocumented
  routes are not merely untested but invisible — otherwise coverage would be measured
  against a surface supplied by the thing being audited.
- `classesNotAssessed` names the weakness classes nothing in the run examined, so "no
  findings" cannot be read as "nothing wrong". **TESTED**
  (`engine.TestClassesNotAssessedIsPopulated`).
- Suspected and confirmed findings are counted separately and never conflated — but both
  can fail a build. The shipped check cannot reach `confirmed` without credentials, so
  gating only on confirmed findings would exit zero on a real authentication bypass and
  silently green-light a pipeline. **TESTED**
  (`cli.TestSuspectedHighFindingFailsThePolicy`).
- Cancelling a run does not make it look cleaner: every planned item that never started
  still gets a blocked ledger row attributing its absence to cancellation. **TESTED**
  (`engine.TestCancelledJobsStillAppearInTheLedger`).
- A discriminator that could not run is recorded as **not passed** and named in the
  finding's `unavailable` list, rather than reported as a verification step that
  succeeded. Confidence drops accordingly. **IMPLEMENTED** (`internal/check`).
- CI rejects any user-facing text that asserts a target's security
  (`scripts/verify-no-assurance-claims.py`).

---

### T-16 Operator credentials supplied to authenticate as an identity

M1 introduced the first credentials Sulayi holds on the operator's behalf. These
are worse than the credentials it observes: an observed session cookie belongs to a test
account created for the run, while a configured credential is one the operator chose to
hand over, often with real privilege.

**Configuration cannot contain a credential at all.**

- `sulayi.yaml` has no field that accepts a credential value. Only a *reference* —
  `credential.env` or `credential.file` — is accepted, and strict decoding rejects anything
  else, so a `token:` key added by a hopeful contributor is a loud parse error rather than a
  committed secret. **TESTED** (`config.TestConfigurationCannotCarryACredentialValue`,
  `TestIdentityConfigurationIsValidated`).
- The same absence is asserted against the JSON Schema, so editor completion never offers a
  place to type one. **TESTED** (`config.TestSchemaAndParserAgreeOnRejection`).
- No CLI flag accepts a secret. Process listings are world-readable on most systems and
  shell history outlives the run. **TESTED** (`cli.TestNoFlagAcceptsARawSecret`).

**A resolved credential cannot reach output.**

- A credential lives in a `Secret`, whose `String`, `GoString` and `MarshalJSON` render a
  placeholder. Reading the value requires `Expose`, which is called from one place. This
  closes `%v`, `%+v`, `%#v`, `%s`, structured logging, error formatting and whole-struct
  JSON marshalling in a single move, rather than relying on every future call site to
  remember. **TESTED** (`identity.TestSecretNeverRendersItsValue`,
  `TestSecretRefusesToUnmarshal`).
- Resolution failures name the *location* and never the contents, so the error reporting a
  misconfigured credential does not become the leak. **TESTED**
  (`identity.TestResolveErrorsNeverContainTheCredential`).
- Credentials are registered with the redactor **before the first request is possible**,
  along with their on-the-wire form, so a target that reflects `Bearer <token>` in a body
  cannot defeat redaction by including the scheme. **TESTED**
  (`identity.TestResolveRegistersCredentialsWithTheRedactor`).
- A bespoke API-key header is registered by **name** as well as by value, so a target
  echoing only part of the credential cannot leave the rest readable. Blanket-redacting
  every unrecognised header would destroy the evidence the report exists to carry, so
  exactly the headers the operator declared as credentials are registered. **TESTED**
  (`identity.TestResolveRegistersCustomCredentialHeader`).
- The end-to-end guarantee is asserted against a hostile fixture that reflects the
  credential in a header, a body and a `Location`, after which every byte of the run
  directory — evidence, JSON, SARIF, metadata — is searched for it. Unit-testing the
  redactor proves the function works, not that every writer goes through it. **TESTED**
  (`evals.TestM1_CredentialNeverReachesDisk`).
- `doctor` reports whether a credential is *available* and never what it is, because its
  output is pasted into issues and CI logs. **TESTED**
  (`cli.TestDoctorReportsIdentitiesWithoutValues`).

**A credential cannot leave the authorized origin.**

- Redirects are never followed, so a `Location` chosen by the target cannot replay a
  credential anywhere. **TESTED** (`evals.TestM1_MaliciousRedirectNeverForwardsTheCredential`,
  which asserts that the off-origin host received *zero* requests).
- Authenticated requests traverse the same client as anonymous ones, so the URL gate and
  the dial-time address gate of T-01 — including the DNS-rebinding protection and the cloud
  metadata denial — apply unchanged. There is no authenticated code path that bypasses
  scope. **TESTED** (`evals.TestM1_OffOriginRedirectTargetIsOutOfScope`).
- Query-string API keys are **deliberately not supported**. A credential in a URL reaches
  the cache-busting logic, reproduction strings, transport error text and every
  intermediary's access log. The redactor covers known parameter names, but the exposure is
  broad and the benefit small, so the mechanism is refused rather than mitigated.

**Identities cannot contaminate one another.**

- `Control.Headers` allocates a fresh map per call and the HTTP client holds no per-request
  state, so two identities executing concurrently cannot present each other's credential.
  **TESTED** (`identity.TestConcurrentIdentitiesDoNotContaminate` asserts on the wire that
  every request carried the right token, `TestHeadersAreNotShared`), and the suite runs
  under `-race`.
- The check's anonymous probes and baseline probes carry no credential, which is what makes
  the anonymous/authenticated comparison meaningful at all. **TESTED**
  (`evals.TestM1_AnonymousProbesCarryNoCredential`).

**Residual risk, stated rather than mitigated.**

- A credential is a Go string in process memory for the run's duration. It is not locked,
  not zeroed on exit, and would appear in a core dump. Fixing this properly needs
  mlock-style handling that Go does not offer portably.
- A Go panic prints a goroutine traceback. Struct fields are rendered as words rather than
  as string contents, so a credential is not expected to appear, but this is a property of
  the runtime rather than a control this project enforces.
- Environment variables are readable by other processes of the same user, and on Linux via
  `/proc/<pid>/environ`. This is the standard secret-delivery mechanism for CI and is
  accepted as such; the file source exists for operators who prefer a mounted secret.
- A credential file's permissions are the operator's to set. A file readable by other users
  produces a **warning** rather than a refusal, because refusing to run because a CI system
  mounted a secret group-readable would be an obstruction.
- Future subprocess engines (M4) must be given a **minimal explicit environment**, or every
  configured credential would be inherited by a third-party binary. This is already recorded
  as an M4 acceptance criterion and is restated here because M1 is what makes it dangerous.

**Credentials are bound to their origin (S0).** Scope may name several hosts; that
authorizes contacting them, not handing each of them every identity's credential.
An identity's request to any origin other than its target's is refused in
`httpx.Do` before anything is sent, and recorded in the request log. **TESTED**
(`identity.TestCredentialIsNeverSentToAnotherInScopeOrigin`).

### T-17 Resource fixtures, cross-owner probing and mutation

M2 introduced the first requests Sulayi builds from operator-supplied
*data* rather than from a specification, and the first requests that deliberately
change somebody's records. Both are new classes of harm.

**A fixture value must not be able to change the shape of a URL.**

- Values are refused at load if they contain a path separator, a backslash, a
  query or fragment delimiter, an authority delimiter, a percent sign, a parent
  directory reference or a control character. Refused rather than escaped: the
  intent of `orderId: ../../admin` is unambiguous and encoding it silently would
  hide a mistake worth surfacing. **TESTED**
  (`resource.TestBindRefusesValuesThatCouldChangeTheURL`, 14 cases).
- Binding works from the parsed parameter list, not by substituting into the path
  text. Generic replacement would rewrite any braced text it found and give no way
  to distinguish a filled operation from an unfilled one. An unfilled template
  segment is an error, never a literal `{name}` on the wire. **TESTED**
  (`resource.TestBindRefusesAnUnfilledTemplateSegment`).
- Each value is percent-encoded exactly once and the finished URL is re-parsed and
  checked: same scheme, same host, no userinfo, no query or fragment, and the base
  path still a prefix. Encoding is the mechanism; the origin check is the control.
  **TESTED** (`resource.TestBindAcceptsRealIdentifierShapes`,
  `TestBindDoesNotDoubleEncode`, `evals.TestM2_FixtureValueCannotEscapeScope`,
  which asserts the off-origin host received zero requests).
- Double-encoding is a correctness control as well as a safety one: a
  double-encoded identifier addresses a resource that does not exist, and the
  resulting 404 would be read as a denial.

**Cross-owner probing must not manufacture a result.**

- The owner control, both identities' liveness, and the owner re-check are all
  required before a denial is recorded as verified. Each closes a way for an
  untested boundary to look enforced. **TESTED**
  (`evals.TestM2_OwnerCannotReachFixtureIsBlocked`,
  `TestM2_DeadAttackerIdentityIsBlockedNotEnforcement`,
  `TestM2_DeadOwnerIdentityIsBlocked`,
  `TestM2_ResourceDisappearingMidTestIsBlocked`).
- **TOCTOU is handled by re-checking, not by locking.** Nothing here can stop a
  resource changing on a live application; what it can do is notice. The window
  between the owner control and the non-owner probe is bounded by doing them
  back to back, and the re-check afterwards turns an undetected race into a
  blocked row.
- Units touching one fixture are serialised, so two of this tool's own units
  cannot interleave their reads and writes and attribute each other's effects.
  Different fixtures still run in parallel. **TESTED**
  (`evals.TestM2_IdentitiesDoNotContaminateEachOther`, which asserts on the wire
  that no request carried the wrong or a mixed credential, under `-race`).
- Two identities in one run double the chance of credential contamination. Header
  maps are rebuilt per request and never shared, which M1 established and M2
  exercises far harder. **TESTED** (`identity.TestHeadersAreNotShared`,
  `evals.TestM2_NeitherCredentialReachesDisk`).

**Mutation must be consented to, verified, and reported honestly.**

- A cross-owner write is state-changing. Under `standard` it is sent only when the
  fixture is declared `disposable`, and only as the exact registered request (see
  T-12); otherwise it needs `aggressive`. The fixture must additionally carry a
  `mutation` block. **TESTED** (`evals.TestM2_MutationOfANonDisposableFixtureRequiresAggressive`,
  which asserts zero write requests were sent).
- A write with no readable operation to observe it is refused rather than sent:
  an unverifiable write is all risk and no evidence. **TESTED**
  (`evals.TestM2_MutationWithoutAReadableOperationIsBlocked`, asserting zero
  writes).
- Confirmation requires the owner's own view to change, field by field, and only
  for fields that did not already hold the written value. **TESTED**
  (`check.TestMutationApplied`, `evals.TestM2_FakeSuccessMutation_IsNotConfirmed`).
- Restoration is attempted as the owner and **verified by re-reading**. When it
  fails the run records a tool failure naming the fixture, because a resource left
  modified is somebody's data still being wrong. It is never silent. **TESTED**
  (`evals.TestM2_VulnerableMutation_IsConfirmedByOwnerSideObservation`).

**Resource values may themselves be sensitive.** A fixture value is an identifier
the operator chose, and it travels in a URL, which is captured in evidence and
rendered in reproduction steps. The existing URL redaction applies, but an
identifier that is itself a secret — a share token, a signed link — is not
recognised as one. Prefer fixtures whose identifiers are opaque row ids.

**Residual risk, stated rather than mitigated.**

- **Mutation is not transactional.** Restoration is best-effort by construction:
  the application may reject the restoring write, may have recomputed dependent
  fields, or may have fired side effects — an email, a webhook, an audit row —
  that no restoration can undo. Cross-owner writes belong in a disposable
  environment, and the intrusive profile exists to make that a decision rather
  than an accident.
- **A confirmed cross-owner read means the fixture's data reached another
  identity during the assessment.** That is the finding, and it is also a real
  disclosure to a real account. Use accounts created for testing.
- **Ownership is asserted, not proven.** A configured fixture is trusted to be
  owned by the identity that claims it. If the operator is wrong, the owner
  control fails and the row blocks — but a fixture owned by *both* identities
  would report a false positive, which is why `crossOwnerAccess: allowed` exists
  and why the expectation is required.
- **Identifier collision across identities.** If A and B each own a resource with
  the same identifier under different scopes, a non-owner probe may address B's
  own record. The resource-identity discriminator catches the common case by
  comparing values at matching paths; it is not a proof against every scheme.

### T-18 Framework adapters and the repository they inspect

M3 introduced two new trust boundaries at once: a third-party executable Sulayi
runs, and a source repository it reads. Both are untrusted, and the repository
should be assumed to be actively hostile — it is, after all, the thing being
audited.

**The inspected repository is data, never code.**

- The shipped adapters read files and execute nothing. That is the entire
  security argument for the static tier and it is kept literally true.
- Framework-native introspection *does* execute the target's code, so it is
  refused unless the operator sets `adapters.trust: execute-target-code`.
  Evidence for why this matters: `artisan` boots every service provider
  (`laravel-api/artisan:9-13`), and `nestjs-api/src/main.ts` runs
  `startTelemetry()` at import time, patching `http`, `pg` and `ioredis`.
  **TESTED** (`adapter.TestTargetCodeExecutionRequiresExplicitTrust`).
- **Dependencies are never installed.** `composer install` on that same
  repository runs `@php artisan package:discover` from `post-autoload-dump`, so
  installing is itself booting. No adapter runs a project script, a package
  manager or a Makefile.
- Adapters are **opt-in and never discovered**. A manifest in a checkout cannot
  cause a program to run.
- Walking is bounded: symlinks are not followed, `vendor/` and `node_modules/`
  are skipped, directory depth, file count, file size and line length are all
  capped, and invalid UTF-8 is repaired rather than propagated.

**The adapter process is contained.**

- Explicit executable, explicit argument vector, no shell anywhere.
- **The environment is built from nothing.** A CI environment holds cloud
  credentials, registry tokens and this tool's own identity credentials; none of
  it reaches an adapter. An operator may forward a named variable, and this
  tool's identity credentials are refused even then. `PATH` is deliberately
  absent, because an adapter is executed by explicit path. **TESTED**
  (`adapter.TestAdapterEnvironmentIsBuiltFromNothing`, which asserts on the
  adapter's own view of its environment).
- Timeout, `WaitDelay`, and a process group so a cancelled adapter's children
  are killed rather than orphaned. **TESTED**
  (`adapter.TestAdapterTimeoutIsEnforced`, `TestAdapterRespectsCancellation`).
- stdout and stderr are bounded and **drained concurrently**: reading one to
  completion first deadlocks as soon as the other fills, which a hostile adapter
  can arrange deliberately. **TESTED** (`adapter.TestStderrIsBounded`,
  `TestBothPipesAreDrainedConcurrently`).
- Truncated stdout is **refused rather than parsed**. A partial document reports
  fewer controls than the adapter found.

**Adapter output is hostile input.**

- Size-bounded before parsing, version-checked before interpretation, strictly
  decoded, trailing content refused. An unknown contract version is refused
  rather than interpreted, because a later contract may give an existing field a
  new meaning. **TESTED** (`adapter.TestDocumentsAreRejectedWholesale`).
- Operation paths carrying a scheme, authority, query, fragment or
  parent-directory reference are dropped: a fact about another origin must not
  enter this target's oracle. Evidence paths that are absolute, drive-lettered
  or escaping are dropped rather than repaired. **TESTED**
  (`adapter.TestIndividualFactsAreDroppedAndCounted`).
- Every string is sanitized and bounded. Adapter strings reach terminals, JSON,
  SARIF and — the roadmap says so explicitly — future model prompts, so control
  characters that rewrite a terminal and unbounded lengths that flood one are
  removed at the boundary. **TESTED** (`adapter.TestHostileStringsAreSanitized`).
- **Provenance cannot be spoofed directly**: there is no confidence field to
  set. An adapter declares a *method* and the core grades it, so lying requires
  misreporting what was done, which appears in the report. **TESTED**
  (`adapter.TestProvenanceIsDerivedFromMethodNotClaimed`,
  `TestSchemaHasNoProvenanceField`).
- An adapter that **misnames itself** is refused, so a document cannot be
  attributed to an adapter that did not produce it.
- An adapter that **contradicts itself** about one subject has both assertions
  withdrawn. Keeping the first makes the outcome depend on document order;
  keeping the last lets a malicious adapter overwrite by appending. **TESTED**
  (`adapter.TestContradictoryFactsWithdrawBoth`).

**A failure must never look like an absence.**

- A crashed, timed-out, malformed or unauthorised adapter contributes nothing
  and leaves the oracle exactly as it was, with a stated limitation saying "this
  does not mean the application has no controls; it means none were read".
  **TESTED** (`adapter.TestCollectReportsFailuresAsLimitations`,
  `evals.TestM3_AdapterFailureDoesNotImproveTheReport`).
- Conflicting sources withdraw the expectation rather than picking a winner, so
  a hostile adapter cannot *remove* an operation from testing by asserting the
  opposite of the specification — it can only make the disagreement visible.

**Residual risk, stated rather than mitigated.**

- **A lexical adapter can be wrong.** Unusual source will be misread. Every fact
  carries a file and line so a human can check, and a wrong fact yields a
  *suspected* finding somebody reads rather than a confirmed one. It cannot
  produce a confirmed finding on its own: confirmation needs runtime evidence.
- **An adapter binary is trusted to the extent the operator trusts it.** Sulayi
  bounds what it can consume and what environment it runs in; it does not
  sandbox the process. An adapter is chosen deliberately, like a compiler.
- **Adapter binary substitution is not detected.** There is no signature or
  checksum on the executable. An attacker who can replace a binary on the
  operator's machine already has the operator's machine.
- **Windows has no process groups** in the POSIX sense, so a grandchild spawned
  by an adapter may outlive a cancellation there. The adapter itself is still
  killed.
- **Source locations are paths from the inspected repository.** They are
  validated as relative and non-escaping, and they do reach reports — a report
  therefore discloses the layout of the inspected source, though never its
  contents.
- **Facts are the application's expectations, not its behaviour.** An adapter
  saying an operation is protected is not evidence that it is. Treating it as
  such is the single most likely way this feature could mislead, which is why
  the report's adapter section says so in words and why no extraction method
  maps to observed or verified provenance.

### T-19 External scanning engines

M4 runs three third-party programs — Nuclei, ZAP, Semgrep/opengrep — against a
target somebody operates, from a machine holding this tool's credentials. Each is
untrusted in three separate ways: the binary itself, the corpus it executes, and
the output it produces.

**Status since S0: an engine that opens its own network connections is not run,
in any profile.** Nuclei and ZAP make connections Sulayi's scope enforcement
cannot see — no URL gate, no dial-time address check, no redirect policy, no
request budget, no request log — so running them would be a security tool
bypassing the boundary it exists to keep. They are refused before the binary is
probed or started, recorded as a blocked ledger row with the reason, their
classes stay unassessed, and the terminal says coverage was reduced. `doctor`
reports them as blocked without executing them. Only an integration declared
`Offline` (the source scanner, which reads local files) runs. This is a temporary
limitation until a verified outbound-destination control exists, not a removal;
the integrations below are kept and their argument vectors are still checked
against real binaries by the manual integration job. **TESTED**
(`scanner.TestNetworkEnginesAreRefusedInEveryProfile`, which builds a binary that
records being started and asserts it never was, in every profile and ZAP mode;
`scanner.TestOnlyOfflineEnginesAreDeclaredOffline`;
`cli.TestEnabledNetworkEngineIsBlockedAndTheTerminalSaysCoverageWasReduced`).

The controls below describe the integrations as built. Where one is about network
behaviour, it applies only once an engine is permitted to run again.

**The process is contained.** All three share the supervisor built for framework
adapters, so there is one implementation of every guarantee rather than three.

- Explicit argument vector, never a shell. A target URL containing `;`, `$()`,
  a backtick or a newline is one argument and stays data. **TESTED**
  (`scanner.TestHostileArgumentsStayData`, which asserts no shell interpretation
  *and* that each hostile value arrived intact as a single argument).
- **Its own process group**, so cancellation reaches descendants. This is the
  concrete ZAP-and-Chromium case: an engine that starts a JVM or a browser must
  not leave one running. **TESTED**
  (`scanner.TestDescendantsAreKilledWithTheEngine`, which spawns a grandchild
  that keeps touching a file and asserts it stops).
- `WaitDelay`, so a child holding a pipe open cannot block the assessment
  indefinitely. **TESTED** (`scanner.TestHungPipeDoesNotBlockForever`).
- *(Sulayi's own HTTP client, not the engines — which is why S0 blocks them.)*
  Every resolved address is scope-checked before any dial, and the request is
  refused entirely if any one of them is denied. Connection attempts then proceed
  through the authorized addresses in turn, sequentially rather than raced, so a
  name that resolves to more addresses than the target listens on is reachable
  without the URL gate and the address gate ever separating. **TESTED**
  (`httpx.TestDialFallsBackToTheNextAuthorizedAddress`,
  `httpx.TestFallbackNeverReachesAnUnauthorizedAddress`).
- Both pipes drained concurrently and bounded. Draining one to completion first
  deadlocks the moment the other fills, which a hostile engine can arrange.
  **TESTED** (`scanner.TestEngineFailuresAreExplicit`).
- Version probes run in their own scratch directory, removed afterwards. An engine
  given no `HOME` — which is what "built from nothing" means — falls back to its
  working directory, so a probe with no directory of its own writes into whatever
  directory the operator ran `sulayi` from. **TESTED**
  (`scanner.TestVersionProbeDoesNotRunInTheWorkingDirectory`).
- A private temporary workspace per run, mode 0700, removed afterwards. ZAP is
  additionally given a private home inside it, so a scan cannot accumulate state
  in the operator's home directory or inherit it from a previous run. **TESTED**
  (`scanner.TestWorkspaceIsRemoved`, `zap.TestInvocationIsolatesZAPState`).

**The environment is built from nothing.** This is the sharpest risk in M4: an
engine runs against the very target this tool authenticates to, so an inherited
environment hands it the credentials.

- Nothing is inherited — not `PATH`, not `HOME`. An engine declares the variables
  it genuinely needs (`JAVA_HOME`, `PATH` and `TMPDIR` for ZAP's JVM launcher;
  nothing at all for Nuclei) and gets those and no more.
- This tool's identity credentials are refused **even when an operator names them
  in `passEnv`**. **TESTED** (`scanner.TestEngineEnvironmentIsBuiltFromNothing`,
  which asserts from the engine's own view of its environment).

**Corpora are a supply chain.**

- Nuclei templates are executable security logic. `-disable-unsigned-templates`
  is passed explicitly, and `-code` — which enables code-protocol templates — is
  never passed. **TESTED** (`nuclei.TestInvocationIsHardened`, which asserts both
  the required flags and the forbidden ones).
- That flag has a second edge, and it cuts the other way. Templates an operator
  writes are unsigned, so a corpus of their own would be excluded in full: Nuclei
  exits successfully having executed nothing, and the run reports a completed
  scan with no findings. The corpus is therefore inspected before the process
  starts — an empty one, or one in which nothing is signed, is refused with an
  explanation — and `engines.nuclei.allowUnsignedTemplates` is the deliberate
  opt-in. **TESTED**
  (`nuclei.TestAnEntirelyUnsignedCorpusIsRefusedRatherThanSilentlySkipped`,
  `nuclei.TestAnEmptyCorpusIsRefused`,
  `nuclei.TestUnsignedTemplatesRunOnlyWhenExplicitlyTrusted`).
- A waived signature check is never reported as an enforced one, and a corpus
  that ran only in part is never reported as one that ran in full. **TESTED**
  (`nuclei.TestTheSignatureClaimReflectsHowTheRunWasConfigured`,
  `nuclei.TestAPartlySignedCorpusRecordsWhatWillNotRun`).
- Neither Nuclei nor the static analyser is allowed to fetch its own corpus.
  Nuclei refuses to run without a template directory; the static analyser refuses
  a registry identifier such as `p/default` or `auto`. A corpus that changes
  overnight makes two runs incomparable, and fetching one is an unannounced
  network call that, for Semgrep, also enables telemetry. **TESTED**
  (`nuclei.TestInvocationRefusesToRunWithoutAnExplicitCorpus`,
  `sast.TestRegistryRuleSourcesAreRefused`).
- Corpus provenance is recorded, pinned to a commit where the directory is a git
  checkout and reported as unpinned where it is not. **TESTED**
  (`nuclei.TestTemplateProvenanceRecordsAPinWhenThereIsOne`).
- **No engine is ever installed.** No download, no package manager, no Docker
  pull. `doctor` reports absence; a scan reports it as blocked.

**Network behaviour is constrained where it can be, and disclosed where it
cannot.**

- Out-of-band interaction is disabled (`-no-interactsh`). Interactsh sends
  target-triggered callbacks to a third-party service by default, which is both
  unannounced egress and a disclosure of what is being tested.
- Redirect following is off, so a target cannot redirect a scan off-origin.
- Cloud upload, the PDCP dashboard and update checks are never enabled.
- **The honest limit:** Sulayi cannot constrain what an individual
  Nuclei template or ZAP rule does once the engine is running. A template in the
  supplied corpus can address a host of its own choosing, and ZAP's spider
  reaches what it can find. The mitigations above narrow this; they do not close
  it. Since S0 that is no longer disclosed and accepted: such engines are not run.

**An engine result is visible without being promoted.** An imported alert is
`observed`, which is neither confirmed nor suspected — so the findings line alone
would tell an operator whose engine reported a dozen criticals that nothing was
found. The terminal states each engine's status and the observed count
separately, rather than folding them into the findings total. **TESTED**
(`report.TestSummaryStatesWhatTheEnginesDid`,
`report.TestSummaryOmitsTheEngineBlockWhenNoneRan`,
`scanner.TestImportedFindingsHaveDistinctStableIdentities`).

**Output is attacker-influenced.** A scanner reports what a target sent back, and
the target chooses that.

- Every imported string is bounded and stripped of control characters before it
  reaches a terminal, a report or SARIF. An ANSI escape can clear a screen or
  rewrite a line, which is how a scan result lies about itself. **TESTED**
  (`scanner.TestHostileEngineOutputIsSanitized`,
  `TestOversizedImportedStringsAreBounded`).
- Imported text passes through the run's redactor, which already knows this
  assessment's credentials — so a bearer token reflected in a matched response
  does not reach disk.
- **Secret-bearing fields are not imported at all.** Nuclei's `request`,
  `response`, `template-encoded`, `extracted-results` and `curl-command` are never
  decoded: the curl
  command carries the `Authorization` header, and the request and response are
  raw HTTP. Semgrep's matched source lines are likewise dropped, because secrets
  live in source and a report that quotes it copies an application into an
  artefact attached to tickets. **TESTED**
  (`nuclei.TestNormalizePreservesProvenanceAndDropsSecretBearingFields`,
  `nuclei.TestNucleiExtractorOutputIsNotImported`,
  `sast.TestMatchedSourceIsNotImported`).
  `extracted-results` was added to that list by the product validation gate, not
  by reasoning: run against the reference Laravel application, the stock
  `missing-cookie-samesite-strict` template extracted the whole `Set-Cookie`
  header, so the field contained a live `api_session` value. It had been imported
  on the belief that the caller's redactor would clean it, and the redactor can
  only remove credentials this assessment registered — never a secret belonging
  to the target. The matcher name is kept instead.
- Recorded argument vectors are redacted before storage, so a credential in a
  target URL does not become a copy-and-paste command in a report.

**A rejected identity is stated in the terminal, not only in the report.** Also
found by the validation gate: with a deliberately expired token the JSON report
was entirely correct — liveness `bad`, the canary's exact status, and a statement
that dependent results were withdrawn — while the terminal printed the same
counts as a healthy run and exited zero. An operator reading their console saw a
clean assessment of an application that had refused every credential, which is a
false-assurance path in this tool's own output. **TESTED**
(`report.TestSummaryStatesAnIdentityTheTargetRejected`,
`report.TestSummaryStatesAnUnusableIdentity`,
`report.TestSummarySaysNothingAboutAHealthyIdentity`).

**A failure never becomes a clean result.** This is the requirement M4 exists
around, since the alternative is a crashed scanner silently contributing nothing
to a report that then reads as green.

- Missing binary, crash, non-zero exit with no results, timeout, cancellation,
  output flood, malformed document and profile refusal all produce a blocked
  ledger row whose text says what was lost. **TESTED**
  (`scanner.TestMissingEngineIsBlockedNotClean`, `TestEngineFailuresAreExplicit`,
  `evals.TestM4_EngineFailureDoesNotMakeTheReportCleaner`).
- Truncated output is **refused rather than parsed**: a shorter document reports
  fewer findings than the engine produced.
- A partial run retains what it found, is marked partial, and **claims no
  coverage at all**. **TESTED** (`scanner.TestPartialResultsClaimNoCoverage`).
- A failed engine cannot remove a class from `classesNotAssessed`. **TESTED**
  (`evals.TestM4_EngineFailureDoesNotMakeTheReportCleaner`).

**An alert is not a finding.** Every external result enters as `observed` with
Sulayi severity `unassessed`, a value with no rank that cannot satisfy a policy
threshold. Agreement between two engines is not verification. **TESTED**
(`scanner.TestExternalAlertsAreOnlyEverObserved`,
`evals.TestM4_AgreementBetweenEnginesIsNotConfirmation`,
`evals.TestM4_ExternalObservationsCannotFailTheBuild`).

**Residual risk, stated rather than mitigated.**

- **Executable provenance cannot be established.** Sulayi records the resolved
  path and the tool's self-reported version and sets `Verified: false` on every
  run. A binary named `nuclei` on `PATH` may be anything; an attacker who can
  replace it already has the operator's machine. There is no signature check,
  and claiming one would be worse than not having it.
- **A compromised engine installation is fully trusted within its sandbox.** The
  boundary bounds what it can consume, what environment it holds and how long it
  lives. It does not sandbox syscalls or filesystem access: an engine reads and
  writes as the invoking user.
- **Engine and corpus drift.** Two runs against different installed versions or
  different template checkouts are not comparable. Versions and corpus
  provenance are recorded so the difference is visible, not prevented.
- **ZAP runs unauthenticated**, so anything reachable only when signed in is
  unscanned. This is a deliberate trade against handing credentials to a
  third-party process, and it is reported as a limitation on every ZAP run.
- **Static analysis is not runtime proof.** A matched sink is not a reachable or
  exploitable one. The observation state and the report's wording carry this;
  nothing in the pipeline converts it.
- **Windows has no POSIX process groups**, so a grandchild spawned by an engine
  may outlive a cancellation there. The engine itself is still killed.
- **Target-triggered scanner bugs are the engine's own.** A malicious target may
  crash or hang a scanner; that becomes a blocked row. It may also trigger a
  memory-safety bug inside the engine, which is outside anything this boundary
  can reach.

### T-20 Discovery of undocumented surface

M5 reads four artefacts the target publishes about itself — the `Link` headers on
its own root response, `robots.txt`, the JavaScript its root document references,
and five standardized metadata documents. Every one of them is written by the
application being audited, which is to say by whoever controls it.

> **Since S2** this section describes the passive discovery sources only. The
> bounded crawler, which does fetch what it finds, is a separate component with
> its own rules in T-24 and [ADR-0021](../adr/0021-surface-without-a-specification.md).

**Nothing discovered by these sources is ever fetched.** This is the strongest
statement in the passive sources and the one worth reading twice. Discovery makes requests to
exactly four things: the target's root (plus at most one same-origin redirect
hop), `/robots.txt`, the same-origin scripts the root document names, and a fixed
list of five well-known paths. A path or URL that discovery *finds* is recorded
and never requested. So the usual server-side request forgery question — "can a
target make the scanner fetch something?" — has no surface to attack: the set of
URLs discovery will request is fixed before any target output is read. **TESTED**
(`discovery.TestOffOriginReferencesAreRecordedAndNeverFetched`, which widens the
scope policy to include the second server deliberately, so that discovery's own
origin rule is what is being tested rather than the allowlist).

**Origin, not scope, bounds discovery.** Scope may authorize several hosts,
because an operator can grant that deliberately. A link on the target is not such
a grant. Discovery therefore compares against the target's own origin using the
same normalization the allowlist uses (`scope.Origin`), so a trailing dot, an
explicit default port, an IPv4-in-IPv6 literal, a Unicode homograph or embedded
credentials cannot make another host look like this one. A second, weaker origin
parser inside discovery is exactly how this would have been bypassed, so there
is not one. **TESTED** (`scope.TestOriginEquality`,
`scope.TestOriginEscapeAttemptsAllFail` — userinfo before the real authority, the
target inside a fragment, the target as a name prefix, IPv4-mapped IPv6,
hexadecimal and integer address forms, a neighbouring port and a backslash before
the authority, all of which are either refused outright or resolve to a different
origin — `scope.TestParseOriginRefusesEmbeddedCredentials`,
`scope.TestOriginNormalizesIPv6`).

**Redirects cannot widen anything.** The HTTP client still never follows a
redirect. Discovery takes one hop deliberately, because a great many
applications answer `/` with a 302 to `/login` and refusing to look would mean
reading no markup at all on a large class of real targets. That hop is
re-checked against the target's origin exactly as the first request was, counts
against the request budget, and drops the query string before re-requesting so a
redirect cannot carry a credential into a request Sulayi made on its own
initiative. An off-origin `Location` ends the walk and is recorded. **TESTED**
(`discovery.TestRedirectsCannotWidenTheAssessment`, both directions).

**Cloud metadata stays unreachable.** It is not on the target's origin, so
discovery will not request it; and if scope somehow permitted the host, the
resolved-address gate still denies the IMDS ranges. Two independent controls, and
the discovery-layer one is tested with the metadata address planted in a `Link`
header, a `<script src>` and a `fetch()` literal.

**Parsers are the attack surface, and none of them uses a regular expression.**
Every input here is a target-controlled string of arbitrary size, and the
conventional URL-matching regex — alternation wrapped in unbounded repetition —
is a catastrophic-backtracking denial of service handed to the party being
audited. The `Link`, `robots.txt`, HTML and JavaScript readers are all
single-pass, left-to-right scanners with at most one byte of lookahead. **TESTED**
(`discovery.TestParseLinkHeaderSurvivesHostileInput`,
`discovery.TestPathLiteralsCannotBeMadeToHang`,
`discovery.TestScriptSourcesSurvivesBrokenMarkup`,
`discovery.TestParseRobotsSurvivesHostileInput` — each feeds multi-megabyte
hostile input under a wall-clock deadline, so a change that introduced
backtracking would fail rather than merely slow down).

**Memory and disk are bounded at four levels.** The HTTP client bounds one
response; the per-source cap bounds what one artefact may contribute; the global
candidate cap bounds the run; and request and byte budgets bound the pass. A
target that emits a million distinct path literals produces a bounded, truncated
result — and one that says it is truncated. **TESTED**
(`discovery.TestBudgetExhaustionIsVisibleAndNeverLooksComplete`,
`discovery.TestPathLiteralsBoundsCandidateExplosion`).

**Truncation can never look like completion.** Incompleteness propagates from
every level to the result, because a global budget, the shared candidate cap and
one source hitting its own limit all mean the same thing to a reader: there was
more to find. **TESTED**
(`discovery.TestBudgetExhaustionIsVisibleAndNeverLooksComplete`).

**Discovered URLs carry credentials, and none is retained.** A password-reset
link, a signed download URL and a session identifier in a query string are all
things an application puts in its own HTML and JavaScript. Candidates keep the
path and nothing else: the query and fragment are dropped at normalization,
before anything is stored, rather than filtered by a list of parameter names
somebody thought of. Dropping the class beats redacting the members of it.
**TESTED** (`discovery.TestCredentialBearingURLsLoseTheirCredentials`,
`evals.TestDiscoveredSecretsNeverReachTheReport`).

**Imported text cannot corrupt a terminal or a report.** Candidate paths are
rejected outright if they contain control characters, whitespace, quotes or
angle brackets — a path that was actually requested contains none of those, and a
literal that does is prose or an injection attempt.

**No security expectation is ever derived from a name.** This is the honesty
control rather than the safety one, and it is the easiest thing in this milestone
to get wrong. `/admin` in a bundle, and `Disallow: /admin` in `robots.txt`, are
both strings. `robots.txt` is crawler guidance: it asks search engines not to
index a path and says nothing whatsoever about who may reach it. A discovered
path gets no method, no security requirement and no check — it becomes one
untested ledger row whose detail states that nothing is known about it. **TESTED**
(`discovery.TestPathNamesCreateNoSecurityExpectation`,
`discovery.TestAPathStringNeverBecomesAnOperation`).

**No method is invented.** A path candidate is a distinct model type precisely so
that it cannot be forced into an Operation, because forcing it would require
choosing a method, and an invented method produces an invented request and an
invented conclusion. The one exception is a route a framework adapter reported:
there the method comes from the application's routing table and the expectation
from the same adapter that would have supplied it had the route been documented.

**Third-party scripts are not executed, and not even fetched.** No JavaScript is
executed anywhere in this milestone; no browser is started; a script referenced
from another origin is recorded and left alone; a `sourceMappingURL` is not
followed; and a script named inside another script is not a script this reads.
**TESTED** (`discovery.TestDiscoveryDoesNotCrawl`, which serves a page whose every
link leads onward and asserts that none of it is requested).

**Discovery adds load to the target, and the budget is what bounds it.** A
complete pass is sized to cost roughly what loading the target's own home page
costs: by default at most twenty requests and eight megabytes, through the same
rate limiter as the rest of the assessment. It is not a scan and cannot be turned
into one by configuration, because there is no depth, seed list or wordlist to
configure.

### T-20a Operator-supplied identifiers must match what the operator can see

`assessment.excludeOperations` is a safety control: it is how an operator says "never send
this request", and it is the mechanism protecting destructive endpoints from a sweep.

It was matched against `Operation.ID`, which carries the specification-relative path. An
operator reads their running application — the framework's route list, the browser, the
access log — and writes the path it is served at. Against any specification with a
`servers` base path, which is every Scramble-generated Laravel document, the two never
matched, and the operation the operator forbade was exercised. A safety control that fails
open because of a spelling in which neither spelling is wrong is not a safety control.

Every operator-facing identifier now accepts both forms. **TESTED**
(`model.TestOperationMatchesBothSpellingsOfItsPath`,
`evals.TestExcludedOperationIsNeverRequested`, which asserts the property that matters —
that no request reaches the excluded operation — rather than the comparison behind it).

The authentication-route heuristic tests both forms too, and skips when either matches:
it exists to avoid locking real accounts out, so the fail-safe direction is to skip.

### T-21 Ownership fixtures address objects, not endpoints

An ownership fixture describes one object. The check it drives asks whether an
identity that does not own that object can read it, and that question only has
meaning when the request names the object at all.

Applying a fixture to every operation it could *bind* was therefore wrong, and
expensively so: an operation with no path parameters binds trivially, so a
device-token fixture reached `GET /api/health/liveness`, `GET /api/enums` and
`GET /api/roles` on the reference NestJS application. Two identities receive
identical bodies from a health endpoint because that is correct behaviour, and
each one became a **confirmed, high** finding that failed the build. Fourteen of
them, all false.

A fixture now applies only where it addresses its object: the operation must
declare at least one required path parameter and the fixture must supply every
one. A collection endpoint that leaks another user's records is a real bug, but
it is a different bug with a different oracle, and answering it with
"a resource is readable by an identity that does not own it" would be a
confident answer to a question nobody asked. **TESTED**
(`resource.TestAFixtureDoesNotApplyToOperationsThatAddressNoObject`, built from
the operations that actually produced the false positives).

### T-22 Stopping, limits and accountability (S0)

An autonomous assessment must be stoppable, bounded and reconstructible, and
stopping it must not be how data gets left modified.

- **Interrupting stops the run, not the cleanup.** The first SIGINT or SIGTERM
  cancels the assessment: unreached work is recorded as cancelled and child
  process groups are killed. Once a cross-owner write may have reached the
  target, the owner's after-read, the restoration and its verification run on a
  detached context bounded to 30 seconds, so cancellation and the duration limit
  cannot interrupt them. A second signal exits at once. **TESTED**
  (`evals.TestS0_CancellationAfterTheWriteStillRestoresTheFixture`, which cancels
  the run at the moment the write lands and fails if the detachment is removed;
  against the built binary, `TestInterruptStopsTheRunAndStillReports` and
  `TestSecondInterruptExitsImmediately`, which sends the second signal while a
  restoration is in progress).
- **A closed client sends nothing.** A request made after the client is closed,
  or waiting for a pacing slot when it closes, is refused rather than released
  unpaced. **TESTED** (`httpx.TestClosedClientSendsNothing`).
- **Incomplete cleanup is never folded into a clean result.** A restoration that
  fails, cannot be verified, or cannot be attempted because the fixture's state is
  unknown names the fixture in `cleanupIncomplete`, at the top of the terminal
  summary, on stderr and as a SARIF notification. **TESTED**
  (`evals.TestS0_FailedRestorationIsReportedAsIncompleteCleanup`,
  `engine.TestOwnershipToolFailureBecomesRunState`).
- **Hard limits.** `assessment.maxRequests` (default 1,000) is counted in
  `httpx.Do` and refuses before anything is sent; restoration draws on a small
  allowance above it (four requests per possible write), and that allowance is
  finite too. `assessment.maxDurationMinutes` (default 30) bounds the run. A run
  stopped by either, or interrupted, still writes its report, says why it stopped,
  records the unreached work as blocked, and exits 4 rather than 0. **TESTED**
  (`httpx.TestBudgetRefusesBeyondTheLimitAndSendsNothing`,
  `cli.TestRequestBudgetStopsTheRunAndSaysSo`, `cli.TestStoppedEarlyNamesTheReason`).
- **Every request is accounted for.** `requests.jsonl` in the run directory holds
  one redacted line per `Do` call — sent, refused, not sent, or failed in flight —
  with the identity that sent it. If a line cannot be written, every later request
  is refused, so the log never has a silent gap. The run directory is created
  before the first request, so discovery is logged too. External engine traffic is
  not in it, which is one reason those engines do not run. **TESTED**
  (`httpx.TestEveryCallIsAuditedOnceIncludingRefusals`,
  `httpx.TestAuditFailureStopsFurtherRequests`,
  `cli.TestRequestLogRecordsEveryRequestAndNoCredential`, which also searches every
  file under `.sulayi/` for a credential the target reflects).
- **Distinguishing "never sent" from "may have arrived"** decides whether a write
  needs cleaning up, so refusals and pre-send cancellations carry a type of their
  own rather than a message. **TESTED** (`httpx.TestCancelledPacingWaitIsNotSent`,
  `httpx.TestNotSentIsFalseForTransportFailures`).

### T-23 Signing in as test accounts (S1)

Sulayi now holds passwords, signs in, and keeps sessions alive. Each step is a
place a credential can leak, an account can be locked, or a dead session can
pass for a protected application. See
[ADR-0020](../adr/0020-login-identities-and-credentials-files.md).

- **The credentials file lends nothing it does not use.** `--env` reads only the
  names `sulayi.yaml` references and ignores the rest, so an application's real
  `.env` passed by mistake contributes none of its database passwords or signing
  keys. Values are held in memory and never placed in the process environment, so
  no child process can inherit one. Nothing is loaded unless `--env` names it.
  **TESTED** (`identity.TestOnlyReferencedNamesAreLoaded`,
  `identity.TestFileValuesNeverEnterTheProcessEnvironment`).
- **A committed credentials file is refused.** A file git tracks stops the run
  before any request or run directory exists; one no ignore rule covers, or one
  readable by other users, is warned about. **TESTED**
  (`identity.TestTrackedCredentialsFileIsRefused`, `cli.TestTrackedEnvFileStopsTheRun`,
  `identity.TestUnignoredCredentialsFileIsWarnedAbout`,
  `identity.TestLooselyPermissionedCredentialsFileIsWarnedAbout`).
- **Errors never print a value.** A malformed file is reported by line number; a
  failed login names the request and its status, never the credentials or the
  response. **TESTED** (`identity.TestParseErrorsNeverEchoContent`,
  `identity.TestRejectedLoginBlocksTheIdentityWithoutEchoingCredentials`).
- **A login reaches only the target.** Its path is a path, never a URL; a GET login
  is refused because credentials do not belong in a URL; the preflight may only be
  GET or HEAD. **TESTED** (`identity.TestLoginValidation`).
- **The token is read without being stored.** Redaction masks JWTs in every
  captured body, so the login response comes back raw, in memory only, through a
  path that returns no exchange to store. Every credential field, preflight value,
  token and cookie is registered with the redactor before the next capture, and
  the end-to-end test fails if registration is removed. **TESTED**
  (`identity.TestBearerLoginSignsInAndRedactsTheToken`,
  `cli.TestLoginThroughEnvFileLeavesNoSecretAnywhere`, which reflects the password,
  token and cookie from the target and searches the terminal and every file under
  `.sulayi/`).
- **A session is a session, not a status.** A login succeeds when it issues one: a
  bearer token from a 2xx body, or cookies the login response itself sets, on a 2xx
  or an unfollowed redirect. Bad credentials answered with 400 leave the identity
  unusable, and its work blocked. **TESTED**
  (`identity.TestLoginWithoutTheTokenAtThePointerFails`,
  `identity.TestBearerLoginAnsweredWithRedirectFails`,
  `identity.TestCookieSessionWithCSRF`, `identity.TestPreflightValueAndRedirectedLogin`).
- **Recovery is bounded and never replays.** An identity signs in again only when
  its canary answers 401 or 419 — a 403 is an authorization result and changes
  nothing — at most three times a run, one sign-in at a time. The request that
  failed is not resent, so a write cannot be duplicated. **TESTED**
  (`identity.TestExpiredSessionIsRecoveredWithoutReplay`,
  `identity.TestForbiddenCanaryDoesNotSignInAgain`,
  `identity.TestReauthenticationIsBounded`, `identity.TestConcurrentSuspicionSignsInOnce`).
- **A dead session cannot produce a clean result.** Every interval in which a
  session may have been dead is kept, including after recovery, and results whose
  authenticated control ran inside one are withdrawn. **TESTED**
  (`engine.TestInvalidationAfterRecoveryCoversOnlyTheDeadInterval`).

**Limits.** Cookie sessions and CSRF handling are tested against local fixtures
modelled on documented flows, not against Laravel Sanctum, NextAuth or any other
framework's real implementation. Bearer logins are validated against the Laravel
Passport and NestJS JWT reference starters by the reference-applications
workflow. OAuth authorization flows, OIDC, MFA and browser login are not
supported. Login and sign-out routes in the specification are excluded from
the sweep by default: a login so accounts are not locked, a sign-out so an
authenticated control request cannot end the session the run depends on.
**TESTED** (`engine.TestSignOutRoutesAreExcludedByDefault`). A sign-out route
whose path does not look like one belongs in `assessment.excludeOperations`.

### T-24 Surface without a specification (S2)

Without an OpenAPI document Sulayi finds routes by crawling, from a browser
recording, or from a framework adapter's routing table, and takes its oracle
from a declared access policy. Each is a way for target output to decide what
Sulayi requests, and each would be an SSRF or a scope escape if it could reach
beyond the target. See [ADR-0021](../adr/0021-surface-without-a-specification.md).

- **The crawler stays on the target and changes nothing.** It requests GET only,
  through the same scope-enforcing client as every check (an identity's through
  its origin-bound control), on the target's own origin under its base path. It
  follows links to a fixed depth and page count, records forms with the method
  they declare and never submits them, executes no script, and records off-origin
  links and redirects without following them. **TESTED**
  (`discovery.TestCrawlStaysOnOriginAndNeverSubmitsOrSignsOut`,
  `discovery.TestCrawlFollowsOnlySameOriginRedirects`,
  `discovery.TestCrawlStaysUnderTheBasePath`).
- **It never signs anyone out or touches a risky route.** Sign-out, login,
  password, verification and other authentication routes, operations configured as
  state-changing and excluded operations are never requested. **TESTED**
  (`discovery.TestCrawlStaysOnOriginAndNeverSubmitsOrSignsOut`,
  `cli.TestSpecLessRouteIsConfirmedAgainstADeclaredPolicy`, which links the crawler
  to `/logout` and a POST form and asserts neither was requested).
- **Its volume is bounded and its gaps are reported.** Pages, depth, the run's
  request budget and its deadline all stop it, and a crawl that stopped says so in
  the ledger statement and the terminal. **TESTED** (`discovery.TestCrawlLimitsAreReported`,
  `discovery.TestCrawlStopsWhenTheBudgetIsSpent`).
- **An SPA fallback is not a route.** A target that answers unknown paths like a
  real page is fingerprinted first, and no such answer becomes an operation.
  **TESTED** (`discovery.TestCrawlIgnoresTheSPAFallback`).
- **A HAR is discovery input, never permission.** Only each entry's method and URL
  are decoded; headers, cookies, bodies, responses and query strings are never read
  into memory. Off-origin, asset and token-bearing entries are left out. Nothing is
  replayed, nothing from the file is stored, and every operation it yields is
  planned and gated like one from a specification — a recorded POST is not sent
  under `standard`. **TESTED** (`discovery.TestHARYieldsOperationsAndNothingElse`,
  `discovery.TestHARRespectsTheTargetsBasePath`, `discovery.TestMalformedHARIsRefusedWithoutEchoingIt`,
  `cli.TestHARIsDiscoveryOnly`, which records secrets in every part of a HAR and
  searches every file under `.sulayi/`).
- **A method is never guessed.** An operation exists only when a source
  establishes its method: a link (GET), a form's declared method, a recorded
  request, a routing table. A path seen without one stays an untested ledger row.
  **TESTED** (`discovery.TestCrawlStaysOnOriginAndNeverSubmitsOrSignsOut`).
- **A declared policy is an expectation, not evidence.** It makes a route
  confirmable only through the existing authenticated-control verification; where
  it contradicts the specification or an adapter, neither is used and the
  disagreement is reported. A route's name is never evidence. **TESTED**
  (`access.TestApplyDeclaresCorroboratesAndReportsConflicts`,
  `access.TestNoPolicyDeclaresNothing`, `access.TestPatternsMatchWholeSegments`,
  `access.TestMalformedPatternsAreRejected`,
  `cli.TestSpecLessRouteIsConfirmedAgainstADeclaredPolicy`).
- **An inference never confirms.** An expectation inferred from an adapter or from
  a route being reachable only while signed in caps its finding at suspected, and
  a navigation inference raises nothing unless the anonymous caller received what
  the signed-in one did — a login page or a "please sign in" document is not a
  vulnerability. **TESTED** (`evals.TestM3_AdapterExpectationStaysSuspectedEvenWithAMatchingControl`,
  `cli.TestSpecLessRouteWithoutPolicyIsOnlySuspected`, which fails if that guard is
  removed).
- **Nothing found is not a clean result.** A spec-less run that finds no operation
  exits 3 and says how to give it a surface; a target that answers no request at all
  aborts with exit 4, because every other source would fail the same way. **TESTED**
  (`cli.TestNoSpecificationAndNothingFoundEstablishesNothing`,
  `cli.TestAdapterAloneIsASurface`, `cli.TestUnreachableTargetAborts`).

**Limits.** The crawler reads server-rendered links; a single-page application
that renders its navigation in JavaScript yields little to it, and a HAR is the
way to give Sulayi that application's API. Navigation inference depends on the
anonymous crawl not reaching a route; an application that links everything from
public pages gives it nothing to infer.

### T-25 Records Sulayi creates, and authorization across accounts and roles (S3)

Sulayi now changes the target under the default profile: it creates the records
an operator declares as each identity, probes them across accounts and probes
declared reads across roles, and deletes what it created. Each of those is a way
to change or destroy data, or to report a boundary that was never tested. See
[ADR-0022](../adr/0022-authorization-across-accounts-and-roles.md).

- **Standard creates and deletes only what was declared and observed.** Each
  creation is granted as one exact POST and body, and the deletion only for the
  URL built from the id that creation returned, each consumed on first use. No
  other DELETE is ever permitted under `standard`, and `safe` creates nothing.
  **TESTED** (`httpx.TestStandardPermitsOneExactCreateAndOneExactCleanup`,
  `httpx.TestSafeIgnoresOneShotGrants`, `cli.TestS3_SafeProfileCreatesNothing`,
  `cli.TestS3_SecureApplicationHoldsBothBoundaries`, which asserts exactly the two
  created records were deleted).
- **A returned id cannot move a request.** The id the application returns passes
  the same validation and origin and base-path check as a fixture value; an id
  that could change the URL's shape is never addressed, and the record is
  reported as not removed. **TESTED** (`record.TestAHostileIDIsNeverAddressed`).
- **Nothing is left behind silently.** Records are removed after the assessment,
  after an interrupt too, on the cleanup allowance; a removal counts only when the
  creator's read of the record answers not found. Every record is in the report,
  and one not removed is incomplete cleanup with its address. **TESTED**
  (`cli.TestS3_RecordNotRemovedIsReported`, `cli.TestS3_SecureApplicationHoldsBothBoundaries`).
- **Ownership is observed, never inferred, and the expectation is declared.** A
  record is owned because the run watched its owner create it; identifiers in
  list responses are never used. A path no `access.owned` rule declares gets no
  conclusion, and roles in `reachableBy` are not probed. **TESTED**
  (`cli.TestS3_UndeclaredOwnershipConcludesNothing`,
  `record.TestAddressesMatchesTheRecordItselfOnly`,
  `access.TestRulesMatchFirstAndCompareRoles`, `access.TestMalformedRulesAreRefused`).
- **A cross-account or cross-role finding is confirmed only by the existing
  verification.** Cross-account reads use ADR-0013's owner control, re-check and
  resource identity unchanged; a cross-role read is confirmed only when an
  allowed identity succeeded and the other received a materially equivalent
  response, and a refusal is a verified denial. **TESTED**
  (`cli.TestS3_VulnerableApplicationIsConfirmedAcrossAccountsAndRoles`,
  `cli.TestS3_SecureApplicationHoldsBothBoundaries`).
- **No state-changing route is probed across roles.** Only GET is planned; a
  state-changing route under a role rule is an untested ledger row. **TESTED**
  (`cli.TestS3_VulnerableApplicationIsConfirmedAcrossAccountsAndRoles`).

**Limits.** With one account per role, cross-account coverage runs between
identities of different roles, so a role in `reachableBy` leaves one direction.
An application whose delete is soft keeps a row its API reports as gone.

## 3. Residual risk accepted at this stage

Stated plainly rather than left for a reader to discover.

- **Redaction is deny-list and pattern based.** It will not catch every bespoke secret
  format — an opaque 32-character session identifier in a JSON field with an unremarkable
  name will survive. It is a mitigation, not a guarantee, and the user-facing
  documentation says so.
- **File permissions are not enforced on Windows.** `os.Chmod` only toggles a read-only
  attribute there. The CLI warns; it does not refuse. An explicit ACL is planned.
- **No sandboxing of external engines** beyond process isolation. Today the mitigation is
  that no engine integration exists at all.
- **`INDETERMINATE` outcomes are reported but not automatically re-tried.**
- **No signing of release artefacts.** Required before any binary distribution.
- **A WAF or intermediary in front of the target can produce false negatives.** Sulayi
  fingerprints edge headers and annotates a denial with the possibility that an
  intermediary, not the application, refused the request — but it cannot yet prove which.
- **Discovery finds some undocumented surface, never all of it.** Four passive sources and
  five well-known probes reveal what an application happens to publish about itself. A
  route referenced from no page, no bundle, no header and no metadata document remains
  invisible, and there is no denominator that would say how many those are — which is why
  no report offers a completeness figure. What changed in M5 is that the routes which
  *are* discoverable are now counted and named as untested rather than absent.
- **A discovered path is almost never testable.** Its HTTP method is unknown and nothing
  states what it should return to whom, so it can be accounted for and not assessed. Only
  routes a framework adapter reports arrive with both, and only those are assessed.
- **JavaScript extraction is lexical and therefore both incomplete and imprecise.** A
  route assembled at runtime from fragments is not found; a string that looks like a path
  and is not one may be reported. The design accepts noise over invention: every candidate
  is explicitly untested, so a false one costs a line in the ledger rather than a false
  finding.
- **Sulayi is fingerprintable, and therefore cloakable.** Its `User-Agent`, its
  `__sulayi_cb` cache-buster and its `sulayi-nonexistent-*` baseline paths are all
  identifiable, so a hostile target can serve a denial to the scanner and real data to
  everyone else. Being identifiable is deliberate — an assessment tool that disguises itself is
  harder to authorize and harder to stop — so this is accepted rather than fixed by
  randomisation. It is a real limitation when assessing an application you do not fully
  control.
- **A target can still influence classification.** Ambiguous responses are now forced to
  `indeterminate` rather than `denied`, so the cheapest suppression attack yields a
  *blocked* row instead of a silent pass. A target that returns a pure, payload-free
  denial envelope alongside a separate data channel could still mislead a single-identity
  check; the answer to that is the authenticated control request, which arrives with
  identities.

## 4. Reporting a vulnerability

See `SECURITY.md`.
