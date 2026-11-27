// Package engine runs an assessment: it plans work, gates it against the safety
// profile, executes it, and records both what happened and what did not.
//
// The ledger is the point. Any scanner can report what it found; this one is
// built so that a run cannot quietly omit what it never attempted.
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaylordibe/sulayi/internal/access"
	"github.com/jaylordibe/sulayi/internal/adapter"
	"github.com/jaylordibe/sulayi/internal/check"
	"github.com/jaylordibe/sulayi/internal/discovery"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/openapi"
	"github.com/jaylordibe/sulayi/internal/resource"
	"github.com/jaylordibe/sulayi/internal/scanner"
)

// Check is the contract the engine consumes.
//
// It is declared here, where it is used, rather than beside its implementation.
// Unlike the storage seam, this interface earns itself immediately: the engine
// iterates a heterogeneous set, the safety gate needs a uniform way to ask what
// a check requires, and a test double is the second implementation on day one.
type Check interface {
	Metadata() check.Metadata
	// RequiredProfile reports the profile needed for this operation, so that
	// impact is a property of the work rather than of the check.
	RequiredProfile(model.Operation) model.Profile
	// Applicable reports whether an oracle exists, and why not when it does not.
	Applicable(model.Operation) (bool, model.BlockedCause, string)
	Run(context.Context, model.Operation) check.Result
}

// MutationGuard is the part of the HTTP client's safety guard the planner uses.
//
// It is declared here, where it is consumed, so the engine does not depend on
// the HTTP client. The guard enforces; the planner only registers the exact
// requests it intends to send and then closes registration.
type MutationGuard interface {
	Profile() model.Profile
	Grant(method, rawURL string, fields []string) error
	Seal()
}

// Surface describes the attack surface and, critically, how much of it we can
// see.
//
// SpecDerived is recorded because it bounds every coverage number in the run:
// when the surface comes from a specification, an undocumented route is not
// untested, it is invisible. Reporting coverage against a surface handed to us
// by the thing we are auditing would reproduce, one level up, exactly the
// false-assurance failure this project exists to prevent.
type Surface struct {
	SpecDerived  bool
	SpecSource   model.Source
	SpecTitle    string
	SpecVersion  string
	Fidelity     openapi.Fidelity
	Operations   []model.Operation
	ExternalRefs []string
	Warnings     []string

	// Adapter* record what framework adapters contributed, and — at least as
	// importantly — what they could not. An adapter that failed found no
	// controls, and an application with no controls also has no controls; the
	// two must never read the same.
	AdapterMerges      []adapter.Merge
	AdapterFailures    []string
	AdapterLimitations []string
	AdapterUnmatched   []string

	// Discovery is what the application revealed about itself beyond any
	// specification: paths found in Link headers, robots.txt, its own
	// JavaScript and standardized metadata documents.
	//
	// These are deliberately not Operations. They have no method and no
	// expectation, so nothing can be planned against them; what they change is
	// the account of what was not assessed, which before this existed had no
	// row at all for a route the specification omitted.
	Discovered []model.PathCandidate
	// DiscoveryCorroborated records discovered paths that a known operation
	// already covers, so one route named by three artefacts stays one route.
	DiscoveryCorroborated []discovery.Corroboration
	// DiscoveryOffOrigin are references to other origins, recorded and never
	// contacted.
	DiscoveryOffOrigin []model.PathCandidate
	// DiscoveryAttempts records every source consulted, including those that
	// could not be. A source that failed and a source that found nothing must
	// never read the same.
	DiscoveryAttempts []discovery.Attempt
	// DiscoveryIncomplete reports that a budget stopped discovery early.
	DiscoveryIncomplete bool
	// DiscoveryLimitations are what discovery could not establish.
	DiscoveryLimitations []string
	// DiscoveryRequests and DiscoveryBytes record what discovery cost the
	// target, so an operator can see the traffic this feature generated.
	DiscoveryRequests int
	DiscoveryBytes    int64
	// AdapterDiscovered names operations an adapter found outside the
	// specification that were adopted into the assessed surface.
	AdapterDiscovered []string

	// HAR is what a browser recording contributed, when one was given. It is
	// discovery input only: nothing in it was replayed.
	HAR *discovery.HARResult
	// HARAdded and HARCorroborated count the recording's operations that were
	// new to the surface and that matched an operation it already had.
	HARAdded, HARCorroborated int
	// Crawls are what the crawler found as each actor — the anonymous caller
	// and each signed-in identity — and what it could not do.
	Crawls []discovery.CrawlResult
	// CrawlAdded counts operations the crawler added to the surface.
	CrawlAdded int
	// NavigationInferred counts routes given an inferred expectation because
	// they were reached by link only while signed in.
	NavigationInferred int
	// Access is what the declared access policy did to the surface.
	Access access.Applied
}

// Environment records operator-stated differences from production.
type Environment struct {
	Name        string
	Differences []string
}

// Options configures a run.
type Options struct {
	RunID        string
	Target       string
	TargetName   string
	Profile      model.Profile
	Surface      Surface
	Checks       []Check
	Environment  Environment
	ScopeEntries []string
	AllowPrivate bool
	// ExcludeOperations lists operation ids that must never be exercised.
	ExcludeOperations []string
	// StateChangingOperations names operations that change state whatever
	// their method. They are planned as state-changing requests.
	StateChangingOperations []string
	// Guard is the HTTP client's safety guard. The planner registers the exact
	// fixture requests the standard profile may send, then seals it before
	// anything executes. Nil means nothing is registered, which leaves the
	// client refusing every state-changing request below aggressive.
	Guard MutationGuard
	// ExcludeAuthEndpoints skips operations that look like authentication
	// routes, so that a sweep cannot trip account lockout.
	ExcludeAuthEndpoints bool
	Concurrency          int
	RequestsPerSecond    float64
	// Identities are the configured principals and their authenticated
	// controls. Nil means none is configured, in which case the run behaves
	// exactly as it did before identities existed.
	Identities *identity.Set
	// Resources are the configured resource fixtures. Empty means no
	// cross-owner work is planned, and the run behaves exactly as it did before
	// fixtures existed.
	Resources []resource.Fixture
	// ResourceCheck runs cross-owner work. Nil disables it.
	ResourceCheck ResourceCheck
	// RoleRules are the declared access.roles rules, and RoleCheck runs the
	// cross-role work they plan. Either nil disables it.
	RoleRules *access.Rules
	RoleCheck ResourceCheck
	// Engines is what the external scanning engines contributed, including what
	// they failed to do.
	Engines scanner.Collection
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
	// EvidenceSink persists a captured exchange and returns a reference to it.
	//
	// It is a function rather than an interface so that the engine does not
	// depend on the storage package. When nil, evidence is discarded and
	// findings carry no references — which is why the CLI always supplies one.
	EvidenceSink func(model.Exchange) (string, error)
}

// Verdict is what re-running a finding established (ADR-0024).
type Verdict string

const (
	// VerdictReproduced means the same check found it again.
	VerdictReproduced Verdict = "reproduced"
	// VerdictFixed means the unit executed and produced no finding.
	VerdictFixed Verdict = "fixed"
	// VerdictInconclusive means the unit did not execute, so nothing was
	// established either way.
	VerdictInconclusive Verdict = "inconclusive"
)

// Verification links a re-run to the finding it re-ran.
type Verification struct {
	OfRun     string
	OfFinding string
	Ref       string
	Verdict   Verdict
	Detail    string
}

// RecordOutcome is one record the run created, or tried to, and what became
// of it.
type RecordOutcome struct {
	Type  string
	Owner string
	ID    string
	URL   string
	// Created is true when the application may hold the record.
	Created bool
	// Removed is true only when its deletion was verified by reading it again.
	Removed bool
	// Problem says why it was not created, or not shown to be removed.
	Problem string
}

// Result is everything one assessment produced.
type Result struct {
	RunID        string
	Target       string
	TargetName   string
	Profile      model.Profile
	StartedAt    time.Time
	FinishedAt   time.Time
	Surface      Surface
	Environment  Environment
	ScopeEntries []string
	AllowPrivate bool

	Findings []model.Finding
	Coverage []model.CoverageEntry
	// ToolFailures records engines or components that failed. A failure is never
	// an absence of findings.
	ToolFailures []string
	// CleanupIncomplete names fixtures the assessment changed, or may have
	// changed, and could not restore or could not verify as restored. It is
	// separate from ToolFailures because it is not about coverage: somebody's
	// data may still be wrong.
	CleanupIncomplete []string
	// Verification is set when this run re-ran one earlier finding.
	Verification *Verification
	// Records lists every record the run created, or tried to, as its
	// identities, and whether each was removed (ADR-0022).
	Records []RecordOutcome
	// StoppedEarly says why the assessment ended before finishing its plan:
	// interrupted, out of time, or out of requests. Empty means it was not.
	StoppedEarly string
	// Requests and RequestLimit record what the assessment sent to the target
	// against its budget, and CleanupRequests what it spent restoring fixtures
	// above it.
	Requests        int
	RequestLimit    int
	CleanupRequests int
	// OutOfScopeHosts were discovered and deliberately not contacted.
	OutOfScopeHosts []string
	// ClassesNotAssessed names weakness classes no check covered. Without this,
	// a report of "no findings" implies far more than it should.
	ClassesNotAssessed []string
	// Identities records what was known about each configured identity. It
	// carries no credential, no credential length and no fingerprint.
	Identities []identity.Status
	// Ownership accounts for the cross-owner boundaries this run exercised, and
	// states plainly what they do not cover.
	Ownership OwnershipSummary
	// Engines is the external engine account.
	Engines scanner.Collection
}

// DimensionOperation is the ledger dimension for assessment work against one
// operation.
const DimensionOperation = "operation"

// DimensionIdentity is the ledger dimension for whether a configured identity
// could be used at all.
//
// Identity rows are ledger material rather than a report footnote: "could this
// identity authenticate?" is a unit of intended work that can be blocked, and a
// run in which it was blocked has tested less than a run in which it was not.
const DimensionIdentity = "identity"

// DimensionPath is the ledger dimension for a discovered path that no
// specification or adapter describes.
//
// It is a separate dimension from operations because the subjects are different
// kinds of thing: an operation row says "this callable unit was or was not
// checked", and a path row says "this exists and nothing was planned against
// it". Collapsing them would require giving every discovered path a method, and
// an invented method produces an invented request and an invented conclusion.
const DimensionPath = "path"

// ExecutedCount returns how many assessment checks actually ran.
//
// Assessment work is counted; preconditions are not. An identity row records
// whether a credential worked, which has to happen before anything can be
// tested but is not itself a test — counting one would let merely configuring an
// identity inflate the number of checks a run claims to have executed.
//
// Cross-owner work does count. It is assessment: a boundary was probed and an
// answer obtained. Leaving it out produced a run that reported confirmed
// findings underneath the sentence "this assessment executed no checks", which
// is precisely the contradiction the assurance statement exists to prevent.
func (r Result) ExecutedCount() int {
	return r.countDisposition(model.DispositionExecuted)
}

// BlockedCount returns how many assessment checks were blocked.
func (r Result) BlockedCount() int {
	return r.countDisposition(model.DispositionBlocked)
}

// IsAssessmentWork reports whether a ledger dimension represents work that tests
// the target, as opposed to a precondition for testing it.
func IsAssessmentWork(dimension string) bool {
	return dimension == DimensionOperation ||
		dimension == DimensionOwnership ||
		// Cross-role work is assessment for the same reason cross-owner work
		// is: a route was probed as a role the declared rule does not allow.
		// Leaving it out reported two confirmed cross-role findings on Juice
		// Shop under "this assessment executed no checks".
		dimension == DimensionRole ||
		// A discovered path is surface that exists and was not assessed, which
		// is precisely what the untested counter means. Excluding it would
		// leave the headline number measuring only the surface the application
		// chose to document — the exact blind spot discovery exists to close.
		dimension == DimensionPath ||
		// An external engine run is assessment: it was planned work against the
		// target. Leaving it out produced a summary reading "blocked: 0" while
		// three engines had failed, which understates exactly the thing this
		// milestone exists to make visible.
		dimension == scanner.DimensionEngine
}

func (r Result) countDisposition(d model.Disposition) int {
	n := 0
	for _, e := range r.Coverage {
		if IsAssessmentWork(e.Dimension) && e.Disposition == d {
			n++
		}
	}
	return n
}

// ledger accumulates coverage entries from concurrent checks.
type ledger struct {
	mu      sync.Mutex
	entries []model.CoverageEntry
}

func (l *ledger) add(e model.CoverageEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

// Run executes an assessment.
func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if !opts.Profile.Valid() {
		return Result{}, fmt.Errorf("engine: invalid profile %q", opts.Profile)
	}
	if opts.Guard != nil && opts.Guard.Profile() != opts.Profile {
		return Result{}, fmt.Errorf("engine: the HTTP client enforces the %s profile but the plan is for %s",
			opts.Guard.Profile(), opts.Profile)
	}

	res := Result{
		RunID:        opts.RunID,
		Target:       opts.Target,
		TargetName:   opts.TargetName,
		Profile:      opts.Profile,
		StartedAt:    opts.Now(),
		Surface:      opts.Surface,
		Environment:  opts.Environment,
		ScopeEntries: opts.ScopeEntries,
		AllowPrivate: opts.AllowPrivate,
	}

	lg := &ledger{}
	var findingsMu sync.Mutex
	var findings []model.Finding

	// Establish whether each configured identity can authenticate, before any
	// assessment work depends on it.
	//
	// Doing this first matters. An identity that is already dead would otherwise
	// be discovered one failed control at a time, and every one of those
	// failures would be indistinguishable from an application that is correctly
	// refusing access.
	probeIdentities(ctx, opts.Identities)

	// The exclusion list is matched against both spellings of an operation's
	// path, because an operator reads the application and the specification
	// spells it differently. See model.Operation.MatchesID: matching only the
	// specification's spelling made this fail open, and this is the control that
	// says "never send this request".
	excludedBy := func(op model.Operation) bool {
		return op.MatchesAnyID(opts.ExcludeOperations)
	}

	type job struct {
		op model.Operation
		ck Check
	}
	var jobs []job

	// Planning. Every operation that is not planned produces a ledger row
	// explaining why, so the difference between "tested and clean" and "never
	// attempted" is always visible.
	for _, op := range opts.Surface.Operations {
		for _, ck := range opts.Checks {
			meta := ck.Metadata()
			base := model.CoverageEntry{
				Dimension:  DimensionOperation,
				Subject:    op.ID,
				CheckID:    meta.ID,
				IdentityID: model.AnonymousIdentity().ID,
			}

			if excludedBy(op) {
				base.Disposition = model.DispositionUntested
				base.Cause = model.CauseSafetyPolicy
				base.Detail = "excluded by configuration"
				lg.add(base)
				continue
			}
			// Both spellings are tested. This heuristic exists to avoid locking
			// real accounts out, so the fail-safe direction is to skip when
			// either form looks like an authentication route.
			if opts.ExcludeAuthEndpoints &&
				(model.LooksLikeAuthRoute(op.PathTemplate) || model.LooksLikeAuthRoute(op.AbsolutePath())) {
				base.Disposition = model.DispositionUntested
				base.Cause = model.CauseSafetyPolicy
				base.Detail = "skipped because the path looks like an authentication or sign-out route; " +
					"sweeping these can lock real accounts or end the session the run depends on. " +
					"Set assessment.excludeAuthEndpoints to false to include them"
				lg.add(base)
				continue
			}

			if ok, cause, why := ck.Applicable(op); !ok {
				base.Disposition = model.DispositionUntested
				base.Cause = cause
				base.Detail = why
				lg.add(base)
				continue
			}

			required := ck.RequiredProfile(op)
			configuredStateChanging := model.IsSafeMethod(op.Method) && op.IsStateChanging(opts.StateChangingOperations)
			if configuredStateChanging {
				required = model.ProfileAggressive
			}
			if allowed, cause := model.GateProfile(opts.Profile, required); !allowed {
				base.Disposition = model.DispositionBlocked
				base.Cause = cause
				what := fmt.Sprintf("this operation uses %s", op.Method)
				if configuredStateChanging {
					what = "this operation is configured in assessment.stateChangingOperations"
				}
				base.Detail = fmt.Sprintf(
					"%s, which requires the %s profile; the effective profile is %s. "+
						"Sending it could change or destroy data, so it was not attempted",
					what, required, opts.Profile)
				lg.add(base)
				continue
			}

			jobs = append(jobs, job{op: op, ck: ck})
		}
	}

	// Cross-owner planning. Fixtures multiply operations by identities, so this
	// is where growth is bounded; everything not planned gets a ledger row.
	ownership := planOwnership(opts, lg)
	ownership = append(ownership, planRoles(opts, lg, len(ownership))...)

	// Registration closes before anything executes, so nothing running during
	// the assessment can widen what the standard profile may change.
	if opts.Guard != nil {
		opts.Guard.Seal()
	}

	// Execution.
	controls := &controlLog{}
	locks := newFixtureLocks()
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var failuresMu sync.Mutex
	failures := map[string]struct{}{}
	cleanup := map[string]struct{}{}

	for i, j := range jobs {
		if ctx.Err() != nil {
			// Every planned job must appear in the ledger. Abandoning the
			// remainder silently would be precisely the omission this package
			// exists to prevent — a shorter run would simply look cleaner.
			for _, remaining := range jobs[i:] {
				lg.add(model.CoverageEntry{
					Dimension:   DimensionOperation,
					Subject:     remaining.op.ID,
					CheckID:     remaining.ck.Metadata().ID,
					IdentityID:  model.AnonymousIdentity().ID,
					Disposition: model.DispositionBlocked,
					Cause:       model.CauseCancelled,
					Detail:      "the assessment was cancelled before this operation was reached",
				})
			}
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()

			out := j.ck.Run(ctx, j.op)
			meta := j.ck.Metadata()

			for _, u := range out.ControlsUsed {
				controls.record(controlUse{
					subject:    j.op.ID,
					checkID:    meta.ID,
					identityID: u.IdentityID,
					at:         u.At,
				})
			}

			// Persist the evidence first, so both the ledger row and any finding
			// can reference it rather than embedding copies.
			refs, sinkErrs := storeExchanges(opts.EvidenceSink, out.Exchanges)
			for _, e := range sinkErrs {
				failuresMu.Lock()
				failures["evidence: "+e] = struct{}{}
				failuresMu.Unlock()
			}

			lg.add(model.CoverageEntry{
				Dimension:    DimensionOperation,
				Subject:      j.op.ID,
				CheckID:      meta.ID,
				IdentityID:   model.AnonymousIdentity().ID,
				Disposition:  out.Disposition,
				Cause:        out.Cause,
				Detail:       out.Detail,
				EvidenceRefs: refs,
			})

			if out.Disposition == model.DispositionBlocked && out.Cause == model.CauseTransportError {
				failuresMu.Lock()
				failures[meta.ID+": "+out.Detail] = struct{}{}
				failuresMu.Unlock()
			}

			if out.Finding != nil {
				f := *out.Finding
				f.ID = findingID(meta.ID, j.op.ID)
				f.Recipe = &model.Recipe{CheckID: meta.ID, Operation: model.RecipeOperationOf(j.op)}
				if len(f.EvidenceRefs) == 0 {
					f.EvidenceRefs = refs
				}
				findingsMu.Lock()
				findings = append(findings, f)
				findingsMu.Unlock()
			}
		}(j)
	}

	for i, u := range ownership {
		if ctx.Err() != nil {
			for _, remaining := range ownership[i:] {
				e := remaining.entry()
				e.Disposition = model.DispositionBlocked
				e.Cause = model.CauseCancelled
				e.Detail = "the assessment was cancelled before this authorization unit was reached"
				lg.add(e)
			}
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u ownershipUnit) {
			defer wg.Done()
			defer func() { <-sem }()

			// Serialise per fixture: two units observing one resource
			// concurrently would interleave their reads and writes, and each
			// would attribute the other's effect to itself.
			// A cross-role unit without a fixture touches no shared resource.
			if u.plan.Fixture.ID != "" {
				lock := locks.get(u.plan.Fixture.ID)
				lock.Lock()
				defer lock.Unlock()
			}

			out := u.rc.RunResource(ctx, u.plan)
			meta := u.rc.MetadataFor(u.plan)

			for _, cu := range out.ControlsUsed {
				controls.record(controlUse{
					subject:    u.plan.Subject(),
					checkID:    meta.ID,
					identityID: cu.IdentityID,
					at:         cu.At,
					resourceID: u.plan.Fixture.ID,
				})
			}

			refs, sinkErrs := storeExchanges(opts.EvidenceSink, out.Exchanges)
			for _, e := range sinkErrs {
				failuresMu.Lock()
				failures["evidence: "+e] = struct{}{}
				failuresMu.Unlock()
			}

			entry := u.entry()
			entry.Disposition = out.Disposition
			entry.Cause = out.Cause
			entry.Detail = out.Detail
			entry.EvidenceRefs = refs
			lg.add(entry)

			if out.ToolFailure != "" {
				failuresMu.Lock()
				cleanup[meta.ID+": "+out.ToolFailure] = struct{}{}
				failuresMu.Unlock()
			}
			if out.Disposition == model.DispositionBlocked && out.Cause == model.CauseTransportError {
				failuresMu.Lock()
				failures[meta.ID+": "+out.Detail] = struct{}{}
				failuresMu.Unlock()
			}

			if out.Finding != nil {
				f := *out.Finding
				f.ID = ownershipFindingID(meta.ID, u.plan)
				f.Recipe = unitRecipe(meta.ID, u.plan)
				if len(f.EvidenceRefs) == 0 {
					f.EvidenceRefs = refs
				}
				findingsMu.Lock()
				findings = append(findings, f)
				findingsMu.Unlock()
			}
		}(u)
	}

	wg.Wait()

	// Probe each identity again now that the work is done.
	//
	// A credential that expired mid-run is only ever observed by a later probe:
	// nothing announces an expiry at the moment it happens. The closing probe
	// bounds the uncertainty window at the end of the run, and any control that
	// ran inside that window is re-scored below.
	probeIdentities(ctx, opts.Identities)

	res.Coverage = lg.entries
	res.Findings = findings
	res.Identities = opts.Identities.Statuses()
	res.Coverage = append(res.Coverage, identityCoverage(res.Identities)...)
	invalidateExpiredControls(&res, controls.snapshot(), res.Identities)
	res.Ownership = summariseOwnership(res.Coverage)
	res.Ownership.Findings = ownershipFindings(res.Findings)

	// External engine work joins the ledger and the findings. A row is added
	// whether the engine succeeded or failed, because an engine that failed is
	// a class nobody assessed and silence about it is how a reader comes to
	// believe otherwise. An engine nobody enabled gets no row: it was never
	// planned work, and counting it would inflate "untested" with everything
	// this tool could conceivably have been configured to do.
	res.Engines = opts.Engines
	res.Coverage = append(res.Coverage, opts.Engines.Coverage...)

	// Discovered surface joins the ledger as untested work.
	//
	// This is the whole mechanism of the milestone. A path the specification
	// omits previously contributed no row at all, so it could not be counted or
	// missed — it was not untested, it was invisible. One row each makes it
	// visible without making it testable: nothing was planned against these,
	// because planning needs a method and an expectation and a discovered path
	// has neither.
	res.Coverage = append(res.Coverage,
		discovery.CoverageRows(DimensionPath, opts.Surface.Discovered)...)
	res.Findings = append(res.Findings, opts.Engines.Findings...)
	res.ToolFailures = append(res.ToolFailures, opts.Engines.Failures...)
	for f := range failures {
		res.ToolFailures = append(res.ToolFailures, f)
	}
	for f := range cleanup {
		res.CleanupIncomplete = append(res.CleanupIncomplete, f)
	}
	res.ClassesNotAssessed = removeEngineCovered(
		qualifyRoleClasses(qualifyOwnershipClasses(classesNotAssessed(res.Coverage), res.Ownership), res.Coverage),
		opts.Engines)
	res.FinishedAt = opts.Now()

	sortResult(&res)
	return res, nil
}

// storeExchanges persists captured evidence and returns its references.
//
// A failure to store evidence is recorded as a tool failure rather than
// discarded: a finding whose evidence could not be written is weaker than one
// whose evidence was, and the report must be able to say so.
func storeExchanges(sink func(model.Exchange) (string, error), exchanges []model.Exchange) ([]string, []string) {
	if sink == nil || len(exchanges) == 0 {
		return nil, nil
	}
	refs := make([]string, 0, len(exchanges))
	var errs []string
	for _, ex := range exchanges {
		ref, err := sink(ex)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		refs = append(refs, ref)
	}
	return refs, errs
}

// sortResult orders every slice deterministically, so that two identical runs
// produce byte-identical output and evaluation fixtures can be diffed.
func sortResult(r *Result) {
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].OperationID != r.Findings[j].OperationID {
			return r.Findings[i].OperationID < r.Findings[j].OperationID
		}
		if r.Findings[i].CheckID != r.Findings[j].CheckID {
			return r.Findings[i].CheckID < r.Findings[j].CheckID
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	sort.Slice(r.Coverage, func(i, j int) bool {
		return r.Coverage[i].Key() < r.Coverage[j].Key()
	})
	sort.Strings(r.ToolFailures)
	sort.Strings(r.CleanupIncomplete)
	sort.Strings(r.OutOfScopeHosts)
	sort.Strings(r.ClassesNotAssessed)
}

// findingID builds a stable identifier so the same finding keeps its identity
// across runs, which consumers rely on for deduplication.
func findingID(checkID, operationID string) string {
	return checkID + ":" + operationID
}

// assessedClasses maps a check to the weakness classes it covers.
var assessedClasses = map[string][]string{
	check.AuthRequiredID: {"CWE-306"},
	check.SQLInjectionID: {"CWE-89"},
	check.ReflectedXSSID: {"CWE-79"},
}

// partlyAssessed qualifies a class a check covers only in part, so the list
// says what was not looked at instead of dropping the class (ADR-0023).
var partlyAssessed = map[string]string{
	"CWE-89": " — assessed only in query and path parameters of GET operations; request bodies, " +
		"headers and other methods were not tested",
	"CWE-79": " — reflected only, in query and path parameters of GET operations; stored and " +
		"DOM-based XSS and request bodies were not tested",
}

// notableClasses are weakness classes a reader of a security report will
// reasonably assume were considered.
var notableClasses = []string{
	"CWE-284 broken access control (object level, BOLA/IDOR)",
	"CWE-285 broken function-level authorization",
	"CWE-639 authorization bypass through user-controlled key",
	"CWE-89 SQL injection",
	"CWE-79 cross-site scripting",
	"CWE-918 server-side request forgery",
	"CWE-22 path traversal",
	"CWE-352 cross-site request forgery",
	"CWE-770 missing rate limiting",
	"CWE-915 mass assignment",
	"business logic and workflow abuse",
	"multi-tenant isolation",
}

// classesNotAssessed lists what nothing in this run looked at. A class counts
// as looked at only when its check executed on at least one operation: a
// check that was registered and then blocked by the profile, or that found
// nothing to run on, assessed nothing.
func classesNotAssessed(coverage []model.CoverageEntry) []string {
	covered := map[string]bool{}
	for _, e := range coverage {
		if e.Disposition != model.DispositionExecuted {
			continue
		}
		for _, cls := range assessedClasses[e.CheckID] {
			covered[cls] = true
		}
	}
	var out []string
	for _, cls := range notableClasses {
		key := strings.SplitN(cls, " ", 2)[0]
		switch q, partial := partlyAssessed[key]; {
		case !covered[key]:
			out = append(out, cls)
		case partial:
			out = append(out, cls+q)
		}
	}
	return out
}

// qualifyRoleClasses annotates function-level authorization once cross-role
// work has run, for the same reason ownership classes are qualified: the
// routes tested are the declared ones, not the application.
func qualifyRoleClasses(classes []string, coverage []model.CoverageEntry) []string {
	var n int
	for _, e := range coverage {
		if e.Dimension == DimensionRole && e.Disposition == model.DispositionExecuted {
			n++
		}
	}
	if n == 0 {
		return classes
	}
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		if strings.HasPrefix(c, "CWE-285 ") {
			c += fmt.Sprintf(" — assessed only for the %d cross-role read(s) under access.roles; not for "+
				"any other route, role or method", n)
		}
		out = append(out, c)
	}
	return out
}

// Request pacing lives in the HTTP client rather than here.
//
// Limiting once per job was wrong: a single check issues several requests
// (baseline probes, the primary request, a repeat, a credential probe), so the
// configured rate was exceeded by roughly that factor — and getting rate limited
// is precisely how an assessment turns into a falsely clean report.

// controlUse records that one ledger row's result depended on an authenticated
// control request issued by a named identity at a known time.
type controlUse struct {
	subject    string
	checkID    string
	identityID string
	at         time.Time
	// resourceID is set for cross-owner work, whose rows are keyed by resource
	// as well as by operation.
	resourceID string
}

// controlLog accumulates control usage from concurrent checks.
type controlLog struct {
	mu   sync.Mutex
	uses []controlUse
}

func (c *controlLog) record(u controlUse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uses = append(c.uses, u)
}

func (c *controlLog) snapshot() []controlUse {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]controlUse, len(c.uses))
	copy(out, c.uses)
	return out
}

// probeIdentities runs each identity's liveness canary.
//
// A probe is best-effort by design: an identity with no canary configured
// cannot be probed, and a transport failure leaves the previous knowledge
// intact rather than declaring the credential dead because the network
// stuttered. What a probe must never do is turn an unknown into a good.
func probeIdentities(ctx context.Context, ids *identity.Set) {
	if ids == nil {
		return
	}
	for _, c := range ids.Controls() {
		if ctx.Err() != nil {
			return
		}
		c.Probe(ctx)
	}
}

// identityCoverage turns each identity's status into a ledger row.
//
// This is what makes an authentication limitation visible in the ledger rather
// than only in a finding's prose. A run whose only identity could not
// authenticate has verified less than one whose identity could, and the
// coverage account has to say so.
func identityCoverage(statuses []identity.Status) []model.CoverageEntry {
	out := make([]model.CoverageEntry, 0, len(statuses))
	for _, st := range statuses {
		e := model.CoverageEntry{
			Dimension:  DimensionIdentity,
			Subject:    st.ID,
			IdentityID: st.ID,
		}
		switch {
		case !st.Usable:
			e.Disposition = model.DispositionBlocked
			e.Cause = model.CauseMissingIdentity
			e.Detail = "the credential could not be resolved from " + st.Source + ": " + st.Problem +
				". No authenticated control request was possible, so no finding for any operation " +
				"could be corroborated against a legitimate caller"
		case st.Liveness == identity.LivenessBad:
			e.Disposition = model.DispositionBlocked
			e.Cause = model.CauseAuthenticationFailed
			e.Detail = "the identity was rejected by the target: " + st.Problem +
				". Authenticated control requests using it are not trustworthy"
		case st.Liveness == identity.LivenessGood:
			e.Disposition = model.DispositionExecuted
			e.Detail = "the liveness canary confirmed this identity authenticates successfully"
		case !st.Monitored:
			e.Disposition = model.DispositionUntested
			e.Cause = model.CauseNoOracle
			e.Detail = "no liveness canary is configured for this identity, so an expiry during the " +
				"run could not be detected. Set identities[].liveness to a safe, " +
				"authentication-requiring operation to close this gap"
		default:
			e.Disposition = model.DispositionBlocked
			e.Cause = model.CauseAuthenticationFailed
			e.Detail = "the liveness canary did not complete, so it is not known whether this " +
				"identity can authenticate"
			if st.Problem != "" {
				e.Detail += ": " + st.Problem
			}
		}
		out = append(out, e)
	}
	return out
}

// invalidateExpiredControls re-scores work that depended on an identity later
// found to be invalid.
//
// A liveness canary observes an expiry when it next runs, not when it happens,
// so the interval between the last good probe and the first bad one is a window
// in which the credential's validity is genuinely unknown. Anything corroborated
// by a control request issued inside that window is therefore corroborated by
// something that may already have been dead.
//
// Two things happen to such work, and the asymmetry is deliberate:
//
//   - The ledger row becomes blocked{authentication_failed}. The check's result
//     rested on the control, and a result resting on an untrusted control has
//     not established what it claims.
//   - A confirmed finding is demoted to suspected rather than discarded. The
//     anonymous observation behind it did not involve the credential at all, so
//     deleting the finding would hide a real unauthenticated success. Only the
//     corroboration is withdrawn.
//
// The one thing that must never happen is the reverse: an expired credential
// making an operation look protected. That cannot arise here because a finding
// is only ever raised by an anonymous success, never by an authenticated
// failure.
func invalidateExpiredControls(res *Result, uses []controlUse, statuses []identity.Status) {
	byID := make(map[string]identity.Status, len(statuses))
	for _, st := range statuses {
		if len(st.AllWindows()) > 0 {
			byID[st.ID] = st
		}
	}
	if len(byID) == 0 || len(uses) == 0 {
		return
	}

	// A control is affected when it completed inside any window in which its
	// identity's credential may not have been valid: after the last
	// confirmed-good canary, and before the identity was confirmed good again.
	// A login identity that signed in again has closed windows; one that did
	// not has an open one.
	type key struct{ subject, checkID, resourceID string }
	type hit struct {
		st identity.Status
		w  identity.Window
	}
	affected := make(map[key]hit)
	for _, u := range uses {
		st, ok := byID[u.identityID]
		if !ok {
			continue
		}
		for _, w := range st.AllWindows() {
			if u.at.IsZero() || w.Contains(u.at) {
				affected[key{u.subject, u.checkID, u.resourceID}] = hit{st, w}
				break
			}
		}
	}
	if len(affected) == 0 {
		return
	}

	for i := range res.Coverage {
		e := &res.Coverage[i]
		if e.Dimension != DimensionOperation && e.Dimension != DimensionOwnership {
			continue
		}
		h, ok := affected[key{e.Subject, e.CheckID, e.ResourceID}]
		if !ok {
			continue
		}
		e.Disposition = model.DispositionBlocked
		e.Cause = model.CauseAuthenticationFailed
		e.Detail = e.Detail + ". This result is withdrawn: identity " + h.st.ID +
			" was found invalid at " + h.w.FirstBad.UTC().Format(time.RFC3339) +
			", and the authenticated control it relied on ran after the last confirmed-good canary at " +
			windowStartLabel(h.w) + windowEndLabel(h.w) + ", so the credential may not have been valid when it was used"
	}

	for i := range res.Findings {
		f := &res.Findings[i]
		h, ok := affected[key{f.OperationID, f.CheckID, f.ResourceID}]
		if !ok {
			continue
		}
		note := "authenticated-control-request: identity " + h.st.ID + " was found invalid at " +
			h.w.FirstBad.UTC().Format(time.RFC3339) + "; the control that corroborated this finding ran " +
			"after the last confirmed-good canary at " + windowStartLabel(h.w) + windowEndLabel(h.w) +
			", so the corroboration is withdrawn and the finding is reported as suspected"
		f.Verification.Unavailable = append(f.Verification.Unavailable, note)
		if f.State == model.StateConfirmed {
			f.State = model.StateSuspected
			f.Confidence = model.ConfidenceMedium
		}
	}
}

// windowStartLabel renders a window's start, or says there was none.
func windowStartLabel(w identity.Window) string {
	if w.From.IsZero() {
		return "no point at all — the identity was never confirmed good"
	}
	return w.From.UTC().Format(time.RFC3339)
}

// windowEndLabel says when the identity was confirmed good again, if it was.
func windowEndLabel(w identity.Window) string {
	if w.To.IsZero() {
		return ""
	}
	return " and before it signed in again and was confirmed good at " + w.To.UTC().Format(time.RFC3339)
}

// unitRecipe records a cross-owner or cross-role unit for a re-run.
func unitRecipe(checkID string, p check.ResourcePlan) *model.Recipe {
	r := &model.Recipe{CheckID: checkID, Operation: model.RecipeOperationOf(p.Operation),
		IdentityID: attackerID(p)}
	if p.Owner != nil {
		r.OwnerIdentityID = p.Owner.ID()
	}
	if p.Fixture.ID != "" {
		r.Fixture = &model.RecipeFixture{ID: p.Fixture.ID, Type: p.Fixture.Type, Owner: p.Fixture.Owner,
			Provenance: string(p.Fixture.Provenance)}
	}
	return r
}

// ownershipFindingID builds a stable identifier for a cross-owner finding.
//
// It includes the resource and the non-owner, because the same operation can
// produce a different finding for a different resource or a different identity,
// and a consumer deduplicating on the id would otherwise lose all but one.
func ownershipFindingID(checkID string, p check.ResourcePlan) string {
	return strings.Join([]string{checkID, p.Subject(), p.Fixture.ID, attackerID(p)}, ":")
}

// removeEngineCovered drops classes an external engine actually assessed.
//
// "Actually" is doing the work. A capability is removed only when an engine
// completed and its normalizer reported the class as covered — which a blocked
// run, a partial run and a passive ZAP scan all decline to do. Removing a class
// because a process started would turn launching a binary into a security
// claim, which is the opposite of what this milestone is for.
//
// What is removed is also qualified rather than deleted outright: the class
// leaves the not-assessed list carrying the engine, its version and its corpus,
// because "assessed by Nuclei against these templates" and "assessed" are
// different statements.
func removeEngineCovered(classes []string, c scanner.Collection) []string {
	if len(c.Covered) == 0 {
		return classes
	}
	covered := map[string]bool{}
	for _, cap := range c.Covered {
		covered[string(cap)] = true
	}
	var by []string
	for _, o := range c.Outcomes {
		if o.Status == scanner.StatusCompleted {
			by = append(by, fmt.Sprintf("%s %s (%s)", o.Engine, o.Provenance.Version,
				o.Provenance.RuleSource))
		}
	}
	sort.Strings(by)
	qualifier := " — assessed by " + strings.Join(by, "; ") +
		", whose results are recorded as observed and are not verified by Sulayi"

	out := make([]string, 0, len(classes))
	for _, cl := range classes {
		if covered[cl] {
			out = append(out, cl+qualifier)
			continue
		}
		out = append(out, cl)
	}
	return out
}
