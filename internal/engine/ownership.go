package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/jaylordibe/sulayi/internal/adapter"
	"github.com/jaylordibe/sulayi/internal/check"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/resource"
)

// DimensionOwnership is the ledger dimension for cross-owner work.
//
// It is separate from the operation dimension because the two answer different
// questions. "This operation was checked for missing authentication" and
// "identity B could not read resource X through this operation" are not
// interchangeable, and a reader who cannot tell them apart will assume the
// second whenever they see the first.
const DimensionOwnership = "ownership"

// DimensionRole is the ledger dimension for cross-role work: whether an
// identity of a role a declared rule does not allow was refused a route.
const DimensionRole = "role"

// MaxOwnershipUnits bounds how much cross-owner work one run will plan.
//
// Fixtures multiply: every fixture applies to every operation it can address,
// for every identity that is not its owner. With explicitly configured fixtures
// that product is small, but the planner is where a future source of fixtures
// would make it large, so the bound exists now and is reported honestly rather
// than being discovered as a runaway run later. Work beyond the bound becomes an
// untested row, never a silent omission.
const MaxOwnershipUnits = 500

// ResourceCheck is a check whose unit of work is a resource, not an operation.
//
// It is a second interface rather than an extension of Check because the shape
// of the work genuinely differs: a Check is planned per operation and needs one
// identity, while this is planned per (operation, fixture, non-owner) and needs
// two. Folding both into one interface would give every existing check
// parameters it has no use for.
//
// It earns being an interface on the same terms Check does (ADR-0009): a test
// double is the second implementation, which is what lets this package test its
// own planning, evidence handling, finding identity, tool-failure propagation
// and cancellation without standing up an HTTP server. Testing the engine
// through a fixture application tests the fixture application.
type ResourceCheck interface {
	MetadataFor(check.ResourcePlan) check.Metadata
	RunResource(context.Context, check.ResourcePlan) check.Result
}

// ownershipUnit is one planned piece of cross-owner work together with the
// ledger row it will produce.
type ownershipUnit struct {
	plan check.ResourcePlan
	rc   ResourceCheck
	// role marks a cross-role unit, which has no owned resource.
	role bool
}

// entry renders the unit's base ledger row.
func (u ownershipUnit) entry() model.CoverageEntry {
	if u.role {
		return roleRow(u.plan, u.rc, "", "", "")
	}
	return model.CoverageEntry{
		Dimension:       DimensionOwnership,
		Subject:         u.plan.Subject(),
		CheckID:         u.rc.MetadataFor(u.plan).ID,
		IdentityID:      attackerID(u.plan),
		ResourceID:      u.plan.Fixture.ID,
		OwnerIdentityID: u.plan.Fixture.Owner,
	}
}

func attackerID(p check.ResourcePlan) string {
	if p.Attacker == nil {
		return ""
	}
	return p.Attacker.ID()
}

// planOwnership expands fixtures and identities into cross-owner units, adding a
// ledger row for everything it decides not to run.
func planOwnership(opts Options, lg *ledger) []ownershipUnit {
	if opts.ResourceCheck == nil || len(opts.Resources) == 0 {
		return nil
	}

	fixtures := make([]resource.Fixture, len(opts.Resources))
	copy(fixtures, opts.Resources)
	resource.SortFixtures(fixtures)

	// Index readable operations by path template, so a mutation unit can find
	// the operation that observes its effect.
	readByPath := map[string]model.Operation{}
	for _, op := range opts.Surface.Operations {
		if !op.IsStateChanging(opts.StateChangingOperations) && op.Method != "OPTIONS" {
			if _, seen := readByPath[op.PathTemplate]; !seen {
				readByPath[op.PathTemplate] = op
			}
		}
	}

	var units []ownershipUnit
	var capped int

	for _, f := range fixtures {
		owner, ownerOK := opts.Identities.ByID(f.Owner)
		attackers := nonOwners(opts.Identities, f)

		if !ownerOK {
			lg.add(model.CoverageEntry{
				Dimension: DimensionOwnership, Subject: "*", CheckID: check.CrossOwnerReadID,
				ResourceID: f.ID, OwnerIdentityID: f.Owner,
				Disposition: model.DispositionBlocked, Cause: model.CauseMissingIdentity,
				Detail: fmt.Sprintf("fixture %q names owner %q, which is not a configured identity, "+
					"so ownership could not be established", f.ID, f.Owner),
			})
			continue
		}
		if len(attackers) == 0 {
			lg.add(model.CoverageEntry{
				Dimension: DimensionOwnership, Subject: "*", CheckID: check.CrossOwnerReadID,
				ResourceID: f.ID, OwnerIdentityID: f.Owner,
				Disposition: model.DispositionUntested, Cause: model.CauseMissingIdentity,
				Detail: fmt.Sprintf("fixture %q has no non-owner identity to probe with. A cross-owner "+
					"boundary needs a second identity; configure one, or list one in "+
					"resources[].nonOwners", f.ID),
			})
			continue
		}

		var addressable int
		for _, op := range opts.Surface.Operations {
			if !f.AppliesTo(op) {
				continue
			}
			binding, err := resource.Bind(op, f.Values)
			if err != nil {
				// Only report a fixture that was aimed at this operation
				// explicitly; otherwise every fixture would emit a row for every
				// operation in the specification.
				if len(f.Operations) > 0 {
					lg.add(model.CoverageEntry{
						Dimension: DimensionOwnership, Subject: op.ID, CheckID: check.CrossOwnerReadID,
						ResourceID: f.ID, OwnerIdentityID: f.Owner,
						Disposition: model.DispositionBlocked, Cause: model.CauseMissingResource,
						Detail: fmt.Sprintf("fixture %q cannot address this operation: %v", f.ID, err),
					})
				}
				continue
			}
			addressable++

			mutating := !model.IsSafeMethod(op.Method)
			stateChanging := op.IsStateChanging(opts.StateChangingOperations)
			for _, attacker := range attackers {
				plan := check.ResourcePlan{
					Operation: op, Fixture: f, URL: binding.URL,
					Owner: owner, Attacker: attacker, Mutate: mutating,
					FrameworkControl: frameworkControlFor(opts.Surface, op.ID),
				}
				if mutating {
					if f.Mutation == nil {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionUntested,
							model.CauseNoOracle,
							fmt.Sprintf("fixture %q configures no mutation values, so no write was "+
								"attempted. Set resources[].mutation.values to test whether a "+
								"non-owner can change this resource", f.ID)))
						continue
					}
					readOp, haveRead := readByPath[op.PathTemplate]
					if !haveRead {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked,
							model.CauseNoOracle,
							"no readable operation addresses this resource, so an unauthorized write "+
								"could not be verified by observing the owner's view of it. A write is "+
								"never confirmed from its own response status"))
						continue
					}
					readBinding, rerr := resource.Bind(readOp, f.Values)
					if rerr != nil {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked,
							model.CauseMissingResource,
							fmt.Sprintf("the readable operation for this resource could not be "+
								"addressed: %v", rerr)))
						continue
					}
					plan.ReadOperation = readOp
					plan.ReadURL = readBinding.URL
				}

				if op.MatchesAnyID(opts.ExcludeOperations) {
					lg.add(planRow(plan, opts.ResourceCheck, model.DispositionUntested,
						model.CauseSafetyPolicy, "excluded by configuration"))
					continue
				}

				required, why := ownershipRequiredProfile(op, f, mutating, stateChanging)
				if allowed, cause := model.GateProfile(opts.Profile, required); !allowed {
					lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked, cause,
						fmt.Sprintf("%s requires the %s profile; the effective profile is %s. "+
							"It was not attempted", why, required, opts.Profile)))
					continue
				}

				if len(units) >= MaxOwnershipUnits {
					capped++
					lg.add(planRow(plan, opts.ResourceCheck, model.DispositionUntested,
						model.CauseSafetyPolicy,
						fmt.Sprintf("this run planned more than %d cross-owner units and stopped "+
							"expanding. Narrow resources[].operations or resources[].nonOwners",
							MaxOwnershipUnits)))
					continue
				}
				// Below aggressive, the HTTP client refuses every state-changing
				// request it was not told about. Register exactly this one: the
				// method, the bound URL, and the fields the fixture may change.
				// The owner's restoring write is the same request with a subset
				// of those fields, so it needs no grant of its own.
				if stateChanging && opts.Profile == model.ProfileStandard {
					if opts.Guard == nil {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked,
							model.CauseSafetyPolicy, "no safety guard is configured to register this "+
								"disposable fixture request, so it would be refused"))
						continue
					}
					if err := opts.Guard.Grant(op.Method, plan.URL, mutationFields(f)); err != nil {
						lg.add(planRow(plan, opts.ResourceCheck, model.DispositionBlocked,
							model.CauseSafetyPolicy, "the request could not be registered as a "+
								"disposable fixture request: "+err.Error()))
						continue
					}
				}
				units = append(units, ownershipUnit{plan: plan, rc: opts.ResourceCheck})
			}
		}

		if addressable == 0 {
			lg.add(model.CoverageEntry{
				Dimension: DimensionOwnership, Subject: "*", CheckID: check.CrossOwnerReadID,
				ResourceID: f.ID, OwnerIdentityID: f.Owner,
				Disposition: model.DispositionUntested, Cause: model.CauseMissingResource,
				Detail: fmt.Sprintf("no operation in the specification can be addressed with fixture "+
					"%q's values. Check that resources[].values names the operation's path "+
					"parameters exactly", f.ID),
			})
		}
	}
	return units
}

// planRoles expands access.roles rules into cross-role units: for each read
// under a rule, every identity whose role is not allowed is compared with one
// whose role is. Only GET is planned; a state-changing route under a rule is
// recorded as untested rather than probed, because proving it reachable would
// do what it does. A path no rule matches has no expectation and is not
// planned. planned counts the units already planned, for the shared bound.
func planRoles(opts Options, lg *ledger, planned int) []ownershipUnit {
	if opts.RoleCheck == nil || !opts.RoleRules.HasRoles() || opts.Identities == nil {
		return nil
	}
	fixtures := make([]resource.Fixture, len(opts.Resources))
	copy(fixtures, opts.Resources)
	resource.SortFixtures(fixtures)

	var units []ownershipUnit
	for _, op := range opts.Surface.Operations {
		rule, ok := opts.RoleRules.Role(op.AbsolutePath())
		if !ok {
			continue
		}
		var allowed, others []*identity.Control
		for _, c := range opts.Identities.Controls() {
			if rule.Allows(c.Role()) {
				allowed = append(allowed, c)
			} else {
				others = append(others, c)
			}
		}
		if len(others) == 0 {
			continue
		}
		base := check.ResourcePlan{Operation: op}
		if len(allowed) > 0 {
			base.Owner = allowed[0]
		}
		skip := func(d model.Disposition, cause model.BlockedCause, detail string) {
			for _, a := range others {
				p := base
				p.Attacker = a
				e := roleRow(p, opts.RoleCheck, d, cause, detail)
				lg.add(e)
			}
		}
		if op.Method != "GET" || op.IsStateChanging(opts.StateChangingOperations) {
			skip(model.DispositionUntested, model.CauseSafetyPolicy, fmt.Sprintf("%s is under an "+
				"access.roles rule, but only reads are probed across roles: proving a state-changing route "+
				"reachable would perform it", op.ID))
			continue
		}
		if op.MatchesAnyID(opts.ExcludeOperations) {
			skip(model.DispositionUntested, model.CauseSafetyPolicy, "excluded by configuration")
			continue
		}
		// The same rule as operation planning: a sign-out or other
		// authentication route requested as the baseline identity could end
		// the session every later unit, and the cleanup, depends on.
		if opts.ExcludeAuthEndpoints &&
			(model.LooksLikeAuthRoute(op.PathTemplate) || model.LooksLikeAuthRoute(op.AbsolutePath())) {
			skip(model.DispositionUntested, model.CauseSafetyPolicy, "skipped because the path looks like "+
				"an authentication or sign-out route; requesting it could end the session the run depends on")
			continue
		}
		if base.Owner == nil {
			skip(model.DispositionBlocked, model.CauseNoOracle, fmt.Sprintf("no configured identity has "+
				"a role access.roles allows for %s (%v), so there is no baseline to compare with",
				op.ID, rule.Allow))
			continue
		}
		u, fixtureID, err := roleURL(op, fixtures)
		if err != nil {
			skip(model.DispositionBlocked, model.CauseMissingResource, "no record or fixture can fill "+
				"this route's path parameters: "+err.Error())
			continue
		}
		base.URL = u
		base.Fixture = resource.Fixture{ID: fixtureID}
		for _, a := range others {
			p := base
			p.Attacker = a
			if planned+len(units) >= MaxOwnershipUnits {
				lg.add(roleRow(p, opts.RoleCheck, model.DispositionUntested, model.CauseSafetyPolicy,
					fmt.Sprintf("this run planned more than %d authorization units and stopped expanding",
						MaxOwnershipUnits)))
				continue
			}
			units = append(units, ownershipUnit{plan: p, rc: opts.RoleCheck, role: true})
		}
	}
	return units
}

// roleURL addresses a route: directly when it has no path parameter, or
// through the first fixture that names it in its operations.
func roleURL(op model.Operation, fixtures []resource.Fixture) (string, string, error) {
	if len(op.RequiredPathParams()) == 0 {
		b, err := resource.Bind(op, nil)
		return b.URL, "", err
	}
	var last error = fmt.Errorf("no fixture or created record applies to it")
	for _, f := range fixtures {
		// A fixture fills a route only where it applies: filling parameters by
		// name alone would put a device token's id into an audit-log route.
		if !f.AppliesTo(op) || len(f.Operations) == 0 {
			continue
		}
		b, err := resource.Bind(op, f.Values)
		if err == nil {
			return b.URL, f.ID, nil
		}
		last = err
	}
	return "", "", last
}

// roleRow renders a cross-role ledger row.
func roleRow(p check.ResourcePlan, rc ResourceCheck, d model.Disposition, cause model.BlockedCause, detail string) model.CoverageEntry {
	return model.CoverageEntry{
		Dimension:   DimensionRole,
		Subject:     p.Subject(),
		CheckID:     rc.MetadataFor(p).ID,
		IdentityID:  attackerID(p),
		ResourceID:  p.Fixture.ID,
		Disposition: d,
		Cause:       cause,
		Detail:      detail,
	}
}

// planRow renders a ledger row for a unit that will not run.
// ownershipRequiredProfile decides the profile a cross-owner unit needs, and
// says why in words a ledger reader can act on.
//
// A request that cannot change state needs only safe. A write needs standard
// only when its fixture is registered as disposable: that is the one case where
// the operator has said this exact record may be changed. Everything else that
// changes state — a write to a fixture not declared disposable, or a read-only
// method the operator has named as state-changing — needs aggressive.
func ownershipRequiredProfile(op model.Operation, f resource.Fixture, mutating, stateChanging bool) (model.Profile, string) {
	switch {
	case !stateChanging:
		return model.ProfileSafe, "this read"
	case mutating && f.Disposable && op.Method != "DELETE":
		return model.ProfileStandard, fmt.Sprintf("a cross-owner %s against disposable fixture %q", op.Method, f.ID)
	case mutating:
		return model.ProfileAggressive, fmt.Sprintf("a cross-owner %s against fixture %q, which is not "+
			"declared disposable (resources[].disposable),", op.Method, f.ID)
	default:
		return model.ProfileAggressive, "an operation configured in assessment.stateChangingOperations"
	}
}

// mutationFields lists the body fields a fixture is configured to change.
func mutationFields(f resource.Fixture) []string {
	if f.Mutation == nil {
		return nil
	}
	fields := make([]string, 0, len(f.Mutation.Values))
	for k := range f.Mutation.Values {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	return fields
}

func planRow(p check.ResourcePlan, rc ResourceCheck, d model.Disposition, cause model.BlockedCause, detail string) model.CoverageEntry {
	return model.CoverageEntry{
		Dimension:       DimensionOwnership,
		Subject:         p.Subject(),
		CheckID:         rc.MetadataFor(p).ID,
		IdentityID:      attackerID(p),
		ResourceID:      p.Fixture.ID,
		OwnerIdentityID: p.Fixture.Owner,
		Disposition:     d,
		Cause:           cause,
		Detail:          detail,
	}
}

// nonOwners returns the identities that should probe a fixture.
func nonOwners(set *identity.Set, f resource.Fixture) []*identity.Control {
	if set == nil {
		return nil
	}
	if len(f.NonOwners) > 0 {
		var out []*identity.Control
		for _, id := range f.NonOwners {
			if c, ok := set.ByID(id); ok && id != f.Owner {
				out = append(out, c)
			}
		}
		return out
	}
	var out []*identity.Control
	for _, c := range set.Controls() {
		if c.ID() != f.Owner {
			out = append(out, c)
		}
	}
	return out
}

// fixtureLocks serialises work that touches the same resource.
//
// Two units probing one fixture concurrently would interleave: a read's owner
// re-check could observe a write from another unit, and a write's before/after
// comparison could attribute somebody else's change to itself. Serialising per
// fixture — rather than serialising the whole engine — keeps different resources
// running in parallel while making each resource's sequence of observations
// mean what it says.
type fixtureLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func newFixtureLocks() *fixtureLocks { return &fixtureLocks{m: map[string]*sync.Mutex{}} }

func (f *fixtureLocks) get(id string) *sync.Mutex {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.m[id]; ok {
		return l
	}
	l := &sync.Mutex{}
	f.m[id] = l
	return l
}

// OwnershipSummary describes exactly which boundaries were tested.
//
// It is a list rather than a percentage. There is no denominator: the number of
// ownership boundaries an application has is unknown and unknowable from a
// specification, so any percentage would be invented. What can be stated
// truthfully is which tuples were exercised and which were not.
type OwnershipSummary struct {
	// Verified counts boundaries where a non-owner was demonstrably refused.
	Verified int
	// Findings counts boundaries where a non-owner was not refused.
	Findings int
	// Blocked counts units that could not establish anything.
	Blocked int
	// Untested counts units that were planned and deliberately not run.
	Untested int
	// Statement says in words what the numbers do and do not mean.
	Statement string
	// Boundaries lists each tested tuple, so a reader can see the actual extent.
	Boundaries []string
}

// summariseOwnership builds the ownership account from the ledger.
func summariseOwnership(entries []model.CoverageEntry) OwnershipSummary {
	var s OwnershipSummary
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Dimension != DimensionOwnership {
			continue
		}
		switch e.Disposition {
		case model.DispositionExecuted:
			s.Verified++
		case model.DispositionBlocked:
			s.Blocked++
		case model.DispositionUntested:
			s.Untested++
		}
		if e.Disposition == model.DispositionExecuted && e.ResourceID != "" {
			key := fmt.Sprintf("%s may not reach %s (owned by %s) via %s",
				e.IdentityID, e.ResourceID, e.OwnerIdentityID, e.Subject)
			if !seen[key] {
				seen[key] = true
				s.Boundaries = append(s.Boundaries, key)
			}
		}
	}
	sort.Strings(s.Boundaries)

	total := s.Verified + s.Blocked + s.Untested
	switch {
	case total == 0:
		s.Statement = "No resource fixtures were configured, so no ownership boundary was tested. " +
			"Nothing in this report says anything about whether one identity can reach another's data."
	default:
		// Position-neutral wording: this sentence is rendered above the list in
		// JSON and below it in the terminal, and a report that misdescribes its
		// own layout invites the reader to distrust the rest of it.
		s.Statement = fmt.Sprintf("This run exercised %d cross-owner boundary check(s), each named "+
			"individually, against the configured fixtures. It says nothing about any other "+
			"resource, any other identity pair, or any operation not named: an ownership boundary "+
			"that held here does not imply that the application enforces ownership anywhere else.",
			s.Verified)
	}
	return s
}

// ownershipFindings counts findings attributable to cross-owner checks.
func ownershipFindings(findings []model.Finding) int {
	n := 0
	for _, f := range findings {
		if strings.HasPrefix(f.CheckID, "cross-owner-") {
			n++
		}
	}
	return n
}

// ownershipClasses are the weakness classes cross-owner work examines.
var ownershipClasses = []string{
	"CWE-284 broken access control (object level, BOLA/IDOR)",
	"CWE-639 authorization bypass through user-controlled key",
}

// qualifyOwnershipClasses annotates the not-assessed list once cross-owner work
// has actually run.
//
// The entries are qualified rather than removed. Removing them would say object-
// level authorization was covered, when what happened is that it was tested for
// the handful of resources somebody configured — which is a completely different
// claim, and the more flattering of the two. Leaving them untouched would be
// wrong in the other direction: the boundaries genuinely were probed.
//
// So the class stays on the list, with the extent attached to it.
func qualifyOwnershipClasses(classes []string, o OwnershipSummary) []string {
	if o.Verified == 0 {
		return classes
	}
	qualifier := fmt.Sprintf(" — assessed only for the %d cross-owner boundary check(s) listed under "+
		"ownership; not assessed for any other resource, identity pair or operation", o.Verified)
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		qualified := c
		for _, oc := range ownershipClasses {
			if c == oc {
				qualified = c + qualifier
				break
			}
		}
		out = append(out, qualified)
	}
	return out
}

// frameworkControlFor returns the authorization control a framework adapter
// found on an operation, if one did.
//
// Only a positive finding is carried through. An adapter reporting "absent"
// says it saw no control, which is not the same as there being none — the
// adapter's own limitations say why — and passing that along would invite a
// reader to treat a blind spot as a fact.
func frameworkControlFor(surface Surface, operationID string) string {
	for _, m := range surface.AdapterMerges {
		if m.OperationID != operationID || m.Kind != adapter.KindAuthorization {
			continue
		}
		if m.AdapterValue != adapter.AuthorizationPresent {
			continue
		}
		if m.Evidence.Detail != "" {
			return m.Evidence.Detail + " (reported by adapter " + m.Adapter + ")"
		}
		return "an authorization control reported by adapter " + m.Adapter
	}
	return ""
}
