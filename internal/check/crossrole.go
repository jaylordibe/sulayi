package check

import (
	"context"
	"fmt"
	"time"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/outcome"
)

// CrossRoleReadID identifies the function-level authorization check.
const CrossRoleReadID = "cross-role-read"

// CrossRole tests whether an identity whose role a declared rule does not
// allow can call a route that identities of an allowed role can (ADR-0022).
//
// This is CWE-285 / OWASP API5. The plan reuses ResourcePlan: Owner is the
// identity of an allowed role, whose success is the baseline, and Attacker is
// the identity that should be refused. Only reads are planned: the routes worth
// protecting by role include resetting another account's password and deleting
// users, and proving those reachable would do the damage.
type CrossRole struct {
	Signals outcome.Signals
	// Now supplies the clock, injected so runs are reproducible.
	Now func() time.Time
}

func (c CrossRole) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Metadata describes the check.
func (CrossRole) Metadata() Metadata {
	return Metadata{
		ID:    CrossRoleReadID,
		Title: "A route restricted to other roles is readable by this identity",
		CWE:   []string{"CWE-285"},
		OWASP: []string{"API5:2023 Broken Function Level Authorization"},
	}
}

// MetadataFor returns the metadata for a plan.
func (c CrossRole) MetadataFor(ResourcePlan) Metadata { return c.Metadata() }

// RunResource executes one cross-role unit: the allowed identity's request,
// then the disallowed identity's.
func (c CrossRole) RunResource(ctx context.Context, p ResourcePlan) Result {
	var exchanges []model.Exchange
	uses := []ControlUse{}
	block := func(cause model.BlockedCause, detail string) Result {
		return Result{Disposition: model.DispositionBlocked, Cause: cause, Detail: detail,
			Exchanges: exchanges, ControlsUsed: uses}
	}
	if p.Owner == nil || p.Attacker == nil {
		return block(model.CauseMissingIdentity, "a cross-role test needs an identity of an allowed role "+
			"and one of a role that is not, and one of them is not configured")
	}
	if ok, cause, why := p.Owner.Usable(); !ok {
		return block(cause, "the allowed identity "+p.Owner.ID()+" cannot be used, so there is no baseline: "+why)
	}
	if ok, cause, why := p.Attacker.Usable(); !ok {
		return block(cause, "the identity "+p.Attacker.ID()+" cannot be used, so its refusal would be an "+
			"authentication failure rather than an authorization decision: "+why)
	}

	// The baseline. A route the allowed role cannot read either says nothing
	// about who else may read it.
	allowedEx, err := p.Owner.Do(ctx, p.Operation.Method, p.URL, probeHeaders())
	if allowedEx.Request.URL != "" {
		exchanges = append(exchanges, allowedEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Owner.ID(), At: c.now()})
	if err != nil || allowedEx.Response == nil {
		return block(transportCause(err), "the allowed identity's request could not be completed: "+summarize(err))
	}
	if cls := outcome.Classify(allowedEx.Response, c.Signals); cls.Outcome != model.OutcomeAllowed {
		p.Owner.NoteSuspicious(ctx)
		return block(model.CauseNoOracle, fmt.Sprintf("the allowed identity %s could not read this route "+
			"(%s), so there is no baseline to compare %s with", p.Owner.ID(), cls.Reason, p.Attacker.ID()))
	}
	if cache := cacheFingerprint(allowedEx.Response); cache != "" {
		return block(model.CauseIndeterminateOutcome, "the allowed identity's response was served from a "+
			"cache ("+cache+"), so it could be replayed to the other identity by the same intermediary")
	}

	probeEx, err := p.Attacker.Do(ctx, p.Operation.Method, p.URL, probeHeaders())
	if probeEx.Request.URL != "" {
		exchanges = append(exchanges, probeEx)
	}
	uses = append(uses, ControlUse{IdentityID: p.Attacker.ID(), At: c.now()})
	if err != nil || probeEx.Response == nil {
		return block(transportCause(err), "the cross-role request could not be completed: "+summarize(err))
	}
	cls := outcome.Classify(probeEx.Response, c.Signals)
	switch cls.Outcome {
	case model.OutcomeDenied, model.OutcomeNotFound:
		return Result{
			Disposition: model.DispositionExecuted,
			Detail: fmt.Sprintf("the role boundary held: %s (role %q) read this route and %s (role %q) "+
				"was refused (%s)", p.Owner.ID(), p.Owner.Role(), p.Attacker.ID(), p.Attacker.Role(), cls.Reason),
			Exchanges: exchanges, ControlsUsed: uses,
		}
	case model.OutcomeRateLimited:
		return block(model.CauseRateLimited, "the target is rate limiting, so a refusal cannot be "+
			"distinguished from a block")
	case model.OutcomeError:
		return block(model.CauseTransportError, "the target returned an error to the cross-role request: "+cls.Reason)
	case model.OutcomeIndeterminate:
		return block(model.CauseIndeterminateOutcome, "the cross-role response could not be classified "+
			"as access granted or refused: "+cls.Reason)
	}
	return c.judge(p, allowedEx, probeEx, exchanges, uses, cls)
}

// judge decides between confirmed and suspected. Confirmation needs the
// disallowed identity to have received what the allowed one did; a different
// success may be the application legitimately narrowing the answer to the
// caller's own data, so it stays suspected.
func (c CrossRole) judge(p ResourcePlan, allowedEx, probeEx model.Exchange, exchanges []model.Exchange,
	uses []ControlUse, cls outcome.Classification) Result {
	eq := materiallyEquivalent(allowedEx.Response, probeEx.Response)
	cache := cacheFingerprint(probeEx.Response)
	steps := []model.VerificationStep{
		{Name: "allowed-role-baseline-established", Passed: true,
			Detail: p.Owner.ID() + " (role " + p.Owner.Role() + ") read the route"},
		{Name: "identity-live", Passed: true,
			Detail: p.Attacker.ID() + " authenticates successfully, so its access was not an authentication artefact"},
		{Name: "access-granted", Passed: true, Detail: cls.Reason},
		{Name: "materially-equivalent-to-allowed-response", Passed: eq.Equivalent, Detail: eq.Reason},
		{Name: "not-served-from-cache", Passed: cache == "", Detail: cacheOrNone(cache)},
	}
	confirmed := eq.Equivalent && cache == ""
	state, confidence := model.StateSuspected, model.ConfidenceMedium
	result := "the identity was not refused, but its response differed from the allowed role's, which " +
		"may be the application narrowing the answer to the caller's own data"
	var unavailable []string
	if !eq.Equivalent {
		unavailable = append(unavailable, "allowed-role-comparison: "+eq.Reason)
	}
	if cache != "" {
		unavailable = append(unavailable, "cross-role-response: served from a cache ("+cache+")")
	}
	if confirmed {
		state, confidence = model.StateConfirmed, model.ConfidenceHigh
		result = "the identity received what the allowed role received"
	}
	finding := &model.Finding{
		CheckID:     CrossRoleReadID,
		Title:       "A route restricted to other roles is readable by this identity",
		State:       state,
		Severity:    model.SeverityHigh,
		Confidence:  confidence,
		CWE:         []string{"CWE-285"},
		OWASP:       []string{"API5:2023 Broken Function Level Authorization"},
		OperationID: p.Operation.ID,
		IdentityID:  p.Attacker.ID(),
		Expected: fmt.Sprintf("access.roles allows only other roles to call %s, so %s (role %q) should "+
			"have been refused", p.Operation.ID, p.Attacker.ID(), p.Attacker.Role()),
		Actual: fmt.Sprintf("%s (role %q) read the route: %s", p.Attacker.ID(), p.Attacker.Role(), result),
		Verification: model.VerificationRecord{
			Strategy:    "allowed-role-baseline-then-cross-role-probe",
			Steps:       steps,
			Performed:   true,
			Result:      result,
			Unavailable: unavailable,
		},
		Remediation: "Enforce the role or permission this route requires on the server, for every caller, " +
			"rather than relying on the client not offering it.",
		Reproduction: []string{
			fmt.Sprintf("%s %s as %s (role %s) — succeeds", p.Operation.Method, p.URL, p.Owner.ID(), p.Owner.Role()),
			fmt.Sprintf("%s %s as %s (role %s) — also succeeds", p.Operation.Method, p.URL, p.Attacker.ID(), p.Attacker.Role()),
		},
	}
	return Result{
		Disposition:  model.DispositionExecuted,
		Detail:       fmt.Sprintf("%s (role %q) was not refused: %s", p.Attacker.ID(), p.Attacker.Role(), result),
		Finding:      finding,
		Exchanges:    exchanges,
		ControlsUsed: uses,
	}
}

func cacheOrNone(cache string) string {
	if cache == "" {
		return "no cache-hit indicators present"
	}
	return cache
}
