// Package access applies the operator's declared access policy: which routes
// require authentication and which are public.
//
// It is the oracle for a surface no specification describes. A declared policy
// is a statement of what should happen, with the same standing as a
// specification's security declaration — never evidence that anything is
// wrong. A finding against it is confirmed only by the same verification as any
// other.
package access

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jaylordibe/sulayi/internal/model"
)

// Decision is what the policy says about one path.
type Decision int

const (
	// Undeclared means no pattern matches.
	Undeclared Decision = iota
	// Protected means the route requires authentication.
	Protected
	// Public means the route is meant to be reachable without credentials.
	Public
)

// Policy is a set of protected and public path patterns. Public patterns are
// exceptions to protected ones: protected /api/** with public /api/health
// means everything under /api except /api/health requires authentication.
type Policy struct {
	protected []pattern
	public    []pattern
}

type pattern struct {
	raw      string
	segments []string
}

// New compiles a policy, rejecting malformed patterns.
func New(protected, public []string) (*Policy, error) {
	p := &Policy{}
	for _, raw := range protected {
		pat, err := compile(raw)
		if err != nil {
			return nil, err
		}
		p.protected = append(p.protected, pat)
	}
	for _, raw := range public {
		pat, err := compile(raw)
		if err != nil {
			return nil, err
		}
		p.public = append(p.public, pat)
	}
	return p, nil
}

// Validate reports whether a pattern is well-formed, for configuration
// validation.
func Validate(raw string) error {
	_, err := compile(raw)
	return err
}

func compile(raw string) (pattern, error) {
	if !strings.HasPrefix(raw, "/") {
		return pattern{}, fmt.Errorf("access pattern %q must begin with /", raw)
	}
	if strings.ContainsAny(raw, "?#\\") {
		return pattern{}, fmt.Errorf("access pattern %q may contain only a path", raw)
	}
	segs := strings.Split(strings.Trim(raw, "/"), "/")
	if raw == "/" {
		segs = nil
	}
	for i, s := range segs {
		switch {
		case s == "**" && i != len(segs)-1:
			return pattern{}, fmt.Errorf("access pattern %q may use ** only as its last segment", raw)
		case s == "." || s == "..":
			return pattern{}, fmt.Errorf("access pattern %q may not contain a dot segment", raw)
		case strings.Contains(s, "*") && s != "*" && s != "**":
			return pattern{}, errors.New("access pattern " + fmt.Sprintf("%q", raw) +
				" may use * and ** only as whole segments")
		}
	}
	return pattern{raw: raw, segments: segs}, nil
}

// match reports whether a path — concrete, or a template with {param}
// segments — fits the pattern. A * matches one segment, a template parameter
// included; ** matches any number of trailing segments, including none.
func (p pattern) match(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if strings.Trim(path, "/") == "" {
		segs = nil
	}
	for i, ps := range p.segments {
		if ps == "**" {
			return true
		}
		if i >= len(segs) {
			return false
		}
		if ps != "*" && ps != segs[i] {
			return false
		}
	}
	return len(segs) == len(p.segments)
}

// Decide says what the policy declares about a path.
func (p *Policy) Decide(path string) Decision {
	if p == nil {
		return Undeclared
	}
	for _, pat := range p.public {
		if pat.match(path) {
			return Public
		}
	}
	for _, pat := range p.protected {
		if pat.match(path) {
			return Protected
		}
	}
	return Undeclared
}

// Empty reports whether the policy declares nothing.
func (p *Policy) Empty() bool { return p == nil || (len(p.protected) == 0 && len(p.public) == 0) }

// Conflict is an operation on which the policy and another source disagree.
type Conflict struct {
	OperationID string
	Detail      string
}

// Applied summarises what applying the policy did.
type Applied struct {
	// Declared counts operations that gained an expectation from the policy.
	Declared int
	// Corroborated counts operations whose existing expectation the policy
	// agrees with.
	Corroborated int
	// Conflicts are operations whose expectation was withdrawn because the
	// policy and the specification or an adapter disagree.
	Conflicts []Conflict
}

// Apply gives operations the policy's expectation.
//
// An operation with no expectation takes the policy's. One whose specification
// or adapter agrees is corroborated. One where they disagree loses its
// expectation entirely and the disagreement is reported: choosing a winner
// would mean deciding without evidence which statement about the application is
// wrong. The operation is matched on the path the application serves.
func (p *Policy) Apply(ops []model.Operation) ([]model.Operation, Applied) {
	var out Applied
	if p.Empty() {
		return ops, out
	}
	res := make([]model.Operation, len(ops))
	copy(res, ops)
	for i := range res {
		op := &res[i]
		decision := p.Decide(op.AbsolutePath())
		if decision == Undeclared {
			continue
		}
		existing := Undeclared
		switch {
		case op.Security == nil:
		case op.DeclaresAuthRequired():
			existing = Protected
		default:
			existing = Public
		}
		// An expectation inferred from navigation is not a statement anyone
		// made; the policy replaces it rather than conflicting with it.
		if op.HasScheme(model.SchemeAuthenticatedNavigation) {
			existing = Undeclared
		}
		switch {
		case existing == Undeclared:
			if decision == Protected {
				op.Security = []model.SecurityRequirement{{Schemes: []string{model.SchemeAccessPolicy}}}
			} else {
				op.Security = []model.SecurityRequirement{}
			}
			op.Sources = append(op.Sources, model.Source{Kind: model.SourceAccessPolicy,
				Ref: "access." + decisionName(decision)})
			out.Declared++
		case existing == decision:
			op.Sources = append(op.Sources, model.Source{Kind: model.SourceAccessPolicy,
				Ref: "access." + decisionName(decision)})
			out.Corroborated++
		default:
			out.Conflicts = append(out.Conflicts, Conflict{
				OperationID: op.ID,
				Detail: fmt.Sprintf("the access policy declares %s %s, but its %s declares it %s; "+
					"neither is used as an oracle and the disagreement is reported instead",
					op.AbsolutePath(), decisionName(decision), sourceName(*op), decisionName(existing)),
			})
			op.Security = nil
		}
	}
	sort.Slice(out.Conflicts, func(i, j int) bool { return out.Conflicts[i].OperationID < out.Conflicts[j].OperationID })
	return res, out
}

func decisionName(d Decision) string {
	switch d {
	case Protected:
		return "protected"
	case Public:
		return "public"
	}
	return "undeclared"
}

func sourceName(op model.Operation) string {
	if inferred, _ := op.InferredExpectation(); inferred {
		return "framework adapter"
	}
	return "specification"
}
