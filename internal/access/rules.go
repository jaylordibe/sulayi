package access

import "fmt"

// Rules are the operator's declared authorization expectations beyond "signed
// in or not" (ADR-0022): which records belong to the identity that created
// them, and which routes only certain roles may call. Like the rest of the
// policy they state expected behaviour and are never evidence. A path no rule
// matches has no expectation, and nothing is concluded about it.
type Rules struct {
	owned []OwnedRule
	roles []RoleRule
}

// OwnedRule declares that records under its patterns belong to their creator.
type OwnedRule struct {
	// Index is the rule's position in access.owned.
	Index    int
	patterns []pattern
	// ReachableBy lists the roles that may reach other identities' records by
	// design, such as an administrator whose permissions cover every record.
	ReachableBy []string
}

// RoleRule declares that routes under its patterns may be called only by the
// roles it allows.
type RoleRule struct {
	patterns []pattern
	Allow    []string
}

// OwnedSpec and RoleSpec are the uncompiled rules, as configured.
type OwnedSpec struct {
	Paths       []string
	ReachableBy []string
}

// RoleSpec is one uncompiled role rule.
type RoleSpec struct {
	Paths []string
	Allow []string
}

// NewRules compiles the rules, rejecting malformed patterns and empty rules.
func NewRules(owned []OwnedSpec, roles []RoleSpec) (*Rules, error) {
	r := &Rules{}
	for i, o := range owned {
		pats, err := compileAll(o.Paths)
		if err != nil {
			return nil, fmt.Errorf("access.owned[%d]: %w", i, err)
		}
		r.owned = append(r.owned, OwnedRule{Index: i, patterns: pats, ReachableBy: o.ReachableBy})
	}
	for i, ro := range roles {
		pats, err := compileAll(ro.Paths)
		if err != nil {
			return nil, fmt.Errorf("access.roles[%d]: %w", i, err)
		}
		if len(ro.Allow) == 0 {
			return nil, fmt.Errorf("access.roles[%d].allow must name at least one role", i)
		}
		r.roles = append(r.roles, RoleRule{patterns: pats, Allow: ro.Allow})
	}
	return r, nil
}

func compileAll(raw []string) ([]pattern, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("paths must name at least one pattern")
	}
	out := make([]pattern, 0, len(raw))
	for _, p := range raw {
		pat, err := compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pat)
	}
	return out, nil
}

func matchAny(pats []pattern, path string) bool {
	for _, p := range pats {
		if p.match(path) {
			return true
		}
	}
	return false
}

// Owned returns the first owned rule matching an application path.
func (r *Rules) Owned(path string) (OwnedRule, bool) {
	if r == nil {
		return OwnedRule{}, false
	}
	for _, o := range r.owned {
		if matchAny(o.patterns, path) {
			return o, true
		}
	}
	return OwnedRule{}, false
}

// Role returns the first role rule matching an application path.
func (r *Rules) Role(path string) (RoleRule, bool) {
	if r == nil {
		return RoleRule{}, false
	}
	for _, ro := range r.roles {
		if matchAny(ro.patterns, path) {
			return ro, true
		}
	}
	return RoleRule{}, false
}

// Reaches reports whether an identity with this role may reach other
// identities' records under the rule.
func (o OwnedRule) Reaches(role string) bool { return role != "" && contains(o.ReachableBy, role) }

// Allows reports whether an identity with this role may call the route.
func (r RoleRule) Allows(role string) bool { return role != "" && contains(r.Allow, role) }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Empty reports whether no rule is declared.
func (r *Rules) Empty() bool { return r == nil || (len(r.owned) == 0 && len(r.roles) == 0) }

// HasRoles reports whether any role rule is declared.
func (r *Rules) HasRoles() bool { return r != nil && len(r.roles) > 0 }
