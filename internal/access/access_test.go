package access

import (
	"strings"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

func mustPolicy(t *testing.T, protected, public []string) *Policy {
	t.Helper()
	p, err := New(protected, public)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPatternsMatchWholeSegments(t *testing.T) {
	p := mustPolicy(t, []string{"/api/**", "/admin/*/edit"}, []string{"/api/health", "/api/auth/**"})
	for path, want := range map[string]Decision{
		"/api":                 Protected,
		"/api/orders":          Protected,
		"/api/orders/{id}":     Protected,
		"/api/health":          Public,
		"/api/health/deep":     Protected, // public /api/health is exact
		"/api/auth/login":      Public,
		"/apiv2/orders":        Undeclared, // whole segments only
		"/admin/users/edit":    Protected,
		"/admin/{id}/edit":     Protected,
		"/admin/users/edit/x":  Undeclared,
		"/":                    Undeclared,
		"/public/landing-page": Undeclared,
	} {
		if got := p.Decide(path); got != want {
			t.Errorf("%s = %s, want %s", path, decisionName(got), decisionName(want))
		}
	}
}

func TestMalformedPatternsAreRejected(t *testing.T) {
	for _, bad := range []string{"api/**", "/api/**/x", "/api/ord*", "/api/../admin", "/api?x=1", "/api#f"} {
		if err := Validate(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func op(method, path string, sec []model.SecurityRequirement) model.Operation {
	return model.Operation{ID: model.OperationID(method, path), Method: method, PathTemplate: path, Security: sec}
}

// The policy fills an expectation where none exists, corroborates one that
// agrees, and withdraws one that disagrees, reporting the disagreement rather
// than choosing a winner.
func TestApplyDeclaresCorroboratesAndReportsConflicts(t *testing.T) {
	p := mustPolicy(t, []string{"/api/**"}, []string{"/api/health"})
	protected := []model.SecurityRequirement{{Schemes: []string{"bearer"}}}
	public := []model.SecurityRequirement{}
	ops, applied := p.Apply([]model.Operation{
		op("GET", "/api/orders", nil),
		op("GET", "/api/health", nil),
		op("GET", "/api/profile", protected),
		op("GET", "/api/catalogue", public),
		op("GET", "/landing", nil),
		op("GET", "/api/me", []model.SecurityRequirement{{Schemes: []string{model.SchemeAuthenticatedNavigation}}}),
	})
	byID := map[string]model.Operation{}
	for _, o := range ops {
		byID[o.ID] = o
	}
	if o := byID["GET /api/orders"]; !o.HasScheme(model.SchemeAccessPolicy) {
		t.Errorf("an undeclared protected route did not take the policy's expectation: %+v", o.Security)
	}
	if o := byID["GET /api/health"]; o.Security == nil || !o.DeclaresPublic() {
		t.Errorf("a public route was not declared public: %+v", o.Security)
	}
	if o := byID["GET /api/profile"]; !o.HasScheme("bearer") {
		t.Errorf("an agreeing specification declaration was replaced: %+v", o.Security)
	}
	if o := byID["GET /api/catalogue"]; o.Security != nil {
		t.Errorf("a conflicting expectation was kept: %+v", o.Security)
	}
	if o := byID["GET /landing"]; o.Security != nil {
		t.Errorf("an undeclared route gained an expectation: %+v", o.Security)
	}
	if o := byID["GET /api/me"]; !o.HasScheme(model.SchemeAccessPolicy) {
		t.Errorf("the policy did not replace an inferred expectation: %+v", o.Security)
	}
	if applied.Declared != 3 || applied.Corroborated != 1 || len(applied.Conflicts) != 1 {
		t.Fatalf("applied = %+v", applied)
	}
	if !strings.Contains(applied.Conflicts[0].Detail, "specification declares it public") {
		t.Errorf("conflict detail = %q", applied.Conflicts[0].Detail)
	}
}

// A path's name is never evidence: with no policy, nothing gains an
// expectation, whatever the route is called.
func TestNoPolicyDeclaresNothing(t *testing.T) {
	var p *Policy
	ops, applied := p.Apply([]model.Operation{op("GET", "/admin", nil), op("GET", "/api/internal/keys", nil)})
	for _, o := range ops {
		if o.Security != nil {
			t.Errorf("%s gained an expectation from its name", o.ID)
		}
	}
	if applied.Declared != 0 {
		t.Errorf("applied = %+v", applied)
	}
}
