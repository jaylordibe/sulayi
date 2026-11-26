package access

import "testing"

func TestRulesMatchFirstAndCompareRoles(t *testing.T) {
	r, err := NewRules(
		[]OwnedSpec{{Paths: []string{"/api/tokens/*"}, ReachableBy: []string{"admin"}}},
		[]RoleSpec{{Paths: []string{"/api/admin/**"}, Allow: []string{"admin"}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	o, ok := r.Owned("/api/tokens/{id}")
	if !ok || !o.Reaches("admin") || o.Reaches("user") || o.Reaches("") {
		t.Errorf("owned rule = %+v, %v", o, ok)
	}
	if _, ok := r.Owned("/api/other/{id}"); ok {
		t.Error("an undeclared path matched an owned rule")
	}
	ro, ok := r.Role("/api/admin/stats")
	if !ok || !ro.Allows("admin") || ro.Allows("user") {
		t.Errorf("role rule = %+v, %v", ro, ok)
	}
}

func TestMalformedRulesAreRefused(t *testing.T) {
	if _, err := NewRules([]OwnedSpec{{}}, nil); err == nil {
		t.Error("an owned rule with no paths was accepted")
	}
	if _, err := NewRules(nil, []RoleSpec{{Paths: []string{"/a"}}}); err == nil {
		t.Error("a role rule allowing no role was accepted")
	}
	if _, err := NewRules(nil, []RoleSpec{{Paths: []string{"a/**"}, Allow: []string{"x"}}}); err == nil {
		t.Error("a pattern without a leading slash was accepted")
	}
}
