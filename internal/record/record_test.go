package record

import (
	"strings"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
)

// An id the application returns is untrusted: one that could change the
// shape of the URL is never addressed, so nothing outside the record is ever
// deleted.
func TestAHostileIDIsNeverAddressed(t *testing.T) {
	for _, id := range []string{"../users/1", "1/../../admin", "x?all=1", "x#y", "%2e%2e", "a@evil.test", "a\\b"} {
		if u, err := itemURL("http://127.0.0.1:8000", "/api/notes/{id}", id); err == nil {
			t.Errorf("id %q was addressed as %s", id, u)
		}
	}
	u, err := itemURL("http://127.0.0.1:8000", "/api/notes/{id}", "9f1c-77")
	if err != nil || u != "http://127.0.0.1:8000/api/notes/9f1c-77" {
		t.Errorf("a plain id gave %q, %v", u, err)
	}
}

func TestAddressesMatchesTheRecordItselfOnly(t *testing.T) {
	op := func(path string) model.Operation {
		return model.Operation{Method: "GET", PathTemplate: path, BaseURL: "http://h"}
	}
	cases := []struct {
		path string
		name string
		ok   bool
	}{
		{"/api/workspaces/{workspaceId}", "workspaceId", true},
		{"/api/workspaces/{id}/memberships", "", false},
		{"/api/workspaces", "", false},
		{"/api/workspaces/{id}/memberships/{membershipId}", "", false},
		{"/api/other/{id}", "", false},
		{"/api/workspaces/mine", "", false},
	}
	for _, c := range cases {
		name, ok := addresses("/api/workspaces/{id}", op(c.path))
		if ok != c.ok || name != c.name {
			t.Errorf("%s: got %q %v, want %q %v", c.path, name, ok, c.name, c.ok)
		}
	}
}

func TestRecipeValidation(t *testing.T) {
	good := Recipe{Type: "note", CreatePath: "/api/notes", Body: map[string]Value{"title": {Random: true}},
		IDPointer: "/id", DeletePath: "/api/notes/{id}"}
	if p := good.Validate("records[0]", map[string]bool{}); len(p) != 0 {
		t.Fatalf("a valid recipe was refused: %v", p)
	}
	bad := good
	bad.DeletePath = "/api/notes/{a}/{b}"
	bad.Body = map[string]Value{"owner": {Self: true, Random: true}}
	bad.As = []string{"ghost"}
	p := strings.Join(bad.Validate("records[0]", map[string]bool{}), "\n")
	for _, want := range []string{"exactly one {param}", "exactly one of value, self or random", "ghost"} {
		if !strings.Contains(p, want) {
			t.Errorf("problems do not mention %q:\n%s", want, p)
		}
	}
}
