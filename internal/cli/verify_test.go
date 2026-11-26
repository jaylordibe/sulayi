package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jaylordibe/sulayi/internal/check"
	"github.com/jaylordibe/sulayi/internal/model"
)

// S5 fixtures (ADR-0024): assess the notes application while it is
// vulnerable, then re-run each finding from its recipe after a fix, without
// one, and with the identity unable to sign in.

// latestReport reads the newest run's report.
func latestReport(t *testing.T) map[string]any {
	t.Helper()
	dirs := runDirs(".sulayi")
	if len(dirs) == 0 {
		t.Fatal("no run")
	}
	raw, err := os.ReadFile(filepath.Join(dirs[0], "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// refOf returns the ref of the one finding a check raised on an operation.
func refOf(t *testing.T, doc map[string]any, checkID, opID string) string {
	t.Helper()
	for _, f := range findingsBy(doc, checkID) {
		if f["operationId"] == opID {
			if f["recipe"] == nil {
				t.Fatalf("finding %v carries no recipe", f["id"])
			}
			return f["ref"].(string)
		}
	}
	t.Fatalf("no %s finding on %s", checkID, opID)
	return ""
}

func verdictOf(t *testing.T, doc map[string]any) string {
	t.Helper()
	v, _ := doc["verification"].(map[string]any)
	if v == nil {
		t.Fatal("the verification run's report has no verification block")
	}
	return v["verdict"].(string)
}

var verifiable = []struct{ check, op string }{
	{"cross-owner-resource-read", "GET /api/notes/{noteId}"},
	{"cross-role-read", "GET /api/admin/stats"},
	{check.AuthRequiredID, "GET /api/notes/count"},
	// An operation check on a route with an id: the record that addressed it
	// is created again for the re-run.
	{check.AuthRequiredID, "GET /api/notes/{noteId}"},
	{"reflected-xss", "GET /api/notes/search"},
}

func TestS5_VerifySaysFixedAfterAFixAndReproducedWithout(t *testing.T) {
	app := newNotesApp(true)
	doc, out := runAuthz(t, app, notesRecords+notesAccess)
	refs := map[string]string{}
	for _, v := range verifiable {
		refs[v.op] = refOf(t, doc, v.check, v.op)
	}
	_ = out

	for _, v := range verifiable {
		code, vout, verr := run(t, "verify", refs[v.op])
		if code != ExitFindings || verdictOf(t, latestReport(t)) != "reproduced" {
			t.Errorf("%s while still vulnerable: exit %d, want reproduced\n%s\n%s", v.op, code, vout, verr)
		}
	}

	app.setVulnerable(false)
	for _, v := range verifiable {
		code, vout, verr := run(t, "verify", refs[v.op])
		if code != ExitOK || verdictOf(t, latestReport(t)) != "fixed" {
			t.Errorf("%s after the fix: exit %d, want fixed\n%s\n%s", v.op, code, vout, verr)
		}
		if !strings.Contains(vout, refs[v.op]) {
			t.Errorf("the verification run does not name the finding it re-ran")
		}
	}
	// Re-creating the cross-owner record and removing it again leaves
	// nothing behind.
	if n := app.remaining(); n != 0 {
		t.Errorf("%d note(s) left after verification", n)
	}
}

// An identity that cannot sign in establishes nothing: the verdict is
// inconclusive, never fixed.
func TestS5_AnUnusableIdentityIsInconclusiveNotFixed(t *testing.T) {
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess)
	ref := refOf(t, doc, "cross-role-read", "GET /api/admin/stats")
	app.setVulnerable(false)
	t.Setenv("AUTHZ_USER_TOKEN", "a-token-the-application-does-not-know")
	code, out, errOut := run(t, "verify", ref)
	if code != ExitNothingExecuted || verdictOf(t, latestReport(t)) != "inconclusive" {
		t.Errorf("exit %d, want inconclusive (3)\n%s\n%s", code, out, errOut)
	}
}

// Verify reads nothing from the earlier run but the recipe: with the earlier
// run's evidence and request log unreadable, it still runs.
func TestS5_VerifyReadsOnlyTheRecipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not restrict reads on Windows")
	}
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess)
	ref := refOf(t, doc, "cross-role-read", "GET /api/admin/stats")
	earlier := runDirs(".sulayi")[0]
	for _, name := range []string{"evidence", "requests.jsonl"} {
		p := filepath.Join(earlier, name)
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o700) })
	}
	code, out, errOut := run(t, "verify", ref)
	if code != ExitFindings {
		t.Errorf("exit %d, want reproduced (1)\n%s\n%s", code, out, errOut)
	}
}

// An unknown ref is a usage error, and report prints refs offline.
func TestS5_ReportPrintsRefsAndVerifyRefusesAnUnknownOne(t *testing.T) {
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess)
	ref := refOf(t, doc, "cross-role-read", "GET /api/admin/stats")
	code, out, _ := run(t, "report")
	if code != ExitOK || !strings.Contains(out, ref) {
		t.Errorf("report: exit %d, output does not list %s:\n%s", code, ref, out)
	}
	if code, _, errOut := run(t, "verify", "000000000000"); code != ExitUsage {
		t.Errorf("unknown ref: exit %d\n%s", code, errOut)
	}
}

// A recipe is read from a file anyone can edit, so one whose operation is not
// a plain path on the target is refused before anything is sent.
func TestS5_AnEditedRecipeCannotLeaveTheTarget(t *testing.T) {
	for _, bad := range []model.Recipe{
		{CheckID: "x", Operation: model.RecipeOperation{ID: "GET /a", Method: "GET", PathTemplate: "//evil.test/a"}},
		{CheckID: "x", Operation: model.RecipeOperation{ID: "GET /a", Method: "GET", PathTemplate: "/a", BasePath: "@evil.test"}},
		{CheckID: "x", Operation: model.RecipeOperation{ID: "GET /a", Method: "GET", PathTemplate: "/../../a"}},
		{CheckID: "x", Operation: model.RecipeOperation{ID: "GET /a", Method: "GET", PathTemplate: "http://evil.test/a"}},
		// An id that does not match its method and path would slip past
		// exclusions, which match by id.
		{CheckID: "x", Operation: model.RecipeOperation{ID: "GET /harmless", Method: "GET", PathTemplate: "/admin/reset"}},
	} {
		if err := checkRecipe(bad); err == nil {
			t.Errorf("recipe %+v was accepted", bad.Operation)
		}
	}
	ok := model.Recipe{CheckID: "x", Operation: model.RecipeOperation{ID: "GET /a/{id}", Method: "GET",
		PathTemplate: "/a/{id}", BasePath: "/api"}}
	if err := checkRecipe(ok); err != nil {
		t.Errorf("a plain recipe was refused: %v", err)
	}
}

// A route the application has since removed answers 404, which a check could
// read as a refusal. Verify says inconclusive, never fixed.
func TestS5_AMovedRouteIsInconclusiveNotFixed(t *testing.T) {
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess)
	ref := refOf(t, doc, check.AuthRequiredID, "GET /api/notes/count")
	app.mu.Lock()
	app.moved = true
	app.mu.Unlock()
	code, out, errOut := run(t, "verify", ref)
	if code != ExitNothingExecuted || verdictOf(t, latestReport(t)) != "inconclusive" {
		t.Errorf("exit %d, want inconclusive (3)\n%s\n%s", code, out, errOut)
	}
}

// A moved route behind a catch-all answers 200 like any other path, which a
// check could read as a fix. Verify says inconclusive.
func TestS5_AMovedRouteBehindACatchAllIsInconclusive(t *testing.T) {
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess)
	ref := refOf(t, doc, check.AuthRequiredID, "GET /api/notes/count")
	app.mu.Lock()
	app.moved, app.catchAll = true, true
	app.mu.Unlock()
	code, out, errOut := run(t, "verify", ref)
	if code != ExitNothingExecuted || verdictOf(t, latestReport(t)) != "inconclusive" {
		t.Errorf("exit %d, want inconclusive (3)\n%s\n%s", code, out, errOut)
	}
}

// report finds runs where attack wrote them, output.dir included.
func TestS5_ReportUsesTheConfiguredOutputDirectory(t *testing.T) {
	app := newNotesApp(true)
	_, _ = runAuthz(t, app, notesRecords+notesAccess+"output:\n  dir: out\n")
	if code, out, errOut := run(t, "report"); code != ExitOK || !strings.Contains(out, "findings") {
		t.Errorf("report with output.dir: exit %d\n%s\n%s", code, out, errOut)
	}
}

// The route check asks as the owner. With the refused identity configured
// first, a fixed application that hides the note from it with a 404 is still
// verified as fixed, not mistaken for a moved route.
func TestS5_TheRouteCheckAsksAsTheOwner(t *testing.T) {
	authzUserFirst = true
	t.Cleanup(func() { authzUserFirst = false })
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess)
	ref := refOf(t, doc, "cross-owner-resource-read", "GET /api/notes/{noteId}")
	app.setVulnerable(false)
	code, out, errOut := run(t, "verify", ref)
	if code != ExitOK || verdictOf(t, latestReport(t)) != "fixed" {
		t.Errorf("exit %d, want fixed (0)\n%s\n%s", code, out, errOut)
	}
}
