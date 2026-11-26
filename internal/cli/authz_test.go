package cli

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// S3 fixtures (ADR-0022): an application with notes owned by their creator and
// an administrators-only route, in a vulnerable and a secure variant. Sulayi
// signs in as an admin and a user, creates one note as each, probes them across
// accounts and the admin route across roles, and deletes what it created.

const (
	authzAdminToken = "authzADMINtoken0123456789abcdef"
	authzUserToken  = "authzUSERtoken0123456789abcdefgh"
)

type notesApp struct {
	vulnerable bool
	// failDelete makes every deletion fail, to test reporting.
	failDelete bool
	// noRead makes a note unreadable, so a removal cannot be verified.
	noRead bool
	// moved removes the count route, as a later version of the application
	// might; catchAll answers every unknown path with the same page, as a
	// single-page application's fallback does.
	moved, catchAll bool

	mu       sync.Mutex
	notes    map[string]map[string]any
	next     int
	requests []string
}

// setVulnerable switches the defect on or off between runs, as a fix would.
func (a *notesApp) setVulnerable(v bool) {
	a.mu.Lock()
	a.vulnerable = v
	a.mu.Unlock()
}

func newNotesApp(vulnerable bool) *notesApp {
	return &notesApp{vulnerable: vulnerable, notes: map[string]map[string]any{}}
}

func (a *notesApp) caller(r *http.Request) (id, role string) {
	switch r.Header.Get("Authorization") {
	case "Bearer " + authzAdminToken:
		return "u-admin", "admin"
	case "Bearer " + authzUserToken:
		return "u-user", "user"
	}
	return "", ""
}

func (a *notesApp) saw(r *http.Request) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.requests...)
}

func (a *notesApp) remaining() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.notes)
}

func (a *notesApp) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.requests = append(a.requests, r.Method+" "+r.URL.Path)
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		who, role := a.caller(r)
		a.mu.Lock()
		vulnerable, moved, catchAll := a.vulnerable, a.moved, a.catchAll
		a.mu.Unlock()
		known := strings.HasPrefix(r.URL.Path, "/api/notes") || r.URL.Path == "/api/me" ||
			strings.HasPrefix(r.URL.Path, "/api/admin")
		if (moved && r.URL.Path == "/api/notes/count") || (catchAll && !known) {
			if catchAll {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html><body>app shell</body></html>"))
				return
			}
			w.WriteHeader(404)
			return
		}
		if r.URL.Path == "/api/notes/count" && (who != "" || vulnerable) {
			_, _ = w.Write([]byte(`{"count":12}`))
			return
		}
		if who == "" && vulnerable && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/notes/n") {
			a.mu.Lock()
			note, ok := a.notes[strings.TrimPrefix(r.URL.Path, "/api/notes/")]
			a.mu.Unlock()
			if ok {
				_ = json.NewEncoder(w).Encode(note)
				return
			}
		}
		if who == "" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"message":"unauthenticated"}`))
			return
		}
		switch {
		case r.URL.Path == "/api/notes/search" && r.Method == http.MethodGet:
			q := r.URL.Query().Get("q")
			if !vulnerable {
				q = html.EscapeString(q)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, "<html><body><p>Notes matching %s</p></body></html>", q)
		case r.URL.Path == "/api/me" && r.Method == http.MethodGet:
			_, _ = fmt.Fprintf(w, `{"id":%q,"role":%q}`, who, role)
		case r.URL.Path == "/api/admin/stats" && r.Method == http.MethodGet:
			if role != "admin" && !vulnerable {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"message":"forbidden"}`))
				return
			}
			_, _ = w.Write([]byte(`{"users":2,"notes":12,"revenue":"secret-figure"}`))
		case r.URL.Path == "/api/notes" && r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["ownerId"] != who {
				w.WriteHeader(403)
				return
			}
			a.mu.Lock()
			a.next++
			id := fmt.Sprintf("n%d", a.next)
			note := map[string]any{"id": id, "ownerId": who, "title": body["title"], "body": "private text of " + who}
			a.notes[id] = note
			a.mu.Unlock()
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(note)
		case strings.HasPrefix(r.URL.Path, "/api/notes/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/notes/")
			a.mu.Lock()
			note, ok := a.notes[id]
			a.mu.Unlock()
			mine := ok && note["ownerId"] == who
			visible := mine || (ok && (role == "admin" || vulnerable))
			switch r.Method {
			case http.MethodGet:
				if !visible || a.noRead {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"message":"not found"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(note)
			case http.MethodDelete:
				if !mine {
					w.WriteHeader(404)
					return
				}
				if a.failDelete {
					w.WriteHeader(500)
					return
				}
				a.mu.Lock()
				delete(a.notes, id)
				a.mu.Unlock()
				w.WriteHeader(204)
			default:
				w.WriteHeader(405)
			}
		default:
			w.WriteHeader(404)
		}
	})
}

const notesSpec = `{"openapi":"3.0.3","info":{"title":"notes","version":"1"},
 "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},
 "security":[{"bearer":[]}],
 "paths":{
  "/api/me":{"get":{}},
  "/api/admin/stats":{"get":{}},
  "/api/admin/reset":{"post":{}},
  "/api/admin/logout":{"get":{}},
  "/api/notes/count":{"get":{}},
  "/api/notes/search":{"get":{"parameters":[{"name":"q","in":"query"}]}},
  "/api/notes":{"post":{}},
  "/api/notes/{noteId}":{"parameters":[{"name":"noteId","in":"path","required":true,"schema":{"type":"string"}}],
    "get":{},"delete":{}}}}`

const notesRecords = `records:
  - type: note
    create:
      path: /api/notes
      body:
        ownerId: { self: true }
        title: { random: true }
    id: /id
    delete: /api/notes/{id}
`

const notesAccess = `access:
  owned:
    - paths: ["/api/notes/*"]
      reachableBy: [admin]
  roles:
    - paths: ["/api/admin/**"]
      allow: [admin]
`

// authzUserFirst lists the user before the admin, so the primary identity is
// the one that should be refused.
var authzUserFirst bool

func authzIdentities() string {
	admin := "  - id: admin\n    role: admin\n    authentication: {type: bearer, credential: {env: AUTHZ_ADMIN_TOKEN}}\n" +
		"    liveness: {path: /api/me, self: /id}\n"
	user := "  - id: user\n    role: user\n    authentication: {type: bearer, credential: {env: AUTHZ_USER_TOKEN}}\n" +
		"    liveness: {path: /api/me, self: /id}\n"
	if authzUserFirst {
		return user + admin
	}
	return admin + user
}

func runAuthz(t *testing.T, app *notesApp, extra string) (map[string]any, string) {
	t.Helper()
	srv := httptest.NewServer(app.handler())
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AUTHZ_ADMIN_TOKEN", authzAdminToken)
	t.Setenv("AUTHZ_USER_TOKEN", authzUserToken)
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + srv.URL + "\n" +
		"discovery:\n  probeWellKnownPaths: false\n  crawl: {enabled: false}\n" + extra +
		"identities:\n" + authzIdentities()
	for name, body := range map[string]string{"sulayi.yaml": cfg, "openapi.json": notesSpec} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, out, errOut := run(t, "attack", "--spec", "openapi.json")
	reports, _ := filepath.Glob(filepath.Join(dir, "*", "runs", "*", "report.json"))
	if len(reports) != 1 {
		t.Fatalf("reports = %d\nstdout: %s\nstderr: %s", len(reports), out, errOut)
	}
	raw, _ := os.ReadFile(reports[0])
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, out + errOut
}

func findingsBy(doc map[string]any, checkID string) []map[string]any {
	var out []map[string]any
	fs, _ := doc["findings"].([]any)
	for _, f := range fs {
		m, _ := f.(map[string]any)
		if m["checkId"] == checkID {
			out = append(out, m)
		}
	}
	return out
}

func coverageRows(doc map[string]any, dimension string) []map[string]any {
	var out []map[string]any
	rows, _ := doc["coverage"].([]any)
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if m["dimension"] == dimension {
			out = append(out, m)
		}
	}
	return out
}

func records(doc map[string]any) []map[string]any {
	var out []map[string]any
	rs, _ := doc["records"].([]any)
	for _, r := range rs {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out
}

// Every record is created as its identity and removed, verified, and nothing
// else is ever deleted.
func assertCleanedUp(t *testing.T, app *notesApp, doc map[string]any) {
	t.Helper()
	rs := records(doc)
	if len(rs) != 2 {
		t.Fatalf("records = %v, want one per identity", rs)
	}
	for _, r := range rs {
		if r["created"] != true || r["removed"] != true {
			t.Errorf("record %v was not created and removed", r)
		}
	}
	if n := app.remaining(); n != 0 {
		t.Errorf("%d note(s) are still in the application", n)
	}
	var deletes []string
	for _, req := range app.saw(nil) {
		if strings.HasPrefix(req, "DELETE ") {
			deletes = append(deletes, req)
		}
	}
	if len(deletes) != 2 {
		t.Errorf("deletes = %v, want exactly the two created notes", deletes)
	}
	if inc, _ := doc["cleanupIncomplete"].([]any); len(inc) != 0 {
		t.Errorf("cleanupIncomplete = %v", inc)
	}
}

func TestS3_VulnerableApplicationIsConfirmedAcrossAccountsAndRoles(t *testing.T) {
	app := newNotesApp(true)
	doc, out := runAuthz(t, app, notesRecords+notesAccess)

	bola := findingsBy(doc, "cross-owner-resource-read")
	if len(bola) != 1 || bola[0]["state"] != "confirmed" || bola[0]["identityId"] != "user" {
		t.Fatalf("cross-owner findings = %v\n%s", bola, out)
	}
	bfla := findingsBy(doc, "cross-role-read")
	if len(bfla) != 1 || bfla[0]["state"] != "confirmed" || bfla[0]["operationId"] != "GET /api/admin/stats" {
		t.Fatalf("cross-role findings = %v\n%s", bfla, out)
	}
	assertCleanedUp(t, app, doc)

	// A state-changing route and a sign-out route under a role rule are never
	// sent, only recorded.
	for _, req := range app.saw(nil) {
		if req == "POST /api/admin/reset" || req == "GET /api/admin/logout" {
			t.Errorf("%s was sent", req)
		}
	}
	var untested bool
	for _, r := range coverageRows(doc, "role") {
		if r["subject"] == "POST /api/admin/reset" && r["disposition"] == "untested" {
			untested = true
		}
	}
	if !untested {
		t.Errorf("the state-changing route has no untested role row: %v", coverageRows(doc, "role"))
	}
}

func TestS3_SecureApplicationHoldsBothBoundaries(t *testing.T) {
	app := newNotesApp(false)
	doc, out := runAuthz(t, app, notesRecords+notesAccess)

	if f := append(findingsBy(doc, "cross-owner-resource-read"), findingsBy(doc, "cross-role-read")...); len(f) != 0 {
		t.Fatalf("findings on the secure application: %v", f)
	}
	executed := func(dim string) int {
		n := 0
		for _, r := range coverageRows(doc, dim) {
			if r["disposition"] == "executed" {
				n++
			}
		}
		return n
	}
	// The user probes the admin's note; the admin, who may reach every note,
	// does not probe the user's.
	if executed("ownership") != 1 {
		t.Errorf("ownership rows = %v\n%s", coverageRows(doc, "ownership"), out)
	}
	if executed("role") != 1 {
		t.Errorf("role rows = %v\n%s", coverageRows(doc, "role"), out)
	}
	assertCleanedUp(t, app, doc)
}

// Safe changes nothing: no record is created, so nothing is deleted either.
func TestS3_SafeProfileCreatesNothing(t *testing.T) {
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords+notesAccess+"assessment:\n  profile: safe\n")
	for _, req := range app.saw(nil) {
		if strings.HasPrefix(req, "POST ") || strings.HasPrefix(req, "DELETE ") {
			t.Errorf("the safe profile sent %s", req)
		}
	}
	for _, r := range records(doc) {
		if r["created"] != false {
			t.Errorf("record %v reported as created under safe", r)
		}
	}
	// The role boundary is a read, and still runs.
	if len(findingsBy(doc, "cross-role-read")) != 1 {
		t.Error("the cross-role read did not run under safe")
	}
}

// A path no access.owned rule declares has no expectation: records are still
// created and removed, and nothing is concluded about them.
func TestS3_UndeclaredOwnershipConcludesNothing(t *testing.T) {
	app := newNotesApp(true)
	doc, _ := runAuthz(t, app, notesRecords)
	if f := findingsBy(doc, "cross-owner-resource-read"); len(f) != 0 {
		t.Errorf("a finding was raised without a declared expectation: %v", f)
	}
	if rows := coverageRows(doc, "ownership"); len(rows) != 0 {
		t.Errorf("ownership rows without a declared expectation: %v", rows)
	}
	assertCleanedUp(t, app, doc)
}

// A record that could not be removed is reported by address, as cleanup that
// is incomplete.
func TestS3_RecordNotRemovedIsReported(t *testing.T) {
	app := newNotesApp(false)
	app.failDelete = true
	doc, out := runAuthz(t, app, notesRecords+notesAccess)
	inc, _ := doc["cleanupIncomplete"].([]any)
	if len(inc) != 2 {
		t.Fatalf("cleanupIncomplete = %v\n%s", inc, out)
	}
	if !strings.Contains(fmt.Sprint(inc[0]), "/api/notes/n") {
		t.Errorf("the incomplete cleanup does not name the record's address: %v", inc[0])
	}
	for _, r := range records(doc) {
		if r["removed"] != false {
			t.Errorf("record %v reported as removed", r)
		}
	}
	if !strings.Contains(out, "CLEANUP INCOMPLETE") {
		t.Errorf("the terminal does not say cleanup is incomplete:\n%s", out)
	}
}

// A not-found after a deletion means the record is gone only if the record
// could be read before it. Otherwise the removal is reported as not verified.
func TestS3_UnverifiableRemovalIsNotReportedAsRemoved(t *testing.T) {
	app := newNotesApp(false)
	app.noRead = true
	doc, out := runAuthz(t, app, notesRecords+notesAccess)
	for _, r := range records(doc) {
		if r["removed"] != false || !strings.Contains(fmt.Sprint(r["problem"]), "not verified") {
			t.Errorf("record %v was reported as removed without a read before the deletion\n%s", r, out)
		}
	}
	if inc, _ := doc["cleanupIncomplete"].([]any); len(inc) != 2 {
		t.Errorf("cleanupIncomplete = %v", inc)
	}
}
