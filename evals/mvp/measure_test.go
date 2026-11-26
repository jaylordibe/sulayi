package mvp

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaylordibe/sulayi/internal/report"
)

func run(findings []report.Finding, coverage []report.CoverageEntry, urls ...string) Run {
	var d report.Document
	d.Run.Target = "http://127.0.0.1:8888"
	d.Run.StartedAt = time.Unix(0, 0)
	d.Run.FinishedAt = time.Unix(42, 0)
	d.Findings, d.Coverage = findings, coverage
	r := Run{Report: d}
	for _, u := range urls {
		r.Requests = append(r.Requests, RequestLine{Method: "GET", URL: u, Outcome: "sent"})
	}
	return r
}

var exp = Expected{
	Entries: []Entry{
		{ID: "bola", Checks: []string{"cross-owner-resource-read"}, Assessed: true,
			Operation: Operation{Method: "GET", Path: "/v/*/location"}},
		{ID: "bfla", Checks: []string{"cross-role-read"}, Assessed: true,
			Operation: Operation{Method: "GET", Path: "/admin/users"}},
		{ID: "sqli", Checks: []string{"sql-injection-boolean"}, Assessed: true,
			Operation: Operation{Method: "GET", Path: "/search"}},
		{ID: "body", Assessed: false, Reason: "in a body", Operation: Operation{Method: "POST", Path: "/coupon"}},
	},
	Negatives: []Negative{{Operation: Operation{Method: "GET", Path: "/videos/*"}}},
}

func TestFindingsAreLabelledAgainstTheGroundTruth(t *testing.T) {
	r := run([]report.Finding{
		{Ref: "a", CheckID: "cross-owner-resource-read", OperationID: "GET /v/{id}/location", State: "confirmed"},
		{Ref: "b", CheckID: "cross-owner-resource-read", OperationID: "GET /videos/{id}", State: "confirmed"},
		{Ref: "c", CheckID: "reflected-xss", OperationID: "GET /other", State: "suspected"},
	}, []report.CoverageEntry{
		{CheckID: "sql-injection-boolean", Subject: "GET /search", Disposition: "executed"},
		{CheckID: "cross-role-read", Subject: "GET /admin/users", Disposition: "blocked", Detail: "no baseline"},
	}, "http://127.0.0.1:8888/a")
	m, err := Measure("t", exp, []Run{r, r, r})
	if err != nil {
		t.Fatal(err)
	}
	if m.TruePositives != 1 || m.FalsePositives != 1 || m.Unlisted != 1 {
		t.Errorf("tp/fp/unlisted = %d/%d/%d", m.TruePositives, m.FalsePositives, m.Unlisted)
	}
	// Unlisted findings are not left out of the share: its upper bound
	// counts them as false until they are triaged.
	if !strings.Contains(m.FalsePositiveShare, "1 false of 3 findings") ||
		!strings.Contains(m.FalsePositiveShare, "up to 2") {
		t.Errorf("share = %q", m.FalsePositiveShare)
	}
	outcomes := map[string]string{}
	for _, e := range m.Entries {
		outcomes[e.ID] = e.Outcome
	}
	want := map[string]string{"bola": "confirmed", "bfla": "unreached", "sqli": "missed", "body": "not-assessed"}
	for id, o := range want {
		if outcomes[id] != o {
			t.Errorf("%s = %s, want %s", id, outcomes[id], o)
		}
	}
	if m.DetectedAssessed != 1 || m.Assessed != 3 {
		t.Errorf("detected %d of %d", m.DetectedAssessed, m.Assessed)
	}
	if !m.Reproducible || m.OutOfScopeRequests != 0 || m.RunSeconds[0] != 42 {
		t.Errorf("reproducible %v, out of scope %d, seconds %v", m.Reproducible, m.OutOfScopeRequests, m.RunSeconds)
	}
}

// A control with no expected vulnerabilities counts every finding as false.
func TestAControlTargetCountsEveryFindingAsFalse(t *testing.T) {
	r := run([]report.Finding{{CheckID: "reflected-xss", OperationID: "GET /x", State: "confirmed"}}, nil)
	m, _ := Measure("starter", Expected{}, []Run{r})
	if m.FalsePositives != 1 {
		t.Errorf("false positives = %d", m.FalsePositives)
	}
}

func TestOutOfScopeAndIrreproducibleRunsAreReported(t *testing.T) {
	a := run(nil, []report.CoverageEntry{{CheckID: "x", Subject: "GET /a", Disposition: "executed"}},
		"http://127.0.0.1:8888/a", "http://evil.test/b")
	b := run(nil, []report.CoverageEntry{{CheckID: "x", Subject: "GET /a", Disposition: "blocked"}})
	m, _ := Measure("t", Expected{}, []Run{a, b})
	if m.OutOfScopeRequests != 1 || !strings.Contains(m.OutOfScopeExamples[0], "evil.test") {
		t.Errorf("out of scope = %d %v", m.OutOfScopeRequests, m.OutOfScopeExamples)
	}
	if m.Reproducible {
		t.Error("runs with different ledgers were reported reproducible")
	}
}

func TestOperationPatterns(t *testing.T) {
	cases := []struct {
		pattern, id string
		want        bool
	}{
		{"/v/*/location", "GET /v/{vehicleId}/location", true},
		{"/v/*/location", "POST /v/{vehicleId}/location", false},
		{"/v/*/location", "GET /v/{id}", false},
		{"/**", "GET /anything/at/all", true},
		{"/rest/basket/*", "GET /rest/basket/6", true},
	}
	for _, c := range cases {
		if got := (Operation{Method: "GET", Path: c.pattern}).Matches(c.id); got != c.want {
			t.Errorf("%s ~ %s = %v", c.pattern, c.id, got)
		}
	}
}

// The committed expected files load strictly: a typo in a field would
// silently drop ground truth.
func TestCommittedExpectedFilesLoad(t *testing.T) {
	files, _ := filepath.Glob("*.expected.yaml")
	if len(files) < 2 {
		t.Fatalf("expected files = %v", files)
	}
	for _, f := range files {
		e, err := LoadExpected(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		for _, en := range e.Entries {
			if en.Assessed && len(en.Checks) == 0 || !en.Assessed && en.Reason == "" || en.ID == "" {
				t.Errorf("%s: entry %+v is incomplete", f, en.ID)
			}
		}
	}
}

// An entry whose operation was in the surface but had no work planned says
// so, rather than claiming the operation was absent.
func TestUnreachedSaysWhetherTheOperationWasThere(t *testing.T) {
	e := Expected{Entries: []Entry{{ID: "sqli", Checks: []string{"sql-injection-boolean"}, Assessed: true,
		Operation: Operation{Method: "GET", Path: "/search"}}, {ID: "redirect", Checks: []string{"open-redirect"},
		Assessed: true, Operation: Operation{Method: "GET", Path: "/redirect"}}}}
	r := run(nil, []report.CoverageEntry{{CheckID: "reflected-xss", Subject: "GET /search", Disposition: "untested"}})
	m, _ := Measure("t", e, []Run{r})
	if !strings.Contains(m.Entries[0].Detail, "was in the surface") {
		t.Errorf("present operation: %q", m.Entries[0].Detail)
	}
	if !strings.Contains(m.Entries[1].Detail, "no operation in the assessed surface") {
		t.Errorf("absent operation: %q", m.Entries[1].Detail)
	}
}
