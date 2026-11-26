// Package mvp computes the MVP measurement (ADR-0025) from what Sulayi wrote
// to disk: three runs' reports and request logs, and a target's expected
// results written from its source before any run. Nothing here is judged by
// hand; a finding that matches no expected entry is reported as unlisted for a
// person to triage, never counted either way.
package mvp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/jaylordibe/sulayi/internal/report"
)

// Expected is a target's ground truth.
type Expected struct {
	Target    string     `yaml:"target"`
	Entries   []Entry    `yaml:"entries"`
	Negatives []Negative `yaml:"negatives"`
}

// Entry is one deliberately shipped vulnerability.
type Entry struct {
	ID        string    `yaml:"id"`
	Challenge string    `yaml:"challenge"`
	Checks    []string  `yaml:"checks"`
	Operation Operation `yaml:"operation"`
	Assessed  bool      `yaml:"assessed"`
	Source    string    `yaml:"source"`
	Reason    string    `yaml:"reason"`
	Note      string    `yaml:"note"`
}

// Negative is a route known to be correct, where a finding is a false positive.
type Negative struct {
	Operation Operation `yaml:"operation"`
	Source    string    `yaml:"source"`
}

// Operation is a method and a path pattern: * is one segment, ** the rest.
type Operation struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// Matches reports whether an operation id ("GET /a/{id}") fits the pattern.
func (o Operation) Matches(operationID string) bool {
	method, path, ok := strings.Cut(operationID, " ")
	if !ok || !strings.EqualFold(method, o.Method) {
		return false
	}
	want := strings.Split(strings.Trim(o.Path, "/"), "/")
	got := strings.Split(strings.Trim(path, "/"), "/")
	for i, w := range want {
		if w == "**" {
			return true
		}
		if i >= len(got) || (w != "*" && w != got[i]) {
			return false
		}
	}
	return len(got) == len(want)
}

// LoadExpected reads a ground-truth file. An empty path is a target with no
// expected vulnerabilities, where every finding is a false positive.
func LoadExpected(path string) (Expected, error) {
	if path == "" {
		return Expected{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Expected{}, err
	}
	var e Expected
	if err := yaml.UnmarshalWithOptions(raw, &e, yaml.Strict()); err != nil {
		return Expected{}, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// Run is one stored run.
type Run struct {
	Dir      string
	Report   report.Document
	Requests []RequestLine
}

// RequestLine is the part of a request-log line the measurement reads.
type RequestLine struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Outcome string `json:"outcome"`
}

// LoadRun reads a run directory.
func LoadRun(dir string) (Run, error) {
	r := Run{Dir: dir}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r.Report); err != nil {
		return r, fmt.Errorf("%s: %w", dir, err)
	}
	f, err := os.Open(filepath.Join(dir, "requests.jsonl"))
	if err != nil {
		return r, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var line RequestLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			return r, fmt.Errorf("%s: request log: %w", dir, err)
		}
		r.Requests = append(r.Requests, line)
	}
	return r, sc.Err()
}

// Label is what a finding was judged to be.
type Label string

const (
	TruePositive  Label = "true-positive"
	FalsePositive Label = "false-positive"
	Unlisted      Label = "unlisted"
)

// LabelledFinding is one finding with its label and the entry it matched.
type LabelledFinding struct {
	Ref       string `json:"ref"`
	CheckID   string `json:"checkId"`
	Operation string `json:"operation"`
	Identity  string `json:"identity,omitempty"`
	State     string `json:"state"`
	Label     Label  `json:"label"`
	Entry     string `json:"entry,omitempty"`
}

// EntryResult says what became of one expected entry.
type EntryResult struct {
	ID       string `json:"id"`
	Assessed bool   `json:"assessed"`
	// Outcome is confirmed, suspected, missed (reached and not found),
	// unreached (no executed check on the operation) or not-assessed.
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Measurement is the whole result for one target.
type Measurement struct {
	Target                  string            `json:"target"`
	Commit                  string            `json:"commit,omitempty"`
	ExpectedSHA256          string            `json:"expectedSha256,omitempty"`
	Runs                    int               `json:"runs"`
	Findings                []LabelledFinding `json:"findings"`
	TruePositives           int               `json:"truePositives"`
	FalsePositives          int               `json:"falsePositives"`
	Unlisted                int               `json:"unlisted"`
	FalsePositiveShare      string            `json:"falsePositiveShare"`
	Entries                 []EntryResult     `json:"entries"`
	DetectedAssessed        int               `json:"detectedAssessed"`
	Assessed                int               `json:"assessed"`
	Executed                int               `json:"executed"`
	Planned                 int               `json:"planned"`
	Reproducible            bool              `json:"reproducible"`
	ReproducibilityDetail   string            `json:"reproducibilityDetail,omitempty"`
	RunSeconds              []float64         `json:"runSeconds"`
	OutOfScopeRequests      int               `json:"outOfScopeRequests"`
	OutOfScopeExamples      []string          `json:"outOfScopeExamples,omitempty"`
	RequestsSentPerRun      []int             `json:"requestsSentPerRun"`
	CleanupIncompletePerRun []int             `json:"cleanupIncompletePerRun"`
}

// Measure computes the measurement from a target's runs. Findings are
// labelled from the first run; every run is checked for reproducibility,
// time and out-of-scope traffic.
func Measure(target string, exp Expected, runs []Run) (Measurement, error) {
	if len(runs) == 0 {
		return Measurement{}, fmt.Errorf("no runs")
	}
	m := Measurement{Target: target, Runs: len(runs)}
	first := runs[0].Report

	for _, f := range first.Findings {
		lf := LabelledFinding{Ref: f.Ref, CheckID: f.CheckID, Operation: f.OperationID, Identity: f.IdentityID,
			State: f.State, Label: Unlisted}
		for _, e := range exp.Entries {
			if contains(e.Checks, f.CheckID) && e.Operation.Matches(f.OperationID) {
				lf.Label, lf.Entry = TruePositive, e.ID
				break
			}
		}
		if lf.Label == Unlisted {
			for _, n := range exp.Negatives {
				if n.Operation.Matches(f.OperationID) {
					lf.Label = FalsePositive
				}
			}
		}
		// A target with no expected vulnerabilities is a false-positive
		// control: anything it reports is a false positive.
		if lf.Label == Unlisted && len(exp.Entries) == 0 {
			lf.Label = FalsePositive
		}
		m.Findings = append(m.Findings, lf)
		switch lf.Label {
		case TruePositive:
			m.TruePositives++
		case FalsePositive:
			m.FalsePositives++
		default:
			m.Unlisted++
		}
	}
	// Unlisted findings await triage, so the share is stated as a range: as
	// judged so far, and as it would be if every unlisted one were false.
	// Reporting only the first would let triage-pending noise read as 0%.
	total := len(m.Findings)
	m.FalsePositiveShare = "n/a (no findings)"
	if total > 0 {
		m.FalsePositiveShare = fmt.Sprintf("%d false of %d findings (%.0f%%); up to %d (%.0f%%) if every "+
			"unlisted one is false", m.FalsePositives, total, 100*float64(m.FalsePositives)/float64(total),
			m.FalsePositives+m.Unlisted, 100*float64(m.FalsePositives+m.Unlisted)/float64(total))
	}

	for _, e := range exp.Entries {
		r := EntryResult{ID: e.ID, Assessed: e.Assessed}
		if !e.Assessed {
			r.Outcome, r.Detail = "not-assessed", e.Reason
			m.Entries = append(m.Entries, r)
			continue
		}
		m.Assessed++
		r.Outcome = "unreached"
		for _, f := range m.Findings {
			if f.Entry == e.ID {
				if f.State == "confirmed" {
					r.Outcome = "confirmed"
				} else if r.Outcome != "confirmed" {
					r.Outcome = "suspected"
				}
			}
		}
		if r.Outcome == "confirmed" {
			m.DetectedAssessed++
		}
		if r.Outcome == "unreached" {
			var why []string
			for _, c := range first.Coverage {
				if !contains(e.Checks, c.CheckID) || !e.Operation.Matches(c.Subject) {
					continue
				}
				if c.Disposition == "executed" {
					r.Outcome = "missed"
					why = append(why[:0], "executed on "+c.Subject+" and found nothing")
					break
				}
				why = append(why, fmt.Sprintf("%s on %s: %s", c.Disposition, c.Subject, c.Detail))
			}
			if len(why) == 0 {
				why = append(why, absentOrUnplanned(first, e))
			}
			r.Detail = strings.Join(why, "; ")
		}
		m.Entries = append(m.Entries, r)
	}

	m.Executed = first.Assurance.ExecutedChecks
	m.Planned = first.Assurance.ExecutedChecks + first.Assurance.BlockedChecks + first.Assurance.UntestedSurface

	m.Reproducible, m.ReproducibilityDetail = reproducible(runs)

	for _, r := range runs {
		m.RunSeconds = append(m.RunSeconds, r.Report.Run.FinishedAt.Sub(r.Report.Run.StartedAt).Seconds())
		m.CleanupIncompletePerRun = append(m.CleanupIncompletePerRun, len(r.Report.CleanupIncomplete))
		origin := originOf(r.Report.Run.Target)
		sent := 0
		for _, q := range r.Requests {
			if q.Outcome != "sent" && q.Outcome != "error" {
				continue
			}
			sent++
			if originOf(q.URL) != origin {
				m.OutOfScopeRequests++
				if len(m.OutOfScopeExamples) < 5 {
					m.OutOfScopeExamples = append(m.OutOfScopeExamples, q.Method+" "+q.URL)
				}
			}
		}
		m.RequestsSentPerRun = append(m.RequestsSentPerRun, sent)
	}
	return m, nil
}

// absentOrUnplanned says why an expected entry has no ledger row: either no
// operation like it was in the surface, or one was and no check planned work
// on it (no parameter to inject into, no fixture to address it).
func absentOrUnplanned(d report.Document, e Entry) string {
	for _, c := range d.Coverage {
		if e.Operation.Matches(c.Subject) {
			return "the operation " + c.Subject + " was in the surface, and no " + strings.Join(e.Checks, " or ") +
				" work was planned on it"
		}
	}
	return "no operation in the assessed surface matched"
}

// reproducible compares every run's ledger (key and disposition) and finding
// ids with the first run's.
func reproducible(runs []Run) (bool, string) {
	base := fingerprint(runs[0].Report)
	for i, r := range runs[1:] {
		if got := fingerprint(r.Report); got != base {
			return false, fmt.Sprintf("run %d differs from run 1 in its ledger or findings", i+2)
		}
	}
	return true, ""
}

func fingerprint(d report.Document) string {
	var rows []string
	for _, c := range d.Coverage {
		rows = append(rows, strings.Join([]string{c.Dimension, c.Subject, c.CheckID, c.IdentityID,
			c.ResourceID, c.Disposition}, "|"))
	}
	for _, f := range d.Findings {
		rows = append(rows, "finding|"+f.CheckID+"|"+f.OperationID+"|"+f.IdentityID+"|"+f.State)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Markdown renders a measurement for the published document.
func Markdown(m Measurement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### %s\n\n", m.Target)
	if m.Commit != "" || m.ExpectedSHA256 != "" {
		fmt.Fprintf(&b, "Scored at commit `%s`", m.Commit)
		if m.ExpectedSHA256 != "" {
			fmt.Fprintf(&b, " against an expected file with SHA-256 `%s`", m.ExpectedSHA256)
		}
		b.WriteString(".\n\n")
	}
	fmt.Fprintf(&b, "| Metric | Result |\n|---|---|\n")
	fmt.Fprintf(&b, "| False positives | %s; %d unlisted await triage |\n", m.FalsePositiveShare, m.Unlisted)
	fmt.Fprintf(&b, "| Detection (confirmed / assessed expected) | %d of %d |\n", m.DetectedAssessed, m.Assessed)
	fmt.Fprintf(&b, "| Coverage (executed / planned) | %d of %d |\n", m.Executed, m.Planned)
	repro := "yes — identical ledgers and findings in all runs"
	if !m.Reproducible {
		repro = "no — " + m.ReproducibilityDetail
	}
	fmt.Fprintf(&b, "| Reproducible across %d runs | %s |\n", m.Runs, repro)
	secs := make([]string, 0, len(m.RunSeconds))
	for _, s := range m.RunSeconds {
		secs = append(secs, fmt.Sprintf("%.0fs", s))
	}
	fmt.Fprintf(&b, "| Time per run | %s |\n", strings.Join(secs, ", "))
	fmt.Fprintf(&b, "| Requests sent per run | %v |\n", m.RequestsSentPerRun)
	fmt.Fprintf(&b, "| Requests outside scope | %d |\n", m.OutOfScopeRequests)
	fmt.Fprintf(&b, "| Records left behind per run | %v |\n\n", m.CleanupIncompletePerRun)
	if len(m.Entries) > 0 {
		fmt.Fprintf(&b, "| Expected | Outcome | Detail |\n|---|---|---|\n")
		for _, e := range m.Entries {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", e.ID, e.Outcome, strings.ReplaceAll(e.Detail, "|", "\\|"))
		}
		b.WriteString("\n")
	}
	if len(m.Findings) > 0 {
		fmt.Fprintf(&b, "| Finding | Check | Operation | State | Label |\n|---|---|---|---|---|\n")
		for _, f := range m.Findings {
			label := string(f.Label)
			if f.Entry != "" {
				label += " (" + f.Entry + ")"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.Ref, f.CheckID, f.Operation, f.State, label)
		}
		b.WriteString("\n")
	}
	return b.String()
}
