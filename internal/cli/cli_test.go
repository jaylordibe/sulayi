package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jaylordibe/sulayi/internal/config"
	"github.com/jaylordibe/sulayi/internal/engine"
	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/store"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := Execute(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// Exit codes are a public contract, so each has a test.
func TestExitCodeMeaningsAreDefined(t *testing.T) {
	for _, c := range []int{ExitOK, ExitFindings, ExitUsage, ExitNothingExecuted, ExitAborted, ExitInternal} {
		if ExitCodeMeaning(c) == "unknown" {
			t.Errorf("exit code %d has no documented meaning", c)
		}
	}
	if ExitCodeMeaning(99) != "unknown" {
		t.Error("an undefined code should report unknown")
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range []int{ExitOK, ExitFindings, ExitUsage, ExitNothingExecuted, ExitAborted, ExitInternal} {
		if seen[c] {
			t.Fatalf("exit code %d is duplicated", c)
		}
		seen[c] = true
	}
}

func TestScanWithNoTargetFailsWithUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	code, _, errOut := run(t, "attack")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "sulayi attack http://localhost:3000") {
		t.Errorf("error does not suggest the next command: %q", errOut)
	}
}

// A configuration under the pre-rename file name must stop the run. Ignoring it
// would assess with defaults and silently drop the operator's scope,
// exclusions and identities.
func TestLegacyConfigFileStopsTheRun(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "appsec.yaml"),
		[]byte("apiVersion: appsec/v1alpha1\ntarget:\n  baseURL: http://127.0.0.1:1/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := run(t, "attack", "http://127.0.0.1:1/")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "appsec.yaml") || !strings.Contains(errOut, "sulayi.yaml") {
		t.Errorf("error does not explain the rename: %q", errOut)
	}
}

func TestInvalidProfileFailsWithUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	code, _, errOut := run(t, "attack", "http://127.0.0.1:1/", "--profile", "reckless")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "safe, standard, aggressive") {
		t.Errorf("error does not list valid profiles: %q", errOut)
	}
}

// A target with no discoverable specification must abort with an explanation,
// not report a clean run.
func TestNoSpecificationAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())

	code, _, errOut := run(t, "attack", srv.URL)
	if code != ExitAborted {
		t.Fatalf("exit = %d, want %d (aborted)", code, ExitAborted)
	}
	if !strings.Contains(strings.ToLower(errOut), "openapi") {
		t.Errorf("error does not explain the missing oracle: %q", errOut)
	}
}

// A run where every planned item was blocked must NOT return success.
func TestAllBlockedRunDoesNotReportSuccess(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{"/api/orders":{"post":{"security":[{"bearer":[]}]}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(spec))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())

	// POST requires the aggressive profile, so nothing may run.
	code, _, errOut := run(t, "attack", srv.URL)
	if code != ExitNothingExecuted {
		t.Fatalf("exit = %d, want %d (nothing executed)", code, ExitNothingExecuted)
	}
	if !strings.Contains(errOut, "establishes nothing") {
		t.Errorf("stderr does not warn that nothing was established: %q", errOut)
	}
}

// The full path: discover, plan, execute, report.
func TestScanProducesReportAndLedger(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{
	    "/api/open":{"get":{"security":[]}},
	    "/api/protected":{"get":{"security":[{"bearer":[]}]}}
	  }}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(spec))
		case "/api/open":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/protected":
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)

	code, out, errOut := run(t, "attack", srv.URL)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	// The summary wraps for the terminal, so compare on normalized whitespace.
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "does not establish that the target is secure") {
		t.Errorf("summary omits the assurance statement: %q", out)
	}

	matches, err := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "report.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("report not written: %v %v", matches, err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc["schemaVersion"] == nil {
		t.Error("report has no schemaVersion")
	}
	if rows, _ := doc["coverage"].([]any); len(rows) != 2 {
		t.Errorf("coverage rows = %d, want 2", len(rows))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(matches[0]), "report.sarif")); err != nil {
		t.Errorf("SARIF not written: %v", err)
	}

	// Evidence must actually reach disk and be referenced, or the report's
	// evidenceRefs are a claim with nothing behind them.
	evidence, err := os.ReadDir(filepath.Join(filepath.Dir(matches[0]), "evidence"))
	if err != nil || len(evidence) == 0 {
		t.Fatalf("no evidence was stored: %v (%d files)", err, len(evidence))
	}
	cov, _ := doc["coverage"].([]any)
	sawRefs := false
	for _, row := range cov {
		m := row.(map[string]any)
		if refs, ok := m["evidenceRefs"].([]any); ok && len(refs) > 0 {
			sawRefs = true
			if s, _ := refs[0].(string); !strings.HasPrefix(s, "sha256:") {
				t.Errorf("evidence ref %q is not algorithm-prefixed", s)
			}
		}
	}
	if !sawRefs {
		t.Error("no coverage row references stored evidence")
	}
	// Where the platform honours POSIX modes, the run directory must be
	// owner-only. Where it does not — Windows, where os.Chmod only toggles a
	// read-only attribute — the contract is instead that the CLI says so, so
	// an operator is never left believing in a protection that is not there.
	info, err := os.Stat(filepath.Dir(matches[0]))
	if store.PermissionsEnforced() {
		if err == nil && info.Mode().Perm() != 0o700 {
			t.Errorf("run directory mode = %o, want 700", info.Mode().Perm())
		}
	} else if !strings.Contains(errOut, "does not enforce owner-only file permissions") {
		t.Errorf("no warning that file permissions are unenforced: %q", errOut)
	}
}

// A run where scope refused everything must say so. Reporting "no document
// found" would misdescribe a refusal as an absence, which is the failure this
// project exists to prevent.
func TestScopeRefusalIsNotReportedAsNothingFound(t *testing.T) {
	t.Chdir(t.TempDir())
	// Cloud metadata is denied unconditionally, so every probe is refused.
	code, _, errOut := run(t, "attack", "http://169.254.169.254/")
	if code != ExitAborted {
		t.Fatalf("exit = %d, want %d", code, ExitAborted)
	}
	if !strings.Contains(errOut, "refused by the scope policy") {
		t.Errorf("a scope refusal was not reported as such: %q", errOut)
	}
	if !strings.Contains(errOut, "not a clean result") {
		t.Errorf("the refusal is not clearly distinguished from a clean result: %q", errOut)
	}
	if strings.Contains(errOut, "no OpenAPI document found") {
		t.Errorf("a scope refusal was misdescribed as a missing document: %q", errOut)
	}
}

func TestInitWritesConfigAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if code, _, _ := run(t, "init"); code != ExitOK {
		t.Fatalf("init exit = %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, "sulayi.yaml"))
	if err != nil {
		t.Fatalf("sulayi.yaml not written: %v", err)
	}
	if !strings.Contains(string(data), "apiVersion: sulayi/v1alpha1") {
		t.Error("generated config has no apiVersion")
	}
	// Only assert the mode where the platform enforces one; see
	// store.PermissionsEnforced.
	info, err := os.Stat(filepath.Join(dir, "sulayi.yaml"))
	if store.PermissionsEnforced() && err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("sulayi.yaml mode = %o, want 600", info.Mode().Perm())
	}

	if code, _, _ := run(t, "init"); code != ExitUsage {
		t.Error("init overwrote an existing config without --force")
	}
	if code, _, _ := run(t, "init", "--force"); code != ExitOK {
		t.Error("init --force failed")
	}
}

// The generated config must itself be valid, or the first thing a user does
// fails.
func TestGeneratedConfigIsValid(t *testing.T) {
	t.Chdir(t.TempDir())
	if code, _, _ := run(t, "init"); code != ExitOK {
		t.Fatal("init failed")
	}
	_, _, errOut := run(t, "attack", "http://127.0.0.1:1/")
	if strings.Contains(errOut, "unknown field") || strings.Contains(errOut, "apiVersion") {
		t.Fatalf("generated config does not parse: %q", errOut)
	}
}

func TestDoctorReportsMissingEnginesWithoutFailing(t *testing.T) {
	// PATH is emptied so this tests the absent-engine path deterministically.
	//
	// Without it the test asserts a property of the developer's machine rather
	// than of the code: it passed everywhere until an engine was actually
	// installed, and then failed — which is exactly backwards, because the
	// repository's own engine-integration CI job installs Nuclei.
	t.Setenv("PATH", t.TempDir())

	code, out, _ := run(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	for _, want := range []string{
		"ZAP", "Nuclei", "Semgrep/opengrep", "Hadrian", "none are bundled",
		// An absent engine must say what it would unlock and how to get it,
		// because "not found" alone tells an operator nothing about what they
		// are missing.
		"not found", "Install opengrep",
		// A network engine is reported as blocked, with why, and is not executed.
		"BLOCKED", "cannot constrain their destinations",
		// And doctor must state that it changes nothing: it is a diagnostic,
		// and a security tool that installs software is a supply chain.
		"never downloads or installs an engine",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q", want)
		}
	}
	// Absent engines must not fail the command, or `doctor` becomes unusable on
	// exactly the machine where it is most needed.
	if code != ExitOK {
		t.Errorf("doctor exit = %d with no engines installed", code)
	}
}

// The help text must not promise assurance.
func TestRootHelpDisclaimsAssurance(t *testing.T) {
	_, out, _ := run(t, "--help")
	if !strings.Contains(out, "does not prove the absence of vulnerabilities") {
		t.Error("root help does not disclaim assurance")
	}
	if !strings.Contains(out, "authorized to test") {
		t.Error("root help does not state the authorization requirement")
	}
}

// A hostname is not the address it resolves to. Deciding loopback from a string
// prefix would let an attacker-registrable name such as "127.0.0.1.nip.io"
// silently enable private addressing for the whole run.
func TestLoopbackDetectionUsesAddressesNotPrefixes(t *testing.T) {
	loopback := []string{
		"http://localhost:3000", "http://127.0.0.1:3000",
		"http://127.5.5.5:3000", "http://[::1]:3000",
	}
	for _, u := range loopback {
		if !isLoopbackTarget(u) {
			t.Errorf("isLoopbackTarget(%q) = false, want true", u)
		}
	}
	notLoopback := []string{
		"http://127.0.0.1.nip.io", // attacker-registrable name
		"http://127.0.0.1.example.com",
		"http://1270.0.0.1",
		"http://example.com",
		"http://localhost.evil.com",
	}
	for _, u := range notLoopback {
		if isLoopbackTarget(u) {
			t.Errorf("isLoopbackTarget(%q) = true; a name must never be assumed to be loopback", u)
		}
	}
}

// A detected authentication bypass must fail a pipeline. The only shipped check
// cannot reach "confirmed" without credentials, so gating solely on confirmed
// findings would exit zero on a real bypass.
func TestSuspectedHighFindingFailsThePolicy(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{
	    "/api/open":{"get":{"security":[]}},
	    "/api/admin":{"get":{"security":[{"bearer":[]}]}}
	  }}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(spec))
		case "/api/admin": // declared protected, served to anyone
			_, _ = w.Write([]byte(`{"users":[{"id":1,"email":"a@b.test","role":"admin"}]}`))
		case "/api/open":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())

	code, _, errOut := run(t, "attack", srv.URL)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d; a detected bypass must fail the build", code, ExitFindings)
	}
	if !strings.Contains(errOut, "policy threshold exceeded") {
		t.Errorf("stderr does not explain the failure: %q", errOut)
	}
}

// Secrets must not be passable on a command line. Process listings are readable
// by other users on most systems, and shell history keeps them long after the
// run.
func TestNoFlagAcceptsARawSecret(t *testing.T) {
	forbidden := []string{"--token", "--api-key", "--apikey", "--password",
		"--secret", "--credential", "--bearer", "--auth"}
	for _, cmd := range []string{"attack", "init", "doctor"} {
		_, out, errOut := run(t, cmd, "--help")
		help := out + errOut
		for _, flag := range forbidden {
			if strings.Contains(help, flag) {
				t.Errorf("%s exposes %s; a credential must come from the environment or a file",
					cmd, flag)
			}
		}
	}
}

// doctor reports whether a credential is available. It must never report what
// the credential is: its output is pasted into issues and CI logs.
func TestDoctorReportsIdentitiesWithoutValues(t *testing.T) {
	const secret = "SULAYI_M1_SECRET_MUST_NEVER_PERSIST_7f91"
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(
		"apiVersion: sulayi/v1alpha1\n"+
			"target:\n  baseURL: http://localhost:3000\n"+
			"identities:\n"+
			"  - id: admin\n"+
			"    authentication:\n"+
			"      type: bearer\n"+
			"      credential:\n        env: SULAYI_DOCTOR_TOKEN\n"+
			"  - id: missing\n"+
			"    authentication:\n"+
			"      type: bearer\n"+
			"      credential:\n        env: SULAYI_DOCTOR_ABSENT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SULAYI_DOCTOR_TOKEN", secret)

	code, out, _ := run(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	if strings.Contains(out, secret) {
		t.Fatal("doctor printed a credential value")
	}
	if !strings.Contains(out, "admin") || !strings.Contains(out, "credential source configured") {
		t.Errorf("doctor does not report a configured identity:\n%s", out)
	}
	if !strings.Contains(out, "credential unavailable") {
		t.Errorf("doctor does not report a missing credential:\n%s", out)
	}
	if !strings.Contains(out, "no liveness canary") {
		t.Errorf("doctor does not warn that expiry cannot be detected:\n%s", out)
	}
}

// With no configuration present, doctor must stay silent about identities
// rather than inventing a section.
func TestDoctorWithoutConfigReportsNoIdentities(t *testing.T) {
	t.Chdir(t.TempDir())
	code, out, _ := run(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	if strings.Contains(out, "Identities") {
		t.Errorf("doctor reported identities with no configuration present:\n%s", out)
	}
}

// A scan whose identity has no resolvable credential must say so on stderr and
// still run, rather than failing or silently proceeding as if authenticated.
func TestScanWarnsAboutAnUnresolvableCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},
			  "paths":{"/api/open":{"get":{"security":[]}}}}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(
		"apiVersion: sulayi/v1alpha1\n"+
			"target:\n  baseURL: "+srv.URL+"\n"+
			"scope:\n  allowPrivateAddresses: true\n"+
			"identities:\n"+
			"  - id: admin\n"+
			"    authentication:\n"+
			"      type: bearer\n"+
			"      credential:\n        env: SULAYI_SCAN_ABSENT\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, errOut := run(t, "attack", "--spec-url", srv.URL+"/openapi.json")
	if !strings.Contains(errOut, "credential unavailable") {
		t.Errorf("a missing credential was not reported on stderr: %q", errOut)
	}
	if !strings.Contains(errOut, "no authenticated control request will be made") {
		t.Errorf("stderr does not say what the missing credential costs: %q", errOut)
	}

	// The identity limitation must reach the report, not only the terminal.
	matches, err := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "report.json"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no report written: %v", err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Assurance  struct{ AuthenticatedControl string } `json:"assurance"`
		Identities []struct {
			ID     string `json:"id"`
			Usable bool   `json:"usable"`
		} `json:"identities"`
		Coverage []struct {
			Dimension string `json:"dimension"`
			Cause     string `json:"cause"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(doc.Identities) != 1 || doc.Identities[0].Usable {
		t.Errorf("the report does not record the unusable identity: %+v", doc.Identities)
	}
	if !strings.Contains(doc.Assurance.AuthenticatedControl, "no credential could be resolved") {
		t.Errorf("assurance does not state the limitation: %q", doc.Assurance.AuthenticatedControl)
	}
	var sawIdentityRow bool
	for _, e := range doc.Coverage {
		if e.Dimension == "identity" && e.Cause == "missing_identity" {
			sawIdentityRow = true
		}
	}
	if !sawIdentityRow {
		t.Error("the coverage ledger does not carry the blocked identity row")
	}
}

// A network engine the operator enabled is refused, and the terminal says that
// coverage was reduced and why, rather than printing a run that reads clean.
// The configured executable is a script that records being started; it must
// never be.
func TestEnabledNetworkEngineIsBlockedAndTheTerminalSaysCoverageWasReduced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tripwire executable is a POSIX shell script")
	}
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
	  "paths":{"/api/open":{"get":{"security":[]}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(spec))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	marker := filepath.Join(dir, "nuclei-started")
	bin := filepath.Join(dir, "nuclei")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch '"+marker+"'\necho v9.9.9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	templates := filepath.Join(dir, "templates")
	if err := os.Mkdir(templates, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + srv.URL + "\n" +
		"engines:\n  nuclei:\n    enabled: true\n    executable: " + bin + "\n    templates: " + templates + "\n"
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	_, out, _ := run(t, "attack")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the Nuclei executable was started")
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "COVERAGE REDUCED") || !strings.Contains(flat, "cannot constrain") {
		t.Errorf("the terminal does not say coverage was reduced by the scope block:\n%s", out)
	}
}

// A run that spends its request budget writes its report, says in the terminal
// that it stopped early and why, records the unreached work as blocked by the
// budget, and does not exit as though it had completed.
func TestRequestBudgetStopsTheRunAndSaysSo(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
	  "/api/a":{"get":{"security":[{"bearer":[]}]}},
	  "/api/b":{"get":{"security":[{"bearer":[]}]}},
	  "/api/c":{"get":{"security":[{"bearer":[]}]}}}}`
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "openapi.json"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + srv.URL + "\n" +
		"assessment:\n  maxRequests: 1\ndiscovery:\n  probeWellKnownPaths: false\n"
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := run(t, "attack", "--spec", "openapi.json")
	if code != ExitAborted {
		t.Fatalf("exit = %d, want %d (aborted)\nstdout: %s\nstderr: %s", code, ExitAborted, out, errOut)
	}
	if got := hits.Load(); got > 1 {
		t.Errorf("the target received %d requests against a budget of 1", got)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "STOPPED EARLY") || !strings.Contains(flat, "maxRequests") {
		t.Errorf("the summary does not say the budget stopped the run:\n%s", out)
	}
	if !strings.Contains(out, "requests: 1 of 1") {
		t.Errorf("the summary does not state the requests sent against the limit:\n%s", out)
	}
	reports, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "report.json"))
	if len(reports) != 1 {
		t.Fatalf("report.json files = %d, want 1: a stopped run must still write its report", len(reports))
	}
	data, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"budget_exceeded"`) || !strings.Contains(string(data), `"stoppedEarly"`) {
		t.Error("the report does not record the unreached work or why the run stopped")
	}
}

func TestStoppedEarlyNamesTheReason(t *testing.T) {
	cfg := config.Default()
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-expired.Done()
	if got := stoppedEarly(expired, cfg, httpx.BudgetUsage{}, engine.Result{}); !strings.Contains(got, "maxDurationMinutes") {
		t.Errorf("deadline: %q", got)
	}
	interrupted, stop := context.WithCancel(context.Background())
	stop()
	if got := stoppedEarly(interrupted, cfg, httpx.BudgetUsage{}, engine.Result{}); !strings.Contains(got, "interrupted") {
		t.Errorf("interrupt: %q", got)
	}
	// Using exactly the budget and finishing is not stopping early.
	full := httpx.BudgetUsage{Limit: 5, Used: 5}
	if got := stoppedEarly(context.Background(), cfg, full, engine.Result{}); got != "" {
		t.Errorf("a run that finished within its budget was reported as stopped: %q", got)
	}
}

// The request log is part of the run directory, so it is held to the same rule
// as everything else there: a credential the target reflects back must not
// reach disk. The target here echoes the bearer token in a header, a body and a
// Location; every byte of every file under .sulayi is searched.
func TestRequestLogRecordsEveryRequestAndNoCredential(t *testing.T) {
	const secret = "SULAYI_M1_SECRET_MUST_NEVER_PERSIST_7f91a2c4d8e6b0f3"
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
	  "/api/me":{"get":{"security":[{"bearer":[]}]}},
	  "/api/orders":{"get":{"security":[{"bearer":[]}]}}}}`
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth := r.Header.Get("Authorization")
		w.Header().Set("X-Echo", auth)
		w.Header().Set("Location", "/next?token="+strings.TrimPrefix(auth, "Bearer "))
		if auth == "" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"seen":"` + auth + `"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "openapi.json"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + srv.URL + "\n" +
		"discovery:\n  probeWellKnownPaths: false\n" +
		"identities:\n  - id: alice\n    authentication:\n      type: bearer\n" +
		"      credential:\n        env: SULAYI_LOG_TOKEN\n" +
		"    liveness:\n      method: GET\n      path: /api/me\n      expectStatus: [200]\n"
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SULAYI_LOG_TOKEN", secret)

	run(t, "attack", "--spec", "openapi.json")

	logs, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "requests.jsonl"))
	if len(logs) != 1 {
		t.Fatalf("requests.jsonl files = %d, want 1", len(logs))
	}
	data, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if int64(len(lines)) < hits.Load() {
		t.Errorf("the log has %d lines but the target received %d requests", len(lines), hits.Load())
	}
	var sawAlice bool
	for i, l := range lines {
		var e store.RequestLogEntry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("line %d is not a log entry: %v", i+1, err)
		}
		if e.Seq != int64(i+1) {
			t.Errorf("line %d has seq %d; the log has a gap or is out of order", i+1, e.Seq)
		}
		if e.Identity == "alice" {
			sawAlice = true
		}
	}
	if !sawAlice {
		t.Error("no log line names the identity that sent it")
	}
	if info, err := os.Stat(logs[0]); err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("requests.jsonl mode = %o, want 600", info.Mode().Perm())
	}

	_ = filepath.Walk(filepath.Join(dir, ".sulayi"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Errorf("read %s: %v", p, rerr)
			return nil
		}
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s contains the credential", p)
		}
		return nil
	})
}

// aggressiveTarget serves a minimal specification and counts every request.
func aggressiveTarget(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/api/a":{"get":{"security":[]}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(spec))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func writeAggressiveConfig(t *testing.T, dir, baseURL string, disposable bool, extra string) {
	t.Helper()
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + baseURL + "\n"
	if disposable {
		cfg += "  disposable: true\n"
	}
	cfg += "assessment:\n  profile: aggressive\n" + extra
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func answerPrompt(t *testing.T, answer string, terminal bool) {
	t.Helper()
	prev := confirmationInput
	confirmationInput = func() (io.Reader, bool) { return strings.NewReader(answer), terminal }
	t.Cleanup(func() { confirmationInput = prev })
}

// Every way of not authorizing aggressive testing stops the run before a single
// request reaches the target.
func TestAggressiveProfileIsRefusedUnlessFullyAuthorized(t *testing.T) {
	cases := []struct {
		name       string
		disposable bool
		extra      string
		args       []string
		answer     string
		terminal   bool
		want       string
	}{
		{"not declared disposable, even with --yes", false, "", []string{"--yes"}, "", false, "target.disposable"},
		{"no terminal and no --yes", true, "", nil, "", false, "--yes"},
		{"wrong origin typed", true, "", nil, "http://127.0.0.1:1\n", true, "did not match"},
		{"nothing typed", true, "", nil, "", true, "did not match"},
		{"wildcard scope", true, "scope:\n  include:\n    - scheme: https\n      host: \"*.example.test\"\n",
			[]string{"--yes"}, "", false, "exact origin"},
		{"scheme left open", true, "scope:\n  include:\n    - host: api.example.test\n",
			[]string{"--yes"}, "", false, "exact origin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, hits := aggressiveTarget(t)
			dir := t.TempDir()
			t.Chdir(dir)
			writeAggressiveConfig(t, dir, srv.URL, c.disposable, c.extra)
			answerPrompt(t, c.answer, c.terminal)

			code, _, errOut := run(t, append([]string{"attack"}, c.args...)...)
			if code != ExitUsage {
				t.Fatalf("exit = %d, want %d\nstderr: %s", code, ExitUsage, errOut)
			}
			if !strings.Contains(errOut, c.want) {
				t.Errorf("stderr does not explain the refusal (%q):\n%s", c.want, errOut)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("the target received %d request(s) before aggressive testing was authorized", n)
			}
		})
	}
}

// Typing the exact origin, or --yes without a terminal, authorizes the run.
func TestAggressiveProfileRunsOnceConfirmed(t *testing.T) {
	for _, mode := range []string{"typed", "--yes"} {
		t.Run(mode, func(t *testing.T) {
			srv, hits := aggressiveTarget(t)
			dir := t.TempDir()
			t.Chdir(dir)
			writeAggressiveConfig(t, dir, srv.URL, true, "")
			args := []string{"attack"}
			if mode == "typed" {
				answerPrompt(t, srv.URL+"\n", true)
			} else {
				answerPrompt(t, "", false)
				args = append(args, "--yes")
			}
			_, _, errOut := run(t, args...)
			if hits.Load() == 0 {
				t.Fatalf("a confirmed aggressive run sent nothing\nstderr: %s", errOut)
			}
		})
	}
}

// doctor says whether a blocked engine is installed, and finds out without
// running it.
func TestDoctorLocatesBlockedEnginesWithoutRunningThem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tripwire executable is a POSIX shell script")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	marker := filepath.Join(dir, "started")
	bin := filepath.Join(dir, "nuclei")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch '"+marker+"'\necho v9.9.9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://127.0.0.1:1\n" +
		"engines:\n  nuclei:\n    enabled: true\n    executable: " + bin + "\n    templates: " + dir + "\n"
	if err := os.WriteFile(filepath.Join(dir, "sulayi.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ := run(t, "doctor")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("doctor executed a blocked engine")
	}
	if !strings.Contains(out, "installed at "+bin+" (not executed)") {
		t.Errorf("doctor does not say where the blocked engine is installed:\n%s", out)
	}
}

// The whole credential path, end to end through the command an operator runs:
// a --env file supplies the login fields, the identity signs in under the
// default profile, and the target reflects every secret it was given — the
// password in a header and a body, the token, the session cookie. None of them,
// nor the unreferenced secret sitting in the same file, may reach the terminal
// or any byte under .sulayi.
func TestLoginThroughEnvFileLeavesNoSecretAnywhere(t *testing.T) {
	const (
		password  = "Login-P4ssword-must-never-persist"
		email     = "alice@example.test"
		unrelated = "DB-PASSWORD-never-loaded-91c2"
		token     = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXNlY3JldA"
		cookie    = "session-cookie-value-7f3d1c9a"
	)
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
	  "/api/profile":{"get":{"security":[{"bearer":[]}]}}}}`
	var logins atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "app_session="+cookie+"; Path=/; HttpOnly")
		switch {
		case r.URL.Path == "/api/auth/login":
			logins.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["identifier"] != email || body["password"] != password {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("X-Echo-Password", body["password"])
			_, _ = w.Write([]byte(`{"accessToken":"` + token + `","echo":"` + body["password"] + `"}`))
		case r.URL.Path == "/api/profile" && r.Header.Get("Authorization") == "Bearer "+token:
			w.Header().Set("X-Echo", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"you":"` + email + `","token":"` + token + `","pw":"` + password + `"}`))
		case r.URL.Path == "/api/profile":
			// The defect: served without authentication. The finding it raises
			// is what makes the authenticated exchange — the one reflecting
			// every secret — become stored evidence.
			_, _ = w.Write([]byte(`{"you":"anyone","token":"none","pw":"none"}`))
		default:
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"message":"unauthorized"}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	for name, body := range map[string]string{
		"openapi.json": spec,
		".env.sulayi.local": "ALICE_EMAIL=" + email + "\nALICE_PASSWORD=\"" + password + "\"\n" +
			"DB_PASSWORD=" + unrelated + "\n",
		"sulayi.yaml": "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + srv.URL + "\n" +
			"discovery:\n  probeWellKnownPaths: false\n" +
			"identities:\n  - id: alice\n    role: member\n    authentication:\n      type: login\n" +
			"      login:\n        path: /api/auth/login\n        body:\n" +
			"          identifier: {env: ALICE_EMAIL}\n          password: {env: ALICE_PASSWORD}\n" +
			"        session: {bearer: /accessToken}\n" +
			"    liveness: {method: GET, path: /api/profile}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_, out, errOut := run(t, "attack", "--spec", "openapi.json", "--env", ".env.sulayi.local")
	if logins.Load() == 0 {
		t.Fatalf("the identity never signed in\nstdout: %s\nstderr: %s", out, errOut)
	}
	if !strings.Contains(errOut, "1 other entr(ies) ignored") {
		t.Errorf("stderr does not say the unreferenced entry was ignored:\n%s", errOut)
	}
	if strings.Contains(errOut, "UNUSABLE") || strings.Contains(out, "UNUSABLE") {
		t.Errorf("the identity did not sign in:\n%s\n%s", out, errOut)
	}
	secrets := []string{password, unrelated, token, cookie, email}
	for _, s := range secrets {
		if strings.Contains(out, s) || strings.Contains(errOut, s) {
			t.Errorf("the terminal shows %q", s)
		}
	}
	reports, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "report.json"))
	if len(reports) != 1 {
		t.Fatalf("reports = %d", len(reports))
	}
	evidence, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "evidence", "*"))
	if len(evidence) == 0 {
		t.Fatal("no evidence was stored, so this search would prove nothing")
	}
	rep, _ := os.ReadFile(reports[0])
	if !strings.Contains(string(rep), `"role": "member"`) || !strings.Contains(string(rep), `"usable": true`) {
		t.Errorf("the report does not show a usable member identity")
	}
	_ = filepath.Walk(filepath.Join(dir, ".sulayi"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s contains %q", filepath.Base(p), s)
			}
		}
		return nil
	})
}

// A credentials file git tracks stops the run before anything is sent.
func TestTrackedEnvFileStopsTheRun(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@example.test"}, {"config", "user.name", "t"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(".env.sulayi.local", []byte("T=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "-f", ".env.sulayi.local"}, {"commit", "-q", "-m", "x"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	code, _, errOut := run(t, "attack", srv.URL, "--env", ".env.sulayi.local")
	if code != ExitUsage || !strings.Contains(errOut, "tracked by git") {
		t.Fatalf("exit = %d, stderr = %q; want a usage refusal", code, errOut)
	}
	if hits.Load() != 0 {
		t.Errorf("the target received %d request(s)", hits.Load())
	}
	if _, err := os.Stat(".sulayi"); err == nil {
		t.Error("a run directory was created for a run that was refused")
	}
}
