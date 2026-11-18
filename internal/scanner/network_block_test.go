package scanner_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/scanner"
	"github.com/jaylordibe/sulayi/internal/scanner/nuclei"
	"github.com/jaylordibe/sulayi/internal/scanner/zap"
)

// tripwire builds an executable that records, in a file, that it was started.
// Any invocation at all — a version probe, a scan — leaves the file behind, so
// "the engine was blocked" is asserted as "the binary never ran", not merely as
// "a blocked status came back".
func tripwire(t *testing.T) (bin, marker string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is not available to build a tripwire engine")
	}
	dir := t.TempDir()
	marker = filepath.Join(dir, "started")
	src := "package main\n\nimport \"os\"\n\nfunc main() {\n" +
		"\t_ = os.WriteFile(" + strconv.Quote(marker) + ", []byte(\"started\"), 0o600)\n" +
		"\tos.Stdout.WriteString(\"v9.9.9\\n\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "engine")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot build tripwire engine: %v\n%s", err, out)
	}
	return bin, marker
}

// Nuclei and ZAP open their own connections, which Sulayi's scope enforcement
// cannot constrain. They must be refused in every profile and every mode,
// before the binary is so much as asked for its version, and the refusal must
// leave the classes they cover unassessed rather than reported as passed.
func TestNetworkEnginesAreRefusedInEveryProfile(t *testing.T) {
	bin, marker := tripwire(t)
	templates := t.TempDir()

	cases := []struct {
		name   string
		engine scanner.Engine
		extra  map[string]string
		rules  string
	}{
		{"nuclei", nuclei.New(), map[string]string{"allowUnsignedTemplates": "true"}, templates},
		{"zap passive", zap.New(), map[string]string{"mode": "passive"}, ""},
		{"zap active", zap.New(), map[string]string{"mode": "active"}, ""},
	}
	for _, c := range cases {
		for _, profile := range []model.Profile{model.ProfileSafe, model.ProfileStandard, model.ProfileAggressive} {
			t.Run(c.name+"/"+string(profile), func(t *testing.T) {
				settings := scanner.Settings{
					Enabled: true, Executable: bin, RuleSource: c.rules, TimeoutSeconds: 30, Extra: c.extra,
				}
				reg := []scanner.Registered{{Engine: c.engine, Settings: settings}}
				coll := scanner.RunAll(context.Background(), reg,
					scanner.Target{BaseURL: "http://127.0.0.1:1", SourceRoot: t.TempDir(), Profile: profile},
					scanner.Options{RunID: "network-block"})

				if _, err := os.Stat(marker); err == nil {
					t.Fatal("the engine binary was started; a network engine must never run")
				}
				if len(coll.Outcomes) != 1 {
					t.Fatalf("outcomes = %d, want 1", len(coll.Outcomes))
				}
				out := coll.Outcomes[0]
				if out.Status != scanner.StatusBlocked || out.Cause != model.CauseSafetyPolicy {
					t.Errorf("outcome = %s/%s, want blocked/safety_policy", out.Status, out.Cause)
				}
				if !strings.Contains(out.Detail, "scope") || !strings.Contains(out.Detail, "every profile") {
					t.Errorf("the detail does not say why or for how long: %q", out.Detail)
				}
				if len(coll.Coverage) != 1 || coll.Coverage[0].Disposition != model.DispositionBlocked {
					t.Errorf("ledger = %+v, want one blocked row", coll.Coverage)
				}
				if len(coll.Covered) != 0 || len(coll.Findings) != 0 {
					t.Errorf("a blocked engine claimed coverage %v or findings %d", coll.Covered, len(coll.Findings))
				}
				if !coll.Failed() {
					t.Error("a blocked engine was not reported as a failure, so the summary would not say coverage was reduced")
				}
			})
		}
	}
}

// The gate is fail-closed: an integration that does not declare itself offline
// is treated as one that opens its own connections.
func TestOnlyOfflineEnginesAreDeclaredOffline(t *testing.T) {
	for _, e := range []scanner.Engine{nuclei.New(), zap.New()} {
		if e.Meta().Offline {
			t.Errorf("%s is declared offline, but it opens its own network connections", e.Meta().ID)
		}
	}
}
