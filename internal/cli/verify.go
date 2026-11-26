package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/sulayi/internal/config"
	"github.com/jaylordibe/sulayi/internal/engine"
	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/openapi"
	"github.com/jaylordibe/sulayi/internal/report"
	"github.com/jaylordibe/sulayi/internal/resource"
	"github.com/jaylordibe/sulayi/internal/store"
)

// focus narrows an assessment to one finding's recipe (ADR-0024).
type focus struct {
	recipe    model.Recipe
	ofRun     string
	ofFinding string
}

func newVerifyCommand(stdout, stderr io.Writer) *cobra.Command {
	var configPath, envFile, outputDir, runID string
	var yes bool
	cmd := &cobra.Command{
		Use:   "verify <finding> [target-url]",
		Short: "Re-run one finding from its recipe and say whether it is fixed",
		Long: "Re-run the check that produced a finding, on the same operation, with fresh sign-ins\n" +
			"and the configuration in force now. Nothing is read from the earlier run but the\n" +
			"finding's recipe. The result is a new run linked to the original, with a verdict:\n" +
			"reproduced (exit 1), fixed (exit 0) or inconclusive (exit 3). Fixed means the check\n" +
			"ran and found nothing; anything that kept it from running is inconclusive.\n\n" +
			"<finding> is the short ref the report prints, or the finding's full id.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(configPath, args[1:])
			if err != nil {
				return err
			}
			if outputDir != "" {
				cfg.Output.Dir = outputDir
			}
			if err := cfg.Validate(); err != nil {
				return fail(ExitUsage, "%v", err)
			}
			found, err := findRecipe(cfg.Output.Dir, args[0], runID)
			if err != nil {
				return err
			}
			if err := narrow(&cfg, found.recipe); err != nil {
				return err
			}
			if cfg.Profile() == model.ProfileAggressive {
				if err := confirmAggressive(cfg, yes, stderr); err != nil {
					return err
				}
			}
			var creds *identity.EnvFile
			if envFile != "" {
				creds, err = identity.LoadEnvFile(envFile, cfg.CredentialEnvNames())
				if err != nil {
					return fail(ExitUsage, "%v", err)
				}
				for _, w := range creds.Warnings {
					fmt.Fprintf(stderr, "sulayi: warning: %s\n", w)
				}
			}
			fmt.Fprintf(stderr, "sulayi: verifying %s (%s) from run %s\n", report.Ref(found.ofFinding),
				found.ofFinding, found.ofRun)
			return runFocused(cmd.Context(), cfg, creds, &found, stdout, stderr)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to sulayi.yaml (default: ./sulayi.yaml if present)")
	cmd.Flags().StringVar(&envFile, "env", "", "credentials file of NAME=value lines")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "run output directory (default: .sulayi)")
	cmd.Flags().StringVar(&runID, "run", "", "look for the finding only in this run")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the aggressive-profile confirmation prompt")
	return cmd
}

// storedRun is the part of a report verify and report read.
type storedRun struct {
	SchemaVersion string `json:"schemaVersion"`
	Run           struct {
		ID string `json:"id"`
	} `json:"run"`
	Findings []struct {
		ID     string         `json:"id"`
		Ref    string         `json:"ref"`
		Recipe *report.Recipe `json:"recipe"`
	} `json:"findings"`
}

// runDirs lists run directories newest first.
func runDirs(outputDir string) []string { return store.Runs(outputDir) }

// findRecipe finds a finding by ref or id, newest run first, and returns only
// its recipe. Nothing else in the earlier run is read.
func findRecipe(outputDir, want, onlyRun string) (focus, error) {
	want = strings.TrimSpace(want)
	var matches []focus
	ids := map[string]bool{}
	for _, dir := range runDirs(outputDir) {
		if onlyRun != "" && filepath.Base(dir) != onlyRun {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
		if err != nil {
			continue
		}
		var r storedRun
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		for _, f := range r.Findings {
			if f.ID != want && !strings.EqualFold(report.Ref(f.ID), want) {
				continue
			}
			if f.Recipe == nil {
				return focus{}, fail(ExitUsage, "finding %s in run %s has no recipe: it is an imported "+
					"observation, or the report predates %s, so it cannot be re-run", want, r.Run.ID,
					report.SchemaVersion)
			}
			if err := checkRecipe(f.Recipe.Model()); err != nil {
				return focus{}, fail(ExitUsage, "finding %s in run %s has a recipe that cannot be used: %v",
					want, r.Run.ID, err)
			}
			if !ids[f.ID] {
				ids[f.ID] = true
				matches = append(matches, focus{recipe: f.Recipe.Model(), ofRun: r.Run.ID, ofFinding: f.ID})
			}
		}
		if len(matches) > 0 {
			break
		}
	}
	switch {
	case len(matches) == 0 && onlyRun != "":
		return focus{}, fail(ExitUsage, "no finding %s in run %s under %s", want, onlyRun, outputDir)
	case len(matches) == 0:
		return focus{}, fail(ExitUsage, "no finding %s in any run under %s", want, outputDir)
	case len(matches) > 1:
		return focus{}, fail(ExitUsage, "%s matches more than one finding in run %s; pass the full id",
			want, matches[0].ofRun)
	}
	return matches[0], nil
}

// checkRecipe refuses a recipe whose operation could address anything but a
// path on the configured target. A report is a file anyone can edit; scope,
// the guard and the budget still apply, and this keeps the recipe a path.
func checkRecipe(r model.Recipe) error {
	op := r.Operation
	if r.CheckID == "" || op.Method == "" || op.ID == "" {
		return fmt.Errorf("it names no check, method or operation")
	}
	for _, p := range []string{op.PathTemplate, op.BasePath} {
		if p != "" && (!strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "..") ||
			strings.ContainsAny(p, "?#\\@") || strings.Contains(p, "://")) {
			return fmt.Errorf("%q is not a plain path", p)
		}
	}
	if !strings.HasPrefix(op.PathTemplate, "/") {
		return fmt.Errorf("the operation has no path")
	}
	// Exclusions and state-changing rules match by id, so the id must be the
	// one its method and path produce.
	if op.ID != model.OperationID(op.Method, op.PathTemplate) {
		return fmt.Errorf("its id %q does not match its method and path", op.ID)
	}
	return nil
}

// narrow reduces the configuration to what one recipe needs: no discovery,
// no adapters, no crawl, no engines, and only the fixture or record type the
// finding was produced through. Scope, profile, identities, budgets and the
// declared ownership and role rules are kept as they are.
func narrow(cfg *config.Config, r model.Recipe) error {
	no := false
	cfg.Discovery.OpenAPIFile, cfg.Discovery.OpenAPIURL = "", ""
	cfg.Discovery.ProbeWellKnownPaths = &no
	cfg.Discovery.Surface.Enabled = &no
	cfg.Discovery.Crawl.Enabled = &no
	cfg.Adapters.Use = nil
	cfg.Engines.Nuclei.Enabled, cfg.Engines.ZAP.Enabled, cfg.Engines.SAST.Enabled = false, false, false
	// The operation's expectation is the recipe's; the access policy would
	// otherwise re-decide it.
	cfg.Access.Protected, cfg.Access.Public = nil, nil

	var resources []config.Resource
	var records []config.Record
	if f := r.Fixture; f != nil {
		if f.Provenance == string(resource.ProvenanceAPICreated) {
			for _, rec := range cfg.Records {
				if rec.Type != f.Type {
					continue
				}
				// The record is created as its owner only if the
				// configuration still lets that identity create one.
				if len(rec.As) > 0 && !contains(rec.As, f.Owner) {
					return fail(ExitUsage, "the finding's %s record was created as %s, which records[].as "+
						"no longer allows", f.Type, f.Owner)
				}
				rec.As = []string{f.Owner}
				records = append(records, rec)
			}
			if len(records) == 0 {
				return fail(ExitUsage, "the finding was produced through a %s record, and sulayi.yaml no "+
					"longer declares how to create one (records[].type %q)", f.Type, f.Type)
			}
		} else {
			for _, res := range cfg.Resources {
				if res.ID == f.ID {
					resources = append(resources, res)
				}
			}
			if len(resources) == 0 {
				return fail(ExitUsage, "the finding was produced through fixture %q, which sulayi.yaml no "+
					"longer declares", f.ID)
			}
		}
	}
	if r.Fixture == nil && len(r.Operation.Parameters) > 0 {
		// An operation check names no fixture; whatever addressed the
		// operation then can address it now. Configured fixtures only fill
		// parameters, and only records of a type that addresses this
		// operation are created.
		resources = cfg.Resources
		op := r.Operation.Operation(origin(cfg.Target.BaseURL))
		recipes := cfg.RecordRecipes()
		for i, rec := range cfg.Records {
			if recipes[i].Addresses(op) {
				records = append(records, rec)
			}
		}
	}
	cfg.Resources, cfg.Records = resources, records
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// focusSurface is the one operation a recipe names, on the configured target.
func focusSurface(cfg config.Config, r model.Recipe) engine.Surface {
	op := r.Operation.Operation(origin(cfg.Target.BaseURL))
	ops := []model.Operation{op}
	return engine.Surface{SpecDerived: true, Operations: ops, Fidelity: openapi.Grade(ops),
		SpecSource: model.Source{Kind: model.SourceKind("recipe"), Ref: r.Operation.ID}}
}

// routeGone establishes that the operation still answers before a verdict of
// fixed can stand, and says why it cannot be shown to, or "" when it can. It
// asks as the identity whose success was the baseline (the owner, or the
// allowed role), so a fix that hides the record from others with a 404 is not
// mistaken for a moved route. A route that answers exactly like a path that
// cannot exist is a catch-all, not the operation. An operation check on a
// state-changing method cannot be asked without changing state, so its fix
// cannot be shown; a cross-owner write's owner control already showed it.
func (f *focus) routeGone(ctx context.Context, op model.Operation, fixtures []resource.Fixture,
	ids *identity.Set, client *httpx.Client) string {
	if op.Method != http.MethodGet && op.Method != http.MethodHead {
		if f.recipe.OwnerIdentityID == "" {
			return "the operation uses " + op.Method + ", so whether it still exists cannot be shown " +
				"without sending a request that changes state; a check that found nothing establishes " +
				"nothing about the fix"
		}
		return ""
	}
	u, ok := boundOperationURL(op, fixtures)
	if !ok {
		return ""
	}
	asker := ids.Primary()
	if f.recipe.OwnerIdentityID != "" {
		if c, ok := ids.ByID(f.recipe.OwnerIdentityID); ok {
			asker = c
		}
	}
	who := "an anonymous request"
	get := func(target string) (model.Exchange, error) {
		header := map[string][]string{"Accept": {"application/json, text/html, */*"}, "Cache-Control": {"no-cache"}}
		if asker != nil {
			if usable, _, _ := asker.Usable(); usable {
				who = "a request as " + asker.ID()
				return asker.Do(ctx, op.Method, target, header)
			}
		}
		return client.Do(ctx, httpx.Request{Method: op.Method, URL: target, Header: header})
	}
	ex, err := get(u)
	if err != nil || ex.Response == nil {
		return ""
	}
	if s := ex.Response.Status; s == http.StatusNotFound || s == http.StatusGone {
		return fmt.Sprintf("the operation answered %d to %s, so it may have moved or been removed; a "+
			"check that found nothing there establishes nothing about the fix", s, who)
	}
	nowhere, err := get(siblingURL(u))
	if err == nil && nowhere.Response != nil && nowhere.Response.Status == ex.Response.Status &&
		string(nowhere.Response.Body) == string(ex.Response.Body) {
		return "the operation answers " + who + " exactly as a path that cannot exist does, so it may " +
			"have moved and a catch-all route is answering in its place; a check that found nothing " +
			"there establishes nothing about the fix"
	}
	return ""
}

// siblingURL is a path beside the operation that cannot exist.
func siblingURL(u string) string {
	q := ""
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u, q = u[:i], u[i:]
	}
	if i := strings.LastIndexByte(u, '/'); i > 0 {
		u = u[:i]
	}
	return u + "/sulayi-nonexistent-route-check" + q
}

// boundOperationURL addresses an operation, through the first fixture that
// applies when it has path parameters.
func boundOperationURL(op model.Operation, fixtures []resource.Fixture) (string, bool) {
	if len(op.RequiredPathParams()) == 0 {
		b, err := resource.Bind(op, nil)
		return b.URL, err == nil
	}
	for _, fx := range fixtures {
		if !fx.AppliesTo(op) {
			continue
		}
		if b, err := resource.Bind(op, fx.Values); err == nil {
			return b.URL, true
		}
	}
	return "", false
}

// keepCheck reports whether a check belongs in a focused run.
func (f *focus) keepCheck(id string) bool { return f == nil || f.recipe.CheckID == id }

// verdict reads the focused run's own result for the recipe's unit.
func (f *focus) verdict(res engine.Result) (engine.Verdict, string) {
	r := f.recipe
	matches := func(checkID, opID, identityID string) bool {
		return checkID == r.CheckID && opID == r.Operation.ID && (r.IdentityID == "" || identityID == r.IdentityID)
	}
	for _, fd := range res.Findings {
		if matches(fd.CheckID, fd.OperationID, fd.IdentityID) {
			return engine.VerdictReproduced, fmt.Sprintf("the check found it again (%s): %s", fd.State, fd.Actual)
		}
	}
	var why []string
	for _, e := range res.Coverage {
		if !matches(e.CheckID, e.Subject, e.IdentityID) {
			continue
		}
		if e.Disposition == model.DispositionExecuted {
			return engine.VerdictFixed, "the check ran on the operation and found nothing: " + e.Detail
		}
		why = append(why, fmt.Sprintf("%s (%s): %s", e.Disposition, e.Cause, e.Detail))
	}
	if len(why) == 0 {
		why = append(why, "the unit was not planned, so nothing was run")
	}
	return engine.VerdictInconclusive, "the check did not run, so nothing is established either way: " +
		strings.Join(why, "; ")
}

// persistVerification writes a verification run and exits by its verdict.
func persistVerification(res engine.Result, run *store.Run, stdout, stderr io.Writer) error {
	if err := persistArtifacts(res, run, stdout, stderr); err != nil {
		return err
	}
	v := res.Verification
	fmt.Fprintf(stdout, "\n  verdict:  %s — %s\n", strings.ToUpper(string(v.Verdict)), v.Detail)
	switch v.Verdict {
	case engine.VerdictReproduced:
		return &exitError{code: ExitFindings}
	case engine.VerdictFixed:
		return nil
	}
	return &exitError{code: ExitNothingExecuted}
}

func newReportCommand(stdout io.Writer) *cobra.Command {
	var outputDir, configPath string
	cmd := &cobra.Command{
		Use:   "report [run-id]",
		Short: "Print a stored run's summary and its findings",
		Long: "Print the summary of a run already on disk, and each finding with the ref\n" +
			"`sulayi verify` takes. Nothing is sent to any target. With no run id, the most\n" +
			"recent run is printed.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The same output directory attack and verify use: the flag, then
			// sulayi.yaml, then the default.
			if outputDir == "" {
				outputDir = config.Default().Output.Dir
				path := configPath
				if path == "" {
					if _, err := os.Stat("sulayi.yaml"); err == nil {
						path = "sulayi.yaml"
					}
				}
				if path != "" {
					cfg, err := config.Load(path)
					if err != nil {
						return fail(ExitUsage, "%v", err)
					}
					outputDir = cfg.Output.Dir
				}
			}
			dirs := runDirs(outputDir)
			var dir string
			for _, d := range dirs {
				if len(args) == 0 || filepath.Base(d) == args[0] {
					dir = d
					break
				}
			}
			if dir == "" {
				return fail(ExitUsage, "no run found under %s", outputDir)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
			if err != nil {
				return fail(ExitUsage, "run %s has no readable report: %v", filepath.Base(dir), err)
			}
			var doc report.Document
			if err := json.Unmarshal(raw, &doc); err != nil {
				return fail(ExitUsage, "run %s's report is not readable: %v", filepath.Base(dir), err)
			}
			fmt.Fprintln(stdout, report.Summary(doc))
			fmt.Fprint(stdout, report.FindingsTable(doc))
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "run output directory (default: .sulayi)")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to sulayi.yaml (default: ./sulayi.yaml if present)")
	return cmd
}
