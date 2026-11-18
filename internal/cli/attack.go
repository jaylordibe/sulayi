package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/sulayi/internal/adapter"
	"github.com/jaylordibe/sulayi/internal/check"
	"github.com/jaylordibe/sulayi/internal/config"
	"github.com/jaylordibe/sulayi/internal/discovery"
	"github.com/jaylordibe/sulayi/internal/engine"
	"github.com/jaylordibe/sulayi/internal/httpx"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/openapi"
	"github.com/jaylordibe/sulayi/internal/outcome"
	"github.com/jaylordibe/sulayi/internal/redact"
	"github.com/jaylordibe/sulayi/internal/scanner"
	"github.com/jaylordibe/sulayi/internal/scanner/nuclei"
	"github.com/jaylordibe/sulayi/internal/scanner/sast"
	"github.com/jaylordibe/sulayi/internal/scanner/zap"
	"github.com/jaylordibe/sulayi/internal/scope"
	"github.com/jaylordibe/sulayi/internal/store"
)

// legacyConfigFile is the configuration file name used before the project was
// renamed to Sulayi. It is recognised only to refuse it with a clear message.
const legacyConfigFile = "appsec.yaml"

func newAttackCommand(stdout, stderr io.Writer) *cobra.Command {
	var (
		configPath string
		specFile   string
		specURL    string
		profile    string
		outputDir  string
		noProbe    bool
		yes        bool
	)

	cmd := &cobra.Command{
		Use:   "attack [target-url]",
		Short: "Assess a target application",
		Long: "Assess an application you own or are explicitly authorized to test.\n\n" +
			"The target URL you supply is the authorization you are giving: Sulayi\n" +
			"will contact that origin and nothing else unless you widen\n" +
			"the scope in sulayi.yaml.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(configPath, args)
			if err != nil {
				return err
			}
			if specFile != "" {
				cfg.Discovery.OpenAPIFile = specFile
				cfg.Discovery.OpenAPIURL = ""
			}
			if specURL != "" {
				cfg.Discovery.OpenAPIURL = specURL
				cfg.Discovery.OpenAPIFile = ""
			}
			if profile != "" {
				cfg.Assessment.Profile = profile
			}
			if outputDir != "" {
				cfg.Output.Dir = outputDir
			}
			if noProbe {
				no := false
				cfg.Discovery.ProbeWellKnownPaths = &no
			}
			if err := cfg.Validate(); err != nil {
				return fail(ExitUsage, "%v", err)
			}
			if cfg.Profile() == model.ProfileAggressive {
				if err := confirmAggressive(cfg, yes, stderr); err != nil {
					return err
				}
			}
			return runScan(cmd.Context(), cfg, stdout, stderr)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to sulayi.yaml (default: ./sulayi.yaml if present)")
	cmd.Flags().StringVar(&specFile, "spec", "", "path to an OpenAPI document on disk")
	cmd.Flags().StringVar(&specURL, "spec-url", "", "URL of an OpenAPI document served by the target")
	cmd.Flags().StringVar(&profile, "profile", "", "safety profile: safe, standard (default), aggressive")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "run output directory (default: .sulayi)")
	cmd.Flags().BoolVar(&noProbe, "no-probe", false, "do not probe well-known specification paths")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the aggressive-profile confirmation prompt; "+
		"needed when there is no terminal. It changes nothing else")
	return cmd
}

// resolveConfig loads sulayi.yaml if present, then applies the positional target.
//
// The URL the operator typed is treated as the authorization they granted: the
// target's own origin is always in scope, and loopback targets enable private
// addressing automatically. Requiring a config file before a first scan would
// make the documented first command fail.
func resolveConfig(configPath string, args []string) (config.Config, error) {
	cfg := config.Default()

	path := configPath
	if path == "" {
		if _, err := os.Stat("sulayi.yaml"); err == nil {
			path = "sulayi.yaml"
		} else if _, err := os.Stat(legacyConfigFile); err == nil {
			// Running with defaults would silently drop the operator's scope,
			// exclusions and identities, so a configuration under the old name
			// stops the run rather than being ignored.
			return config.Config{}, fail(ExitUsage,
				"found %s but no sulayi.yaml.\n\n"+
					"  This project was renamed to Sulayi. Rename the file to sulayi.yaml and\n"+
					"  set apiVersion: %s, or pass it explicitly with --config.",
				legacyConfigFile, config.CurrentAPIVersion)
		}
	}
	if path != "" {
		loaded, err := config.Load(path)
		if err != nil {
			return config.Config{}, fail(ExitUsage, "%v", err)
		}
		cfg = loaded
	}

	if len(args) == 1 {
		cfg.Target.BaseURL = args[0]
	}
	if cfg.Target.BaseURL == "" {
		return config.Config{}, fail(ExitUsage,
			"no target given.\n\n  Try:  sulayi attack http://localhost:3000\n"+
				"  Or:   sulayi init    (to create a sulayi.yaml)")
	}
	if !strings.Contains(cfg.Target.BaseURL, "://") {
		cfg.Target.BaseURL = "http://" + cfg.Target.BaseURL
	}
	// The URL the operator typed is the authorization they granted, so a loopback
	// target enables private addressing. A configuration file that already said
	// so is unaffected; one that said nothing gets the convenience.
	if isLoopbackTarget(cfg.Target.BaseURL) {
		cfg.Scope.AllowPrivateAddresses = true
	}
	return cfg, nil
}

// isLoopbackTarget reports whether the operator typed a loopback address.
//
// It parses the host as an address rather than matching a string prefix. A
// prefix test would treat an attacker-registrable name such as
// "127.0.0.1.nip.io" as loopback and silently enable private addressing for the
// entire run — overriding whatever the configuration said, and opening exactly
// the internal-service access the scope policy exists to prevent.
func isLoopbackTarget(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// A name, not an address. Names are never assumed to be loopback: the
		// name is not the address it resolves to.
		return false
	}
	return addr.IsLoopback()
}

func runScan(ctx context.Context, cfg config.Config, stdout, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// The duration limit bounds the whole assessment, discovery included.
	// Restoring a fixture is deliberately outside it: that runs on its own
	// short, bounded context so that running out of time cannot be the reason
	// data is left modified.
	ctx, cancelDeadline := context.WithTimeout(ctx,
		time.Duration(cfg.Assessment.MaxDurationMinutes)*time.Minute)
	defer cancelDeadline()
	now := time.Now
	runID := newRunID(now())

	policy, err := cfg.ScopePolicy()
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	red := redact.New()

	// The run directory is created before the first request, so evidence can be
	// written as it is captured and the request log covers discovery as well as
	// the assessment.
	run, err := store.Create(cfg.Output.Dir, runID, now())
	if err != nil {
		return fail(ExitInternal, "%v", err)
	}
	if err := run.WriteFingerprintKey(red.FingerprintKey()); err != nil {
		return fail(ExitInternal, "%v", err)
	}

	// The guard is built from the same validated profile the plan uses, and the
	// engine refuses to run if the two ever disagree.
	guard, err := httpx.NewGuard(cfg.Profile(), cfg.Assessment.StateChangingOperations)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}

	client, err := httpx.New(httpx.Options{
		Policy:            policy,
		Redactor:          red,
		Timeout:           time.Duration(cfg.Assessment.TimeoutSeconds) * time.Second,
		MaxBodyBytes:      httpx.DefaultMaxBodyBytes,
		Now:               now,
		RequestsPerSecond: cfg.Assessment.RequestsPerSecond,
		MaxRequests:       cfg.Assessment.MaxRequests,
		CleanupAllowance:  cleanupAllowance(cfg),
		Guard:             guard,
		Audit: func(r httpx.AuditRecord) error {
			return run.LogRequest(store.RequestLogEntry{
				Seq: r.Seq, Time: r.Time, Method: r.Method, URL: r.URL, Identity: r.Identity,
				Cleanup: r.Cleanup, Outcome: r.Outcome, Reason: r.Reason, Status: r.Status,
				ElapsedMs: r.Elapsed.Milliseconds(),
			})
		},
	})
	if err != nil {
		return fail(ExitInternal, "%v", err)
	}
	defer client.Close()

	if cfg.Scope.AllowPrivateAddresses {
		fmt.Fprintf(stderr, "sulayi: scope: %s (private addresses permitted for this target)\n", cfg.Target.BaseURL)
	}
	if !store.PermissionsEnforced() {
		fmt.Fprintln(stderr,
			"sulayi: warning: this platform does not enforce owner-only file permissions, "+
				"so the run directory may be readable by other users")
	}

	surface, err := discover(ctx, cfg, client, now)
	if err != nil {
		return fail(ExitAborted, "discovery failed: %v", err)
	}

	// Framework adapters run before planning, because their whole purpose is to
	// change what the plan knows. They are opt-in: nothing here executes unless
	// the operator named an adapter.
	var merged adapter.MergeResult
	if specs := cfg.AdapterSpecs(); len(specs) > 0 {
		collected := adapter.Collect(ctx, specs, adapter.Options{
			Trust: cfg.AdapterTrust(),
			// This tool's own identity credentials can never reach an adapter,
			// whatever the configuration asks for.
			ForbiddenEnv: cfg.CredentialEnvNames(),
			Now:          now,
		})
		for _, f := range collected.Failures {
			fmt.Fprintf(stderr, "sulayi: %s\n", f)
		}
		merged = adapter.MergeInto(surface.Operations, collected.Documents, func() model.Source {
			return model.Source{ObservedAt: now()}
		})
		surface.Operations = merged.Operations
		surface.AdapterFailures = collected.Failures
		surface.AdapterLimitations = append(merged.Limitations, collected.Limitations...)
		surface.AdapterMerges = merged.Merges
		surface.AdapterUnmatched = merged.UnmatchedOperations

		// Operations an adapter found that the specification does not document
		// are surface beyond the specification with a method and an oracle:
		// the adapter read the routing table, so nothing has to be invented to
		// assess them. This is the one narrow case where discovered surface is
		// genuinely testable, and it is still a switch, because it means
		// requesting routes the operator may not have known were there.
		if len(merged.DiscoveredOperations) > 0 && cfg.AssessAdapterDiscovered() {
			surface.Operations = append(surface.Operations, merged.DiscoveredOperations...)
			model.SortOperations(surface.Operations)
			for _, op := range merged.DiscoveredOperations {
				surface.AdapterDiscovered = append(surface.AdapterDiscovered, op.ID)
			}
			fmt.Fprintf(stderr, "sulayi: %d operation(s) reported by an adapter are absent from "+
				"the specification and were added to the assessed surface\n",
				len(merged.DiscoveredOperations))
		}

		// Re-grade the oracle: adapter facts may have given operations an
		// expectation the specification did not carry, and the grade must
		// reflect the surface actually being assessed.
		surface.Fidelity = openapi.Grade(surface.Operations)
	}

	// Discovery of surface the specification does not describe. It runs after
	// adapters so that a path an adapter already accounted for corroborates
	// that operation rather than appearing as a separate undocumented route.
	if sources := cfg.DiscoverySources(); sources.Any() {
		found := discovery.Run(ctx, discovery.Options{
			Target: cfg.Target.BaseURL,
			Client: client,
			Limits: cfg.DiscoveryLimits(),
			Enable: sources,
			Now:    now,
		})
		m := discovery.Merge(surface.Operations, found.Candidates)
		surface.Discovered = m.Undocumented
		surface.DiscoveryCorroborated = m.Corroborated
		surface.DiscoveryOffOrigin = m.OffOrigin
		surface.DiscoveryAttempts = found.Attempts
		surface.DiscoveryIncomplete = found.Incomplete
		surface.DiscoveryLimitations = found.Limitations
		surface.DiscoveryRequests = found.Requests
		surface.DiscoveryBytes = found.Bytes

		if n := len(m.Undocumented); n > 0 {
			fmt.Fprintf(stderr, "sulayi: discovery found %d path(s) no specification or adapter "+
				"describes; each is recorded as untested\n", n)
		}
		if found.Incomplete {
			fmt.Fprintln(stderr, "sulayi: discovery stopped at a budget, so the discovered "+
				"surface below is a floor rather than a total")
		}
	}

	// Identities are resolved before any request is possible, so that every
	// credential is registered with the redactor before the first exchange can
	// be captured. Resolution never fails the run: an identity whose credential
	// is missing becomes a blocked ledger row, which is strictly more useful
	// than an error, and far more useful than proceeding anonymously in silence.
	identities := identity.Resolve(cfg.IdentityModels(), cfg.Target.BaseURL, client, red)
	for _, st := range identities.Statuses() {
		if !st.Usable {
			fmt.Fprintf(stderr, "sulayi: identity %s: credential unavailable from %s (%s); "+
				"no authenticated control request will be made\n", st.ID, st.Source, st.Problem)
		}
		for _, w := range st.Warnings {
			fmt.Fprintf(stderr, "sulayi: identity %s: warning: %s\n", st.ID, w)
		}
	}

	// One signal set for every check, so an operator-supplied error-code oracle
	// cannot apply to one classification and not another.
	signals := outcome.Signals{
		ErrorCodePointer: cfg.Outcome.ErrorCodePointer,
		DeniedCodes:      cfg.Outcome.DeniedCodes,
		NotFoundCodes:    cfg.Outcome.NotFoundCodes,
	}

	fixtures := cfg.ResourceFixtures()

	checks := []engine.Check{
		check.AuthRequired{
			Client:         client,
			Signals:        signals,
			BaselineProbes: 2,
			Resources:      fixtures,
			Control:        identities.Primary(),
			Now:            now,
		},
	}

	if len(fixtures) > 0 && identities.Len() < 2 {
		fmt.Fprintln(stderr, "sulayi: warning: resource fixtures are configured but fewer than two "+
			"identities are; a cross-owner boundary needs an owner and a non-owner, so no "+
			"cross-owner work can run")
	}

	// External engines run before the assessment is assembled, because what
	// they did or did not do changes the coverage account. They are opt-in:
	// nothing here executes unless the operator enabled an engine.
	engines := scanner.RunAll(ctx, []scanner.Registered{
		{Engine: nuclei.New(), Settings: cfg.Engines.Nuclei.EngineSettings()},
		{Engine: zap.New(), Settings: cfg.Engines.ZAP.EngineSettings()},
		{Engine: sast.New(), Settings: cfg.Engines.SAST.EngineSettings()},
	}, scanner.Target{
		BaseURL:    cfg.Target.BaseURL,
		SourceRoot: cfg.Engines.SourceRoot,
		Profile:    cfg.Profile(),
	}, scanner.Options{
		// This tool's own identity credentials can never reach a scanner.
		ForbiddenEnv: cfg.CredentialEnvNames(),
		Redactor:     red,
		RunID:        runID,
		Now:          now,
	})
	for _, f := range engines.Failures {
		fmt.Fprintf(stderr, "sulayi: %s\n", f)
	}

	// An operator may name a state-changing operation in the specification's
	// spelling, which is relative to its server URL. The guard sees request
	// URLs, so it is also given the application-absolute spelling of every
	// operation the name matches. Registration closes when planning ends.
	for _, op := range surface.Operations {
		if op.MatchesAnyID(cfg.Assessment.StateChangingOperations) {
			if err := guard.AddStateChangingTemplate(op.Method + " " + op.AbsolutePath()); err != nil {
				return fail(ExitInternal, "%v", err)
			}
		}
	}

	res, err := engine.Run(ctx, engine.Options{
		RunID:                   runID,
		Target:                  cfg.Target.BaseURL,
		TargetName:              cfg.Target.Name,
		Profile:                 cfg.Profile(),
		Surface:                 surface,
		Checks:                  checks,
		Environment:             engine.Environment{Name: cfg.Environment.Name, Differences: cfg.Environment.Differences},
		ScopeEntries:            scopeStrings(policy),
		AllowPrivate:            cfg.Scope.AllowPrivateAddresses,
		ExcludeOperations:       cfg.Assessment.ExcludeOperations,
		StateChangingOperations: cfg.Assessment.StateChangingOperations,
		Guard:                   guard,
		ExcludeAuthEndpoints:    cfg.ShouldExcludeAuthEndpoints(),
		Concurrency:             cfg.Assessment.Concurrency,
		RequestsPerSecond:       cfg.Assessment.RequestsPerSecond,
		Identities:              identities,
		Resources:               fixtures,
		ResourceCheck:           check.CrossOwner{Signals: signals, Now: now},
		Now:                     now,
		Engines:                 engines,
		EvidenceSink:            run.PutEvidence,
	})
	if err != nil {
		return fail(ExitInternal, "%v", err)
	}
	res.OutOfScopeHosts = policy.OutOfScopeHosts()
	usage := client.Usage()
	res.Requests, res.RequestLimit, res.CleanupRequests = usage.Used, usage.Limit, usage.CleanupUsed
	res.StoppedEarly = stoppedEarly(ctx, cfg, usage, res)

	return persistAndSummarize(res, run, cfg.Policy, stdout, stderr)
}

// discover builds the attack surface.
func discover(ctx context.Context, cfg config.Config, client *httpx.Client, now func() time.Time) (engine.Surface, error) {
	var raw []byte
	var source model.Source

	switch {
	case cfg.Discovery.OpenAPIFile != "":
		path := filepath.Clean(cfg.Discovery.OpenAPIFile)
		data, err := os.ReadFile(path)
		if err != nil {
			return engine.Surface{}, fmt.Errorf("cannot read specification: %w", err)
		}
		if len(data) > openapi.MaxDocumentBytes {
			return engine.Surface{}, fmt.Errorf("specification exceeds %d bytes", openapi.MaxDocumentBytes)
		}
		raw = data
		source = openapi.SourceAt(model.SourceOpenAPIFile, path, now())

	case cfg.Discovery.OpenAPIURL != "":
		data, err := fetchSpec(ctx, client, cfg.Discovery.OpenAPIURL)
		if err != nil {
			return engine.Surface{}, err
		}
		raw = data
		source = openapi.SourceAt(model.SourceOpenAPIURL, cfg.Discovery.OpenAPIURL, now())

	case cfg.ShouldProbeWellKnownPaths():
		base := strings.TrimRight(cfg.Target.BaseURL, "/")
		// Track whether the probes were refused by scope rather than simply
		// finding nothing. Reporting "no document found" when in fact every
		// request was refused would misdescribe what happened, which is the
		// failure this project exists to prevent.
		var scopeRefusal error
		var parseFailure error
		for _, p := range openapi.WellKnownPaths() {
			candidate := base + p
			data, err := fetchSpec(ctx, client, candidate)
			if err != nil {
				var oos *httpx.ErrOutOfScope
				if errors.As(err, &oos) && scopeRefusal == nil {
					scopeRefusal = oos
				}
				continue
			}
			if len(data) == 0 {
				continue
			}
			if _, perr := openapi.Parse(data, cfg.Target.BaseURL, model.Source{}); perr != nil {
				// A target serving only a malformed document should be told it
				// was malformed, not that nothing was found.
				if parseFailure == nil {
					parseFailure = fmt.Errorf("%s: %v", p, perr)
				}
				continue
			}
			raw = data
			source = openapi.SourceAt(model.SourceOpenAPIURL, candidate, now())
			break
		}
		if raw == nil && scopeRefusal != nil {
			return engine.Surface{}, fmt.Errorf(
				"every request to the target was refused by the scope policy, so nothing "+
					"was assessed\n\n  %v\n\n"+
					"  This is a refusal, not a clean result. Cloud metadata addresses are\n"+
					"  always denied. To assess a different host, widen scope deliberately:\n"+
					"    scope.include in sulayi.yaml", scopeRefusal)
		}
		if raw == nil && parseFailure != nil {
			return engine.Surface{}, fmt.Errorf(
				"a document was served at a well-known path but could not be parsed\n\n"+
					"  %v\n\n"+
					"  This is a parse failure, not an absence. Point Sulayi at a valid\n"+
					"  document:\n"+
					"    sulayi attack <target> --spec ./openapi.json", parseFailure)
		}
		if raw == nil {
			return engine.Surface{}, fmt.Errorf(
				"no OpenAPI document found.\n\n" +
					"  Sulayi derives what should be protected from the application's own\n" +
					"  specification. Without one it has no oracle and would be guessing.\n\n" +
					"  Point it at a document:\n" +
					"    sulayi attack <target> --spec ./openapi.json\n" +
					"    sulayi attack <target> --spec-url <target>/api/docs-json")
		}
	default:
		return engine.Surface{}, fmt.Errorf("no specification configured and probing is disabled")
	}

	res, err := openapi.Parse(raw, cfg.Target.BaseURL, source)
	if err != nil {
		return engine.Surface{}, err
	}
	return engine.Surface{
		SpecDerived:  true,
		SpecSource:   source,
		SpecTitle:    res.Title,
		SpecVersion:  res.Version,
		Fidelity:     res.Fidelity,
		Operations:   res.Operations,
		ExternalRefs: res.ExternalRefs,
		Warnings:     res.Warnings,
	}, nil
}

func fetchSpec(ctx context.Context, client *httpx.Client, rawURL string) ([]byte, error) {
	ex, err := client.Do(ctx, httpx.Request{
		Method: "GET",
		URL:    rawURL,
		Header: map[string][]string{"Accept": {"application/json, application/yaml, */*"}},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot fetch specification: %w", err)
	}
	if ex.Response == nil || ex.Response.Status < 200 || ex.Response.Status > 299 {
		status := 0
		if ex.Response != nil {
			status = ex.Response.Status
		}
		return nil, fmt.Errorf("specification request returned status %d", status)
	}
	return ex.Response.Body, nil
}

func scopeStrings(p *scope.Policy) []string { return p.EntryStrings() }

// newRunID is time-ordered so runs sort naturally, with a random suffix so two
// runs started in the same second cannot collide.
func newRunID(t time.Time) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return t.UTC().Format("20060102T150405Z")
	}
	return t.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// CleanupRequestsPerWrite is the most a single cross-owner write needs after it
// is sent: the owner's after-read, the restoring write and its verification,
// with one to spare.
const CleanupRequestsPerWrite = 4

// cleanupAllowance sizes the requests reserved above the budget for restoring
// fixtures: enough for every write the configuration could make, and no more.
func cleanupAllowance(cfg config.Config) int {
	attackers := len(cfg.Identities) - 1
	if attackers < 1 {
		attackers = 1
	}
	var writes int
	for _, r := range cfg.Resources {
		if r.Mutation != nil {
			writes += attackers
		}
	}
	return writes * CleanupRequestsPerWrite
}

// stoppedEarly says why an assessment ended before finishing its plan, or ""
// when it did not.
func stoppedEarly(ctx context.Context, cfg config.Config, usage httpx.BudgetUsage, res engine.Result) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Sprintf("the %d-minute duration limit (assessment.maxDurationMinutes) was reached",
			cfg.Assessment.MaxDurationMinutes)
	case errors.Is(ctx.Err(), context.Canceled):
		return "the assessment was interrupted"
	}
	if usage.Limit > 0 && usage.Used >= usage.Limit {
		for _, e := range res.Coverage {
			if e.Cause == model.CauseBudgetExceeded {
				return fmt.Sprintf("the %d-request budget (assessment.maxRequests) was spent", usage.Limit)
			}
		}
	}
	return ""
}

// confirmationInput supplies the operator's answer to the aggressive-profile
// prompt, and whether there is a terminal to ask on. It is a variable so that
// tests can answer the prompt.
var confirmationInput = func() (io.Reader, bool) {
	info, err := os.Stdin.Stat()
	return os.Stdin, err == nil && info.Mode()&os.ModeCharDevice != 0
}

// confirmAggressive is the last gate before aggressive testing starts.
//
// The configuration has already declared the target disposable; this asks the
// person running the command to say which target they mean, by typing its exact
// origin. Typing the name, rather than answering y, is the established pattern
// for irreversible operations: it cannot be answered by reflex, and it catches a
// configuration copied from the wrong environment. --yes replaces the prompt for
// a run with no terminal and changes nothing else.
func confirmAggressive(cfg config.Config, yes bool, stderr io.Writer) error {
	origin, err := scope.ParseOrigin(cfg.Target.BaseURL)
	if err != nil {
		return fail(ExitUsage, "the target's origin could not be established, so aggressive "+
			"testing cannot be confirmed: %v", err)
	}
	want := origin.String()
	if yes {
		fmt.Fprintf(stderr, "sulayi: aggressive profile confirmed by --yes for %s\n", want)
		return nil
	}
	in, terminal := confirmationInput()
	if !terminal {
		return fail(ExitUsage, "the aggressive profile needs confirmation and there is no terminal "+
			"to ask on. Run it interactively, or pass --yes to confirm %s", want)
	}
	fmt.Fprintf(stderr, "The aggressive profile may change or destroy any data %s holds.\n"+
		"Type the target origin to confirm: ", want)
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != want {
		return fail(ExitUsage, "confirmation did not match %s; nothing was sent", want)
	}
	return nil
}
