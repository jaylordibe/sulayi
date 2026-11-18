package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jaylordibe/sulayi/internal/config"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/scanner"
	"github.com/jaylordibe/sulayi/internal/scanner/nuclei"
	"github.com/jaylordibe/sulayi/internal/scanner/sast"
	"github.com/jaylordibe/sulayi/internal/scanner/zap"
	"github.com/jaylordibe/sulayi/internal/store"
)

// engineTool describes an optional external engine.
//
// Nothing here is bundled and nothing is required. An absent engine is reported
// as an explicit gap rather than silently reducing what a run covers.
type engineTool struct {
	name    string
	binary  string
	unlocks string
	status  string
}

func newDoctorCommand(stdout, stderr io.Writer) *cobra.Command {
	var configPath, envFile string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what is available and what each missing piece would unlock",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(stdout, "sulayi %s (%s/%s, %s)\n\n",
				resolveVersion(), runtime.GOOS, runtime.GOARCH, runtime.Version())

			fmt.Fprintln(stdout, "Core")
			fmt.Fprintf(stdout, "  %-22s %s\n", "specification ingest", "available (OpenAPI 3.x)")
			fmt.Fprintf(stdout, "  %-22s %s\n", "declared-auth check", "available")
			if store.PermissionsEnforced() {
				fmt.Fprintf(stdout, "  %-22s %s\n", "file permissions", "enforced (owner-only)")
			} else {
				fmt.Fprintf(stdout, "  %-22s %s\n", "file permissions", "NOT enforced on this platform")
			}

			reportIdentities(stdout, configPath, envFile)

			reportEngines(cmd.Context(), stdout, configPath)

			fmt.Fprintln(stdout, "\nOther optional tools (none are bundled; none are required)")
			tools := []engineTool{
				{name: "Hadrian", binary: "hadrian", unlocks: "multi-identity authorization testing (not integrated)"},
			}
			for i := range tools {
				if _, err := exec.LookPath(tools[i].binary); err == nil {
					tools[i].status = "found"
				} else {
					tools[i].status = "not found"
				}
				fmt.Fprintf(stdout, "  %-22s %-10s %s\n", tools[i].name, tools[i].status, tools[i].unlocks)
			}

			fmt.Fprintln(stdout, "\nNote: Sulayi never downloads or installs an engine, and this command\n"+
				"changes nothing on this machine. An engine that is absent is reported as blocked\n"+
				"during a scan, never as a clean result.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to sulayi.yaml (default: ./sulayi.yaml if present)")
	cmd.Flags().StringVar(&envFile, "env", "", "credentials file to check, as sulayi attack --env reads it")
	return cmd
}

// reportIdentities says whether each configured identity's credential can be
// resolved.
//
// It reports availability and location only. A credential value is never
// printed, and neither is its length or a fingerprint of it: `doctor` output is
// pasted into issues and CI logs, which is exactly where a secret must not be.
//
// This deliberately does not contact the target. Checking whether a credential
// is *accepted* is the liveness canary's job during a run; doing it here would
// turn a local diagnostic into an unannounced authenticated request.
func reportIdentities(stdout io.Writer, configPath, envFile string) {
	path := configPath
	if path == "" {
		if _, err := os.Stat("sulayi.yaml"); err != nil {
			return
		}
		path = "sulayi.yaml"
	}

	fmt.Fprintln(stdout, "\nIdentities (from "+path+")")
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stdout, "  %-22s %s\n", "configuration", "could not be read; run a scan for the full error")
		return
	}
	lookup := identity.ProcessEnv
	if envFile != "" {
		creds, err := identity.LoadEnvFile(envFile, cfg.CredentialEnvNames())
		if err != nil {
			fmt.Fprintf(stdout, "  %-22s %v\n", "credentials file", err)
		} else {
			lookup = creds.Lookup
			fmt.Fprintf(stdout, "  %-22s %s (%d referenced name(s) defined, %d other entr(ies) ignored)\n",
				"credentials file", creds.Path(), len(cfg.CredentialEnvNames())-missingIn(creds, cfg.CredentialEnvNames()),
				creds.Ignored)
			for _, w := range creds.Warnings {
				fmt.Fprintf(stdout, "  %-22s warning: %s\n", "", w)
			}
		}
	}
	ids := cfg.IdentityModels()
	if len(ids) == 0 {
		fmt.Fprintf(stdout, "  %-22s %s\n", "none configured",
			"no authenticated control request is possible, so no finding can reach confirmed")
		return
	}
	for _, id := range ids {
		label := id.ID
		if id.Role != "" {
			label += " (" + id.Role + ")"
		}
		if id.Auth.Scheme == identity.SchemeLogin && id.Auth.Login != nil {
			method, _, _, _ := id.LoginRequest(cfg.Target.BaseURL)
			status := "login fields configured"
			for _, f := range id.Auth.Login.Fields {
				if f.FromPreflight != "" {
					continue
				}
				if _, rerr := f.Source.ResolveWith(lookup); rerr != nil {
					status = "login field " + f.Name + " unavailable: " + rerr.Error()
					break
				}
			}
			fmt.Fprintf(stdout, "  %-22s %s (login %s %s; doctor does not sign in)\n", label, status,
				method, id.Auth.Login.Path)
			if !id.Live.Configured() {
				fmt.Fprintf(stdout, "  %-22s %s\n", "",
					"no liveness canary; an expired session could not be detected or recovered")
			}
			continue
		}
		status := "credential source configured"
		if _, rerr := id.Auth.Credential.ResolveWith(lookup); rerr != nil {
			status = "credential unavailable: " + rerr.Error()
		}
		fmt.Fprintf(stdout, "  %-22s %s (%s)\n", label, status, id.Auth.Credential.Describe())
		if !id.Live.Configured() {
			fmt.Fprintf(stdout, "  %-22s %s\n", "",
				"no liveness canary; an expiry during a run could not be detected")
		}
	}
}

// reportEngines says what each external engine could do on this machine.
//
// It resolves executables and asks them their version, which is what "usable"
// actually means; reporting presence on PATH alone would say a binary exists
// without saying whether it runs. It changes nothing: no download, no install,
// no scan.
func reportEngines(ctx context.Context, stdout io.Writer, configPath string) {
	if ctx == nil {
		ctx = context.Background()
	}
	fmt.Fprintln(stdout, "\nExternal scanning engines (none are bundled; none are required)")

	// Settings from the configuration when there is one, so `doctor` reports on
	// the engines this project is actually set up to use.
	settings := map[string]scanner.Settings{}
	if cfg, err := loadConfigIfPresent(configPath); err == nil {
		settings["nuclei"] = cfg.Engines.Nuclei.EngineSettings()
		settings["zap"] = cfg.Engines.ZAP.EngineSettings()
		settings["sast"] = cfg.Engines.SAST.EngineSettings()
	}

	// Blocked engines are located without being run, so doctor can still say
	// whether one is installed.
	locators := map[string]func(scanner.Settings) (string, error){
		"nuclei": nuclei.Locate,
		"zap":    zap.Locate,
	}
	for _, e := range []scanner.Engine{nuclei.New(), zap.New(), sast.New()} {
		meta := e.Meta()
		enabledLabel := "disabled"
		if settings[meta.ID].Enabled {
			enabledLabel = "enabled"
		}
		// An engine that opens its own network connections is not executed here
		// either: probing its version means running it, and some engines
		// contact the network on start-up. It is reported as blocked, with why.
		if !meta.Offline {
			fmt.Fprintf(stdout, "  %-12s %-18s %-9s %s\n", meta.Title, "BLOCKED", enabledLabel, meta.Unlocks)
			if locate := locators[meta.ID]; locate != nil {
				if path, err := locate(settings[meta.ID]); err == nil {
					fmt.Fprintf(stdout, "  %-12s installed at %s (not executed)\n", "", path)
				} else {
					fmt.Fprintf(stdout, "  %-12s not found: %v\n", "", err)
				}
			}
			fmt.Fprint(stdout, wrapIndented(scanner.NetworkBlockedDetail(meta.Title), 64, "               "))
			continue
		}
		avail := e.Detect(ctx, settings[meta.ID])
		status := "not found"
		if avail.Present {
			status = "found " + avail.Version
		}
		fmt.Fprintf(stdout, "  %-12s %-18s %-9s %s\n", meta.Title, status, enabledLabel, meta.Unlocks)
		if !avail.Present {
			fmt.Fprintf(stdout, "  %-12s %s\n", "", meta.InstallHint)
			if avail.Problem != "" {
				fmt.Fprintf(stdout, "  %-12s %s\n", "", avail.Problem)
			}
			continue
		}
		fmt.Fprintf(stdout, "  %-12s at %s\n", "", avail.Path)
		for _, w := range avail.Warnings {
			fmt.Fprintf(stdout, "  %-12s note: %s\n", "", w)
		}
	}
}

// loadConfigIfPresent reads the configuration when one exists.
func loadConfigIfPresent(configPath string) (config.Config, error) {
	path := configPath
	if path == "" {
		if _, err := os.Stat("sulayi.yaml"); err != nil {
			return config.Config{}, err
		}
		path = "sulayi.yaml"
	}
	return config.Load(path)
}

// wrapIndented breaks text into lines of at most width characters, each
// prefixed with indent.
func wrapIndented(text string, width int, indent string) string {
	var b strings.Builder
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && len(line)+1+len(w) > width {
			b.WriteString(indent + line + "\n")
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		b.WriteString(indent + line + "\n")
	}
	return b.String()
}
