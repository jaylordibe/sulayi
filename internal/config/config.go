// Package config loads and validates sulayi.yaml.
//
// Configuration is trusted in the sense that the operator wrote it, but it is
// validated strictly anyway: a trusted author still makes mistakes, and a
// configuration file may arrive through a pull request.
//
// Three YAML behaviours are deliberately not enabled. The decoder is never given
// ReferenceFiles or ReferenceDirs, which would let a configuration file pull
// anchor definitions from arbitrary filesystem paths. Input is size-capped, and
// alias expansion is bounded, because alias/merge expansion is a classic
// exponential-blowup denial of service (threat model T-04).
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/jaylordibe/sulayi/internal/access"
	"github.com/jaylordibe/sulayi/internal/adapter"
	"github.com/jaylordibe/sulayi/internal/discovery"
	"github.com/jaylordibe/sulayi/internal/identity"
	"github.com/jaylordibe/sulayi/internal/model"
	"github.com/jaylordibe/sulayi/internal/record"
	"github.com/jaylordibe/sulayi/internal/resource"
	"github.com/jaylordibe/sulayi/internal/scanner"
	"github.com/jaylordibe/sulayi/internal/scope"
)

// adapterNamePattern constrains an adapter name to a plain identifier.
var adapterNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// envPattern constrains an environment variable name to the POSIX shape.
var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// engineSeverityPattern constrains a severity filter to a plain word, so an
// operator-supplied value reaching an argument vector cannot look like a flag.
var engineSeverityPattern = regexp.MustCompile(`^[a-z]{1,16}$`)

// MaxConfigBytes bounds a configuration file.
const MaxConfigBytes = 1 << 20 // 1 MiB

// CurrentAPIVersion is the only configuration version this build understands.
//
// It is required from day one. Adding a version field later, after strict
// decoding has already rejected unknown fields, would make every existing
// configuration invalid.
const CurrentAPIVersion = "sulayi/v1alpha1"

// httpMethodPattern accepts an HTTP method token as an operator would write one.
var httpMethodPattern = regexp.MustCompile(`^[A-Za-z]+$`)

// Assessment budget defaults and ceilings. The defaults are deliberately
// conservative for a first run against an unfamiliar target; both are
// configurable.
const (
	DefaultMaxRequests        = 1000
	DefaultMaxDurationMinutes = 30
	MaxMaxRequests            = 100000
	MaxMaxDurationMinutes     = 24 * 60
)

// legacyAPIVersion is the apiVersion written before the project was renamed to
// Sulayi. It is recognised only to reject it with a migration message.
const legacyAPIVersion = "appsec/v1alpha1"

// Config is the parsed sulayi.yaml.
type Config struct {
	APIVersion  string      `yaml:"apiVersion"`
	Target      Target      `yaml:"target"`
	Scope       Scope       `yaml:"scope"`
	Assessment  Assessment  `yaml:"assessment"`
	Identities  []Identity  `yaml:"identities"`
	Resources   []Resource  `yaml:"resources"`
	Records     []Record    `yaml:"records"`
	Adapters    Adapters    `yaml:"adapters"`
	Engines     Engines     `yaml:"engines"`
	Discovery   Discovery   `yaml:"discovery"`
	Access      Access      `yaml:"access"`
	Outcome     Outcome     `yaml:"outcome"`
	Environment Environment `yaml:"environment"`
	Policy      Policy      `yaml:"policy"`
	Output      Output      `yaml:"output"`
}

// Policy decides when a run fails the build.
//
// Without this the exit code is decorative: the only shipped check produces
// suspected findings, so gating solely on confirmed ones would exit 0 on a real
// authentication bypass and quietly green-light a pipeline.
type Policy struct {
	// FailOnConfirmed is the lowest severity of a CONFIRMED finding that fails
	// the run. Empty disables the rule.
	FailOnConfirmed string `yaml:"failOnConfirmed"`
	// FailOnSuspected is the lowest severity of a SUSPECTED finding that fails
	// the run. Suspected findings are unverified by definition, so the default is
	// deliberately high rather than off: an unverified high-severity finding is
	// worth a human looking at it.
	FailOnSuspected string `yaml:"failOnSuspected"`
}

// Target names the application under assessment.
type Target struct {
	// BaseURL is the root of the application, e.g. http://localhost:3000.
	BaseURL string `yaml:"baseURL"`
	// Name is a label used in reports.
	Name string `yaml:"name"`
	// Disposable declares that the target is an isolated environment whose
	// data may be changed or destroyed. The aggressive profile requires it, and
	// it is a statement in a reviewable file rather than a flag, so that the
	// decision is visible to whoever reads the configuration.
	Disposable bool `yaml:"disposable"`
}

// Scope is the network authorization boundary.
type Scope struct {
	// Include lists additional allowed endpoints. The target's own origin is
	// always included.
	Include []ScopeEntry `yaml:"include"`
	// AllowPrivateAddresses permits loopback and RFC1918 addresses. Assessing a
	// local application requires this, and requiring it to be stated makes the
	// decision deliberate rather than accidental.
	AllowPrivateAddresses bool `yaml:"allowPrivateAddresses"`
}

// ScopeEntry is one allowlist grant.
type ScopeEntry struct {
	Scheme     string `yaml:"scheme"`
	Host       string `yaml:"host"`
	Ports      []int  `yaml:"ports"`
	PathPrefix string `yaml:"pathPrefix"`
}

// Assessment controls safety and pacing.
type Assessment struct {
	// Profile is the effective safety profile. It never escalates implicitly.
	Profile string `yaml:"profile"`
	// LegacyAuthorizeIntrusive is the pre-Sulayi authorization switch. It is
	// parsed only so that a configuration still using it is refused with a
	// migration message rather than a generic unknown-field error.
	LegacyAuthorizeIntrusive *bool `yaml:"authorizeIntrusive"`
	// MaxRequests bounds every request the assessment sends to the target. A
	// small fixed allowance above it is reserved for restoring fixtures.
	MaxRequests int `yaml:"maxRequests"`
	// MaxDurationMinutes bounds the wall-clock length of the assessment.
	MaxDurationMinutes int `yaml:"maxDurationMinutes"`
	// StateChangingOperations lists operation ids that change state even though
	// their HTTP method says otherwise, such as GET /logout. They are held to
	// the rules for state-changing requests whatever their method.
	StateChangingOperations []string `yaml:"stateChangingOperations"`
	// Concurrency bounds simultaneous requests to the target.
	Concurrency int `yaml:"concurrency"`
	// RequestsPerSecond bounds request rate. Assessment tooling that hammers a
	// target gets itself blocked, and every later response then classifies as a
	// denial, producing a false clean report.
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
	// TimeoutSeconds bounds a single request.
	TimeoutSeconds int `yaml:"timeoutSeconds"`
	// ExcludeOperations lists operation ids that must never be exercised.
	ExcludeOperations []string `yaml:"excludeOperations"`
	// ExcludeAuthEndpoints skips operations whose path looks like
	// authentication. Sweeping unauthenticated requests across login routes can
	// trip account lockout on real accounts and poison the rest of the run.
	ExcludeAuthEndpoints *bool `yaml:"excludeAuthEndpoints"`
}

// Identity is one security principal Sulayi may act as.
//
// The credential itself is deliberately absent from this struct. Only a
// reference to where the material lives is configurable, so that a credential
// cannot be committed to a repository, reviewed in a pull request, or copied
// into a CI log by the ordinary act of sharing a configuration file.
type Identity struct {
	// ID is a stable, short name used in the ledger and in reports.
	ID string `yaml:"id"`
	// Label is a human-readable description.
	Label string `yaml:"label"`
	// Role labels what the identity is in the application. Reported only.
	Role string `yaml:"role"`
	// Authentication says how to authenticate as this identity.
	Authentication Authentication `yaml:"authentication"`
	// Liveness configures a canary that establishes whether the identity is
	// still usable. Optional, and strongly recommended: without one, a
	// credential expiring mid-run cannot be detected.
	Liveness *LivenessProbe `yaml:"liveness"`
}

// Authentication is a supported authentication mechanism and its credential
// reference.
type Authentication struct {
	// Type is bearer, apiKey or login.
	Type string `yaml:"type"`
	// Header is the field name for the apiKey type.
	Header string `yaml:"header"`
	// ValuePrefix is prepended to the credential for the apiKey type.
	ValuePrefix string `yaml:"valuePrefix"`
	// Credential references where the secret is read from.
	Credential Credential `yaml:"credential"`
	// Login is the sign-in flow for the login type.
	Login *LoginFlow `yaml:"login"`
}

// LoginFlow signs in through the application's own login request.
type LoginFlow struct {
	// Method defaults to POST.
	Method string `yaml:"method"`
	// Path is a path on the target, never a URL.
	Path string `yaml:"path"`
	// Form sends a URL-encoded form instead of JSON.
	Form bool `yaml:"form"`
	// Body maps each field to where its value comes from.
	Body map[string]LoginField `yaml:"body"`
	// Preflight is an optional read-only request sent first.
	Preflight *LoginPreflight `yaml:"preflight"`
	// Session says what the login issues.
	Session LoginSession `yaml:"session"`
	// CSRF copies a cookie into a header for a cookie session.
	CSRF *LoginCSRF `yaml:"csrf"`
}

// LoginField is one login body field: a reference, never a value.
type LoginField struct {
	Env           string `yaml:"env"`
	File          string `yaml:"file"`
	FromPreflight string `yaml:"fromPreflight"`
}

// LoginPreflight is a GET or HEAD sent before the login.
type LoginPreflight struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// LoginSession is either a bearer token read from the response by JSON
// pointer, or the cookies the response sets.
type LoginSession struct {
	Bearer  string `yaml:"bearer"`
	Cookies bool   `yaml:"cookies"`
}

// LoginCSRF names the cookie whose value is sent in a header.
type LoginCSRF struct {
	Cookie string `yaml:"cookie"`
	Header string `yaml:"header"`
}

// Credential references a secret without containing one.
type Credential struct {
	// Env names an environment variable.
	Env string `yaml:"env"`
	// File names a file whose contents are the credential.
	File string `yaml:"file"`
}

// LivenessProbe is a safe, authentication-requiring operation used to establish
// whether an identity still authenticates.
type LivenessProbe struct {
	Method string `yaml:"method"`
	// Path is resolved against target.baseURL and is subject to the scope
	// policy like every other request.
	Path string `yaml:"path"`
	// ExpectStatus lists statuses meaning the identity is still good. Empty
	// means any 2xx.
	ExpectStatus []int `yaml:"expectStatus"`
	// Self is a JSON pointer to the identity's own id in the response, used
	// in record creation bodies.
	Self string `yaml:"self"`
}

// Record declares a kind of record Sulayi creates as each identity, uses as
// that identity's owned resource, and deletes afterwards (ADR-0022).
type Record struct {
	// Type names the kind of record, e.g. device-token.
	Type string `yaml:"type"`
	// Create is the request that creates one.
	Create RecordCreate `yaml:"create"`
	// ID is a JSON pointer to the new record's id in the creation response.
	ID string `yaml:"id"`
	// Delete is the path of one record, with exactly one {param}: its id.
	Delete string `yaml:"delete"`
	// As lists the identities that each create one. Empty means every one.
	As []string `yaml:"as"`
}

// RecordCreate is a POST of a JSON object to a path on the target's origin.
type RecordCreate struct {
	Path string                 `yaml:"path"`
	Body map[string]RecordValue `yaml:"body"`
}

// RecordValue is one body field: a literal value, the creating identity's own
// id (self), or a value random per run. It can never reference a credential.
type RecordValue struct {
	Value  any  `yaml:"value"`
	Self   bool `yaml:"self"`
	Random bool `yaml:"random"`
}

// Resource is one concrete resource known to belong to an identity.
//
// A fixture is what makes a cross-owner test mean anything: without one, asking
// for /api/orders/{orderId} means inventing an identifier and reading a 404 that
// says nothing about authorization.
type Resource struct {
	// ID is a stable, short name used in the ledger and in reports.
	ID string `yaml:"id"`
	// Type is a logical label such as "order". Descriptive only.
	Type string `yaml:"type"`
	// Owner is the identity id that owns this resource.
	Owner string `yaml:"owner"`
	// CrossOwnerAccess is "denied" or "allowed". Required: whether non-owners
	// may reach this resource is a statement about the application that Sulayi
	// must not guess. Assuming every owned resource is private would
	// report every deliberately shared record as a broken access control.
	CrossOwnerAccess string `yaml:"crossOwnerAccess"`
	// Values fill an operation's declared parameters, keyed by parameter name.
	Values map[string]string `yaml:"values"`
	// Operations optionally narrows which operation ids this fixture applies to.
	Operations []string `yaml:"operations"`
	// NonOwners optionally narrows which identities probe this fixture. Empty
	// means every configured identity except the owner.
	NonOwners []string `yaml:"nonOwners"`
	// Mutation enables cross-owner write testing. Absent means read-only.
	Mutation *ResourceMutation `yaml:"mutation"`
	// Disposable declares this exact resource disposable test data. Under the
	// standard profile, state-changing requests are permitted only against the
	// exact requests bound from disposable fixtures.
	Disposable bool `yaml:"disposable"`
}

// ResourceMutation holds the explicit values a cross-owner write attempts.
//
// Deliberately not a payload language. A generic mutation DSL would need
// templating, generators and coercion, all pointed at somebody's real data, for
// no gain over naming the two fields you want to change.
type ResourceMutation struct {
	Values map[string]any `yaml:"values"`
}

// Adapters configures framework adapters.
//
// Adapters are opt-in and are never discovered from a target repository. A
// manifest sitting in a checkout must not be able to cause a program to run
// (ADR-0002).
type Adapters struct {
	// SourceRoot is the application source to inspect. Required when any
	// adapter is configured.
	SourceRoot string `yaml:"sourceRoot"`
	// Trust authorises adapters that execute the inspected application's own
	// code. "none" (the default) permits only adapters that do not.
	//
	// This is a separate decision from configuring an adapter because
	// framework-native introspection is not passive: asking Laravel to list its
	// routes boots the framework and runs every service provider, and importing
	// a NestJS module executes it. Neither should happen because somebody added
	// a line naming an executable.
	Trust string `yaml:"trust"`
	// Use lists the adapters to run.
	Use []AdapterUse `yaml:"use"`
}

// AdapterUse is one configured adapter.
type AdapterUse struct {
	// Name must match the name the adapter reports, so a document cannot be
	// attributed to an adapter that did not produce it.
	Name string `yaml:"name"`
	// Path is the adapter executable. It is executed directly with an explicit
	// argument vector and never through a shell.
	Path string `yaml:"path"`
	// Args are extra arguments passed after --source-root.
	Args []string `yaml:"args"`
	// TimeoutSeconds bounds this adapter. Zero uses the default.
	TimeoutSeconds int `yaml:"timeoutSeconds"`
	// PassEnv names environment variables to forward. The adapter's environment
	// is otherwise built from nothing: a CI environment holds cloud
	// credentials, registry tokens and this tool's own identity credentials,
	// and none of that belongs in a third-party binary run against an untrusted
	// repository.
	PassEnv []string `yaml:"passEnv"`
}

// Engines configures external scanning engines.
//
// Each engine is a named, known integration rather than a command an operator
// composes. There is deliberately no `command`, `args` or `env` here: those
// would make Sulayi a general process runner, and the argument-vector
// construction, minimal environment and profile gating that make an engine safe
// to run would all become optional.
type Engines struct {
	// SourceRoot is an application checkout, for engines that read code.
	SourceRoot string `yaml:"sourceRoot"`
	Nuclei     Engine `yaml:"nuclei"`
	ZAP        Engine `yaml:"zap"`
	SAST       Engine `yaml:"sast"`
}

// Engine is one external engine's settings.
type Engine struct {
	// Enabled turns the engine on. Engines are off by default: none runs
	// because it happens to be installed.
	Enabled bool `yaml:"enabled"`
	// Executable is an explicit path. Empty means look the engine's own binary
	// name up on PATH.
	Executable string `yaml:"executable"`
	// Templates or Rules is the corpus the engine runs. It must be a local
	// path: Sulayi ships none and fetches none, because a corpus that
	// changes between runs makes results incomparable and an unrecorded corpus
	// is an unrecorded dependency.
	Templates string `yaml:"templates"`
	Rules     string `yaml:"rules"`
	// Mode narrows what an engine may do, for engines that have modes. ZAP's
	// "active" mode sends attack payloads and requires the aggressive profile.
	Mode string `yaml:"mode"`
	// Severity optionally narrows which severities an engine reports.
	Severity []string `yaml:"severity"`
	// RateLimit bounds requests per second, for engines that send traffic.
	RateLimit int `yaml:"rateLimit"`
	// TimeoutSeconds bounds the run.
	TimeoutSeconds int `yaml:"timeoutSeconds"`
	// PassEnv names environment variables to forward. The engine's environment
	// is otherwise built from nothing, and this tool's identity credentials can
	// never be forwarded whatever is named here.
	PassEnv []string `yaml:"passEnv"`
	// AllowUnsignedTemplates lets Nuclei execute templates that carry no
	// signature.
	//
	// It exists because refusing them outright would rule out every template an
	// operator writes themselves, and defaults to false because a template is
	// executable security logic that runs against the operator's own target.
	// Turning it on is a statement that this directory is trusted, and the
	// provenance of every resulting observation records that nothing else
	// established it.
	AllowUnsignedTemplates bool `yaml:"allowUnsignedTemplates"`
}

// Discovery configures how the attack surface is learned.
type Discovery struct {
	// OpenAPIFile is a path to a specification on disk.
	OpenAPIFile string `yaml:"openAPIFile"`
	// OpenAPIURL is a specification served by the target.
	OpenAPIURL string `yaml:"openAPIURL"`
	// ProbeWellKnownPaths permits fetching the usual specification locations on
	// the target's own origin when neither of the above is set.
	ProbeWellKnownPaths *bool `yaml:"probeWellKnownPaths"`
	// Surface configures discovery of paths the specification does not
	// describe.
	Surface SurfaceDiscovery `yaml:"surface"`
	// Crawl is the bounded, same-origin, GET-only crawler that finds routes
	// without a specification.
	Crawl CrawlDiscovery `yaml:"crawl"`
	// Browser is Sulayi's headless browser, which finds a single-page
	// application's API from what its front end requests.
	Browser BrowserDiscovery `yaml:"browser"`
}

// BrowserDiscovery configures the headless browser. It is off unless enabled:
// it starts a local browser that runs the target's code, which an operator
// should choose rather than discover. It runs as the anonymous caller and as
// each signed-in identity, and every request a page makes is sent, or refused,
// by Sulayi's own client.
type BrowserDiscovery struct {
	Enabled bool `yaml:"enabled"`
	// Executable is the Chrome or Chromium to run. Empty means the first
	// standard installation found. Sulayi never downloads a browser.
	Executable string `yaml:"executable"`
	// MaxPages bounds the pages loaded per identity. Default 20.
	MaxPages int `yaml:"maxPages"`
	// MaxDepth bounds how many links from the root are followed. Default 3.
	MaxDepth int `yaml:"maxDepth"`
	// MaxRequests bounds the requests the browser's pages may make in all,
	// divided evenly among the identities it runs as. Default 300. They also
	// count against assessment.maxRequests.
	MaxRequests int `yaml:"maxRequests"`
}

// CrawlDiscovery configures the crawler. It runs as the anonymous caller and
// as each signed-in identity.
type CrawlDiscovery struct {
	// Enabled defaults to true: an application with no specification is
	// otherwise invisible.
	Enabled *bool `yaml:"enabled"`
	// MaxPages bounds the pages fetched per identity. Default 50.
	MaxPages int `yaml:"maxPages"`
	// MaxDepth bounds how many links from the root are followed. Default 3.
	MaxDepth int `yaml:"maxDepth"`
}

// Access is the operator's declared access policy: which routes require
// authentication and which are public. It is the oracle for routes no
// specification describes, and a statement of expected behaviour — never
// evidence. Public patterns are exceptions to protected ones.
type Access struct {
	Protected []string `yaml:"protected"`
	Public    []string `yaml:"public"`
	// Owned declares paths whose records belong to the identity that created
	// them, and the roles that may reach other identities' records by design.
	Owned []OwnedAccess `yaml:"owned"`
	// Roles declares paths only the roles it allows may call.
	Roles []RoleAccess `yaml:"roles"`
}

// OwnedAccess is one access.owned rule.
type OwnedAccess struct {
	Paths       []string `yaml:"paths"`
	ReachableBy []string `yaml:"reachableBy"`
}

// RoleAccess is one access.roles rule.
type RoleAccess struct {
	Paths []string `yaml:"paths"`
	Allow []string `yaml:"allow"`
}

// SurfaceDiscovery configures the discovery of undocumented surface.
//
// There is deliberately no depth, no seed list, no wordlist and no include
// pattern here. Each of those is a knob a crawler needs and this is not one: it
// makes a single non-recursive pass over artefacts the application publishes
// about itself. A configuration that could express "crawl three levels deep"
// would mean the code behind it could too.
type SurfaceDiscovery struct {
	// Enabled turns discovery on. It defaults to on, because the alternative is
	// a coverage ledger that silently measures only the surface the application
	// chose to document.
	Enabled *bool `yaml:"enabled"`
	// LinkHeaders, Robots, JavaScript and WellKnown enable individual sources.
	// Each defaults to on when discovery is enabled; they exist so an operator
	// whose target dislikes one of them can turn just that one off.
	LinkHeaders *bool `yaml:"linkHeaders"`
	Robots      *bool `yaml:"robots"`
	JavaScript  *bool `yaml:"javascript"`
	WellKnown   *bool `yaml:"wellKnown"`

	// MaxRequests, MaxScripts, MaxBytes and MaxCandidates bound what a target
	// can make discovery do. Zero means the built-in default.
	MaxRequests   int   `yaml:"maxRequests"`
	MaxScripts    int   `yaml:"maxScripts"`
	MaxBytes      int64 `yaml:"maxBytes"`
	MaxCandidates int   `yaml:"maxCandidates"`

	// AssessAdapterDiscovered permits assessing operations a framework adapter
	// found that the specification does not document.
	//
	// It is separate from the sources above and defaults to on, because it is
	// the one case where discovered surface is genuinely testable: the adapter
	// read the application's routing table, so the method is known and the
	// authentication expectation comes from the same source that would have
	// supplied it had the route been documented. Nothing is invented. It is
	// still a switch, because it means requests to routes the operator may not
	// have known were there.
	AssessAdapterDiscovered *bool `yaml:"assessAdapterDiscovered"`
}

// Outcome supplies application-specific signals for classifying responses.
//
// These come from the operator only. A hostile target that could define its own
// oracle could map "allowed" to "denied" and suppress every finding.
type Outcome struct {
	// ErrorCodePointer is a JSON pointer to a stable error-code field, e.g.
	// "/errorCode". Real applications frequently return 200 or 400 with a
	// machine-readable code that is far more reliable than the status.
	ErrorCodePointer string `yaml:"errorCodePointer"`
	// DeniedCodes map error-code values to a denial outcome.
	DeniedCodes []string `yaml:"deniedCodes"`
	// NotFoundCodes map error-code values to a not-found outcome.
	NotFoundCodes []string `yaml:"notFoundCodes"`
}

// Environment records how the assessed environment differs from production.
// These are facts stated by the operator, not a score.
type Environment struct {
	Name string `yaml:"name"`
	// Differences lists production-equivalence deviations, e.g.
	// "rateLimiting: relaxed".
	Differences []string `yaml:"differences"`
}

// Output controls where results are written.
type Output struct {
	// Dir is the run directory root.
	Dir string `yaml:"dir"`
}

// Default returns a configuration with safe defaults applied.
func Default() Config {
	probe := true
	excludeAuth := true
	return Config{
		APIVersion: CurrentAPIVersion,
		Assessment: Assessment{
			Profile:              string(model.ProfileStandard),
			MaxRequests:          DefaultMaxRequests,
			MaxDurationMinutes:   DefaultMaxDurationMinutes,
			Concurrency:          4,
			RequestsPerSecond:    10,
			TimeoutSeconds:       20,
			ExcludeAuthEndpoints: &excludeAuth,
		},
		Discovery: Discovery{ProbeWellKnownPaths: &probe},
		Policy: Policy{
			FailOnConfirmed: string(model.SeverityLow),
			FailOnSuspected: string(model.SeverityHigh),
		},
		Output: Output{Dir: ".sulayi"},
	}
}

// Load reads and validates a configuration file.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if info.Size() > MaxConfigBytes {
		return Config{}, fmt.Errorf("config: file is %d bytes, limit is %d", info.Size(), MaxConfigBytes)
	}
	return Parse(io.LimitReader(f, MaxConfigBytes+1), path)
}

// Parse decodes and validates configuration from a reader.
func Parse(r io.Reader, name string) (Config, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config: input exceeds %d bytes", MaxConfigBytes)
	}

	cfg := Default()
	// Strict decoding rejects unknown fields, so a typo becomes a loud error
	// rather than a silently ignored setting. ReferenceFiles and ReferenceDirs
	// are deliberately absent.
	dec := yaml.NewDecoder(strings.NewReader(string(raw)), yaml.Strict())
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: %s:\n%s", name, yaml.FormatError(err, false, true))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", name, err)
	}
	return cfg, nil
}

// Validate applies semantic rules that a schema cannot express.
func (c *Config) Validate() error {
	var problems []string

	if c.APIVersion == "" {
		c.APIVersion = CurrentAPIVersion
	}
	if c.APIVersion == legacyAPIVersion {
		problems = append(problems, fmt.Sprintf(
			"apiVersion %q is from before the project was renamed to Sulayi; set apiVersion: %s",
			c.APIVersion, CurrentAPIVersion))
	} else if c.APIVersion != CurrentAPIVersion {
		problems = append(problems, fmt.Sprintf(
			"apiVersion %q is not supported by this build (expected %q)", c.APIVersion, CurrentAPIVersion))
	}

	if c.Target.BaseURL == "" {
		problems = append(problems, "target.baseURL is required")
	} else if u, err := url.Parse(c.Target.BaseURL); err != nil {
		problems = append(problems, "target.baseURL is not a valid URL")
	} else if u.Scheme != "http" && u.Scheme != "https" {
		problems = append(problems, fmt.Sprintf("target.baseURL scheme %q is not supported (use http or https)", u.Scheme))
	} else if u.Host == "" {
		problems = append(problems, "target.baseURL must include a host")
	} else if u.User != nil {
		problems = append(problems, "target.baseURL must not embed credentials; put them in an identity instead")
	}

	profile := model.Profile(c.Assessment.Profile)
	if replacement, legacy := model.LegacyProfiles[c.Assessment.Profile]; legacy {
		problems = append(problems, fmt.Sprintf(
			"assessment.profile %q is a pre-Sulayi profile name; the closest is %q. Profiles are now "+
				"safe, standard (default) and aggressive, and they permit different things, so the "+
				"name is not translated automatically", c.Assessment.Profile, replacement))
	} else if !profile.Valid() {
		problems = append(problems, fmt.Sprintf(
			"assessment.profile %q is not one of safe, standard, aggressive", c.Assessment.Profile))
	} else if profile == model.ProfileAggressive && !c.Target.Disposable {
		problems = append(problems, "assessment.profile is aggressive but target.disposable is not true; "+
			"aggressive testing can change or destroy any data the target holds, so the target must be "+
			"declared an isolated, disposable environment")
	}
	if profile == model.ProfileAggressive {
		// Every origin aggressive testing may reach is named exactly. A wildcard
		// or an unstated scheme is a range of hosts, and nobody can have
		// declared a range of hosts disposable.
		for i, e := range c.Scope.Include {
			if e.Scheme == "" || strings.HasPrefix(e.Host, "*.") || len(e.Ports) > 1 {
				problems = append(problems, fmt.Sprintf("scope.include[%d] must name one exact origin "+
					"(an explicit scheme, no wildcard host and at most one port) under the aggressive profile", i))
			}
		}
	}
	if c.Assessment.LegacyAuthorizeIntrusive != nil {
		problems = append(problems, "assessment.authorizeIntrusive was removed: the aggressive profile is "+
			"authorized by target.disposable: true and a confirmation naming the target")
	}
	for i, pat := range c.Access.Protected {
		if err := access.Validate(pat); err != nil {
			problems = append(problems, fmt.Sprintf("access.protected[%d]: %v", i, err))
		}
	}
	for i, pat := range c.Access.Public {
		if err := access.Validate(pat); err != nil {
			problems = append(problems, fmt.Sprintf("access.public[%d]: %v", i, err))
		}
	}
	if p := c.Discovery.Crawl.MaxPages; p != 0 && (p < 1 || p > 1000) {
		problems = append(problems, "discovery.crawl.maxPages must be between 1 and 1000")
	}
	if d := c.Discovery.Crawl.MaxDepth; d != 0 && (d < 1 || d > 10) {
		problems = append(problems, "discovery.crawl.maxDepth must be between 1 and 10")
	}
	if p := c.Discovery.Browser.MaxPages; p != 0 && (p < 1 || p > 200) {
		problems = append(problems, "discovery.browser.maxPages must be between 1 and 200")
	}
	if d := c.Discovery.Browser.MaxDepth; d != 0 && (d < 1 || d > 10) {
		problems = append(problems, "discovery.browser.maxDepth must be between 1 and 10")
	}
	if n := c.Discovery.Browser.MaxRequests; n != 0 && (n < 1 || n > 5000) {
		problems = append(problems, "discovery.browser.maxRequests must be between 1 and 5000")
	}
	for i, id := range c.Assessment.StateChangingOperations {
		method, path, ok := strings.Cut(strings.TrimSpace(id), " ")
		if !ok || !httpMethodPattern.MatchString(method) || !strings.HasPrefix(strings.TrimSpace(path), "/") {
			problems = append(problems, fmt.Sprintf(
				"assessment.stateChangingOperations[%d] %q is not of the form \"METHOD /path\"", i, id))
		}
	}
	if c.Assessment.MaxRequests < 1 || c.Assessment.MaxRequests > MaxMaxRequests {
		problems = append(problems, fmt.Sprintf("assessment.maxRequests must be between 1 and %d", MaxMaxRequests))
	}
	if c.Assessment.MaxDurationMinutes < 1 || c.Assessment.MaxDurationMinutes > MaxMaxDurationMinutes {
		problems = append(problems, fmt.Sprintf(
			"assessment.maxDurationMinutes must be between 1 and %d", MaxMaxDurationMinutes))
	}

	if c.Assessment.Concurrency < 1 || c.Assessment.Concurrency > 64 {
		problems = append(problems, "assessment.concurrency must be between 1 and 64")
	}
	if c.Assessment.RequestsPerSecond <= 0 || c.Assessment.RequestsPerSecond > 1000 {
		problems = append(problems, "assessment.requestsPerSecond must be greater than 0 and at most 1000")
	}
	if c.Assessment.TimeoutSeconds < 1 || c.Assessment.TimeoutSeconds > 300 {
		problems = append(problems, "assessment.timeoutSeconds must be between 1 and 300")
	}

	if c.Discovery.OpenAPIFile != "" && c.Discovery.OpenAPIURL != "" {
		problems = append(problems, "discovery.openAPIFile and discovery.openAPIURL are mutually exclusive")
	}
	if c.Discovery.OpenAPIURL != "" {
		if u, err := url.Parse(c.Discovery.OpenAPIURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			problems = append(problems, "discovery.openAPIURL must be an http or https URL")
		}
	}

	if c.Outcome.ErrorCodePointer != "" && !strings.HasPrefix(c.Outcome.ErrorCodePointer, "/") {
		problems = append(problems, `outcome.errorCodePointer must be a JSON pointer beginning with "/"`)
	}

	for i, e := range c.Scope.Include {
		if e.Host == "" {
			problems = append(problems, fmt.Sprintf("scope.include[%d].host is required", i))
		}
		if e.Scheme != "" && e.Scheme != "http" && e.Scheme != "https" {
			problems = append(problems, fmt.Sprintf("scope.include[%d].scheme %q is not http or https", i, e.Scheme))
		}
		for _, p := range e.Ports {
			if p < 1 || p > 65535 {
				problems = append(problems, fmt.Sprintf("scope.include[%d] port %d is out of range", i, p))
			}
		}
	}

	for name, v := range map[string]string{
		"policy.failOnConfirmed": c.Policy.FailOnConfirmed,
		"policy.failOnSuspected": c.Policy.FailOnSuspected,
	} {
		if v != "" && !model.Severity(v).Valid() {
			problems = append(problems, fmt.Sprintf(
				"%s %q is not one of info, low, medium, high, critical (or empty to disable)", name, v))
		}
	}

	if c.Output.Dir == "" {
		problems = append(problems, "output.dir is required")
	}

	// Identity rules live in the identity package beside the types they
	// constrain, so that the validation a credential must pass cannot drift
	// away from the code that resolves it.
	problems = append(problems, identity.ValidateAll(c.IdentityModels())...)

	known := map[string]bool{}
	for _, i := range c.Identities {
		if i.ID != "" {
			known[i.ID] = true
		}
	}
	problems = append(problems, resource.ValidateAll(c.ResourceFixtures(), known)...)
	if _, err := c.AccessRules(); err != nil {
		problems = append(problems, err.Error())
	}
	// Under ownership or role rules, an identity's role decides whether it is
	// probed and what its access means. One without a role would be treated
	// as allowed nothing, so an administrator configured without one would
	// produce findings against access it legitimately has.
	if len(c.Access.Owned) > 0 || len(c.Access.Roles) > 0 {
		for i, id := range c.Identities {
			if id.Role == "" {
				problems = append(problems, fmt.Sprintf("identities[%d].role is required when access.owned "+
					"or access.roles is declared: the rules are stated per role", i))
			}
		}
	}
	types := map[string]int{}
	for i, r := range c.RecordRecipes() {
		path := fmt.Sprintf("records[%d]", i)
		problems = append(problems, r.Validate(path, known)...)
		if first, dup := types[r.Type]; dup && r.Type != "" {
			problems = append(problems, fmt.Sprintf("%s.type %q duplicates records[%d]", path, r.Type, first))
		}
		types[r.Type] = i
	}
	problems = append(problems, c.validateAdapters()...)
	problems = append(problems, c.validateEngines()...)

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  - "))
	}
	return nil
}

// IdentityModels maps the configured identities onto the identity package's
// types.
//
// The mapping is explicit rather than a shared struct because the two have
// different jobs: the config type is the YAML wire format and must keep its
// tags and its pointer-for-optional fields, while the identity type is the
// domain model and carries none.
func (c Config) IdentityModels() []identity.Identity {
	out := make([]identity.Identity, 0, len(c.Identities))
	for _, i := range c.Identities {
		id := identity.Identity{
			ID:    i.ID,
			Label: i.Label,
			Role:  i.Role,
			Auth: identity.Authentication{
				Scheme:      identity.Scheme(i.Authentication.Type),
				Header:      i.Authentication.Header,
				ValuePrefix: i.Authentication.ValuePrefix,
				Credential: identity.CredentialSource{
					Env:  i.Authentication.Credential.Env,
					File: i.Authentication.Credential.File,
				},
				Login: loginModel(i.Authentication.Login),
			},
		}
		if i.Liveness != nil {
			id.Live = identity.Liveness{
				Method:       i.Liveness.Method,
				Path:         i.Liveness.Path,
				ExpectStatus: i.Liveness.ExpectStatus,
				Self:         i.Liveness.Self,
			}
		}
		out = append(out, id)
	}
	return out
}

// validateAdapters checks the adapter configuration.
func (c Config) validateAdapters() []string {
	var problems []string
	if len(c.Adapters.Use) == 0 {
		if c.Adapters.SourceRoot != "" || c.Adapters.Trust != "" {
			problems = append(problems, "adapters.sourceRoot and adapters.trust have no effect "+
				"without adapters.use")
		}
		return problems
	}
	if c.Adapters.SourceRoot == "" {
		problems = append(problems, "adapters.sourceRoot is required when an adapter is configured; "+
			"an adapter must be told what to inspect rather than discovering it")
	}
	if t := c.Adapters.Trust; t != "" && !adapter.TrustMode(t).Valid() {
		problems = append(problems, fmt.Sprintf("adapters.trust %q is not one of none, %s",
			t, adapter.TrustExecuteTargetCode))
	}
	seen := map[string]int{}
	for i, a := range c.Adapters.Use {
		path := fmt.Sprintf("adapters.use[%d]", i)
		switch {
		case a.Name == "":
			problems = append(problems, path+".name is required")
		case !adapterNamePattern.MatchString(a.Name):
			problems = append(problems, fmt.Sprintf("%s.name %q must be lowercase letters, digits, "+
				"hyphen or underscore", path, a.Name))
		default:
			if first, dup := seen[a.Name]; dup {
				problems = append(problems, fmt.Sprintf("%s.name %q duplicates adapters.use[%d]",
					path, a.Name, first))
			}
			seen[a.Name] = i
		}
		if a.Path == "" {
			problems = append(problems, path+".path is required; an adapter is executed by explicit "+
				"path and is never searched for")
		}
		if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 900 {
			problems = append(problems, path+".timeoutSeconds must be between 0 and 900")
		}
		for j, e := range a.PassEnv {
			if !envPattern.MatchString(e) {
				problems = append(problems, fmt.Sprintf("%s.passEnv[%d] %q is not a valid environment "+
					"variable name", path, j, e))
			}
		}
	}
	return problems
}

// validateEngines checks the external engine configuration.
func (c Config) validateEngines() []string {
	var problems []string
	named := map[string]Engine{
		"nuclei": c.Engines.Nuclei, "zap": c.Engines.ZAP, "sast": c.Engines.SAST,
	}
	for _, name := range []string{"nuclei", "sast", "zap"} {
		e := named[name]
		path := "engines." + name
		if !e.Enabled {
			continue
		}
		if e.TimeoutSeconds < 0 || e.TimeoutSeconds > 7200 {
			problems = append(problems, path+".timeoutSeconds must be between 0 and 7200")
		}
		if e.RateLimit < 0 || e.RateLimit > 1000 {
			problems = append(problems, path+".rateLimit must be between 0 and 1000")
		}
		for i, v := range e.PassEnv {
			if !envPattern.MatchString(v) {
				problems = append(problems, fmt.Sprintf("%s.passEnv[%d] %q is not a valid "+
					"environment variable name", path, i, v))
			}
		}
		for i, v := range e.Severity {
			if !engineSeverityPattern.MatchString(v) {
				problems = append(problems, fmt.Sprintf("%s.severity[%d] %q is not a plain "+
					"severity name", path, i, v))
			}
		}
		switch name {
		case "nuclei":
			if e.Templates == "" {
				problems = append(problems, path+".templates is required when nuclei is enabled; "+
					"Sulayi will not let it fetch templates for itself, because a scan "+
					"against a corpus that changed overnight is not reproducible")
			}
		case "sast":
			if e.Rules == "" {
				problems = append(problems, path+".rules is required when sast is enabled; Sulayi "+
					"ships no rules and will not pull them from a registry")
			}
			if c.Engines.SourceRoot == "" {
				problems = append(problems, "engines.sourceRoot is required when sast is enabled; "+
					"a static analyser needs an application checkout to read")
			}
		case "zap":
			if e.Mode != "" && e.Mode != "passive" && e.Mode != "active" {
				problems = append(problems, path+`.mode must be "passive" or "active"`)
			}
			if e.Mode == "active" && c.Profile() != model.ProfileAggressive {
				problems = append(problems, "engines.zap.mode is active, which sends attack "+
					"payloads and requires assessment.profile: aggressive")
			}
		}
	}
	return problems
}

// EngineSettings maps a configured engine onto the scanner package's settings.
func (e Engine) EngineSettings() scanner.Settings {
	s := scanner.Settings{
		Enabled:        e.Enabled,
		Executable:     e.Executable,
		TimeoutSeconds: e.TimeoutSeconds,
		PassEnv:        e.PassEnv,
		Severity:       e.Severity,
		Extra:          map[string]string{},
	}
	// One of the two corpus fields, whichever the engine uses.
	s.RuleSource = e.Templates
	if s.RuleSource == "" {
		s.RuleSource = e.Rules
	}
	if e.Mode != "" {
		s.Extra["mode"] = e.Mode
	}
	if e.RateLimit > 0 {
		s.Extra["rateLimit"] = strconv.Itoa(e.RateLimit)
	}
	if e.AllowUnsignedTemplates {
		s.Extra["allowUnsignedTemplates"] = "true"
	}
	return s
}

// AdapterTrust returns the effective trust mode.
func (c Config) AdapterTrust() adapter.TrustMode {
	if c.Adapters.Trust == "" {
		return adapter.TrustNone
	}
	return adapter.TrustMode(c.Adapters.Trust)
}

// AdapterSpecs maps the configured adapters onto execution specs.
func (c Config) AdapterSpecs() []adapter.Spec {
	out := make([]adapter.Spec, 0, len(c.Adapters.Use))
	for _, a := range c.Adapters.Use {
		out = append(out, adapter.Spec{
			Name:       a.Name,
			Path:       a.Path,
			Args:       a.Args,
			SourceRoot: c.Adapters.SourceRoot,
			Timeout:    time.Duration(a.TimeoutSeconds) * time.Second,
			PassEnv:    a.PassEnv,
		})
	}
	return out
}

// CredentialEnvNames returns the environment variables holding this tool's own
// identity credentials, so they can be kept out of every adapter.
func (c Config) CredentialEnvNames() []string {
	var out []string
	for _, i := range c.IdentityModels() {
		out = append(out, i.CredentialEnvNames()...)
	}
	return out
}

// loginModel maps a configured login flow onto the identity package's types.
// Body fields are ordered by name so the request is the same on every run.
func loginModel(l *LoginFlow) *identity.Login {
	if l == nil {
		return nil
	}
	m := &identity.Login{
		Method:  l.Method,
		Path:    l.Path,
		Form:    l.Form,
		Session: identity.Session{Bearer: l.Session.Bearer, Cookies: l.Session.Cookies},
	}
	names := make([]string, 0, len(l.Body))
	for n := range l.Body {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := l.Body[n]
		m.Fields = append(m.Fields, identity.LoginField{
			Name:          n,
			Source:        identity.CredentialSource{Env: f.Env, File: f.File},
			FromPreflight: f.FromPreflight,
		})
	}
	if l.Preflight != nil {
		m.Preflight = &identity.Preflight{Method: l.Preflight.Method, Path: l.Preflight.Path}
	}
	if l.CSRF != nil {
		m.CSRF = &identity.CSRF{Cookie: l.CSRF.Cookie, Header: l.CSRF.Header}
	}
	return m
}

// ResourceFixtures maps the configured resources onto the resource package's
// types.
func (c Config) ResourceFixtures() []resource.Fixture {
	out := make([]resource.Fixture, 0, len(c.Resources))
	for _, r := range c.Resources {
		f := resource.Fixture{
			ID:               r.ID,
			Type:             r.Type,
			Owner:            r.Owner,
			CrossOwnerAccess: resource.Expectation(r.CrossOwnerAccess),
			Values:           r.Values,
			Operations:       r.Operations,
			NonOwners:        r.NonOwners,
			Disposable:       r.Disposable,
			// Everything configurable is, by definition, configured. Records
			// Sulayi creates (records[]) carry ProvenanceAPICreated.
			Provenance: resource.ProvenanceConfigured,
		}
		if r.Mutation != nil {
			f.Mutation = &resource.Mutation{Values: r.Mutation.Values}
		}
		out = append(out, f)
	}
	return out
}

// Profile returns the validated profile.
func (c Config) Profile() model.Profile { return model.Profile(c.Assessment.Profile) }

// ShouldExcludeAuthEndpoints reports the effective setting.
func (c Config) ShouldExcludeAuthEndpoints() bool {
	if c.Assessment.ExcludeAuthEndpoints == nil {
		return true
	}
	return *c.Assessment.ExcludeAuthEndpoints
}

// ShouldProbeWellKnownPaths reports the effective setting.
// SurfaceDiscoveryEnabled reports whether undocumented-surface discovery runs.
func (c Config) SurfaceDiscoveryEnabled() bool {
	return boolOr(c.Discovery.Surface.Enabled, true)
}

// AssessAdapterDiscovered reports whether adapter-found operations that the
// specification omits are assessed.
func (c Config) AssessAdapterDiscovered() bool {
	return boolOr(c.Discovery.Surface.AssessAdapterDiscovered, true)
}

// DiscoverySources maps the configuration onto the discovery package's source
// selection.
func (c Config) DiscoverySources() discovery.Sources {
	if !c.SurfaceDiscoveryEnabled() {
		return discovery.Sources{}
	}
	s := c.Discovery.Surface
	return discovery.Sources{
		LinkHeaders: boolOr(s.LinkHeaders, true),
		Robots:      boolOr(s.Robots, true),
		JavaScript:  boolOr(s.JavaScript, true),
		WellKnown:   boolOr(s.WellKnown, true),
	}
}

// DiscoveryLimits maps the configuration onto the discovery package's budgets.
// Unset fields keep the built-in defaults rather than becoming zero, which would
// disable discovery by accident.
func (c Config) DiscoveryLimits() discovery.Limits {
	s := c.Discovery.Surface
	l := discovery.DefaultLimits()
	if s.MaxRequests > 0 {
		l.MaxRequests = s.MaxRequests
	}
	if s.MaxScripts > 0 {
		l.MaxScripts = s.MaxScripts
	}
	if s.MaxBytes > 0 {
		l.MaxBytes = s.MaxBytes
	}
	if s.MaxCandidates > 0 {
		l.MaxCandidates = s.MaxCandidates
	}
	return l
}

// boolOr resolves an optional boolean against its default.
func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func (c Config) ShouldProbeWellKnownPaths() bool {
	if c.Discovery.ProbeWellKnownPaths == nil {
		return true
	}
	return *c.Discovery.ProbeWellKnownPaths
}

// ScopePolicy builds the network authorization boundary.
//
// The target's own origin is always included: the URL the operator typed is the
// authorization they gave. Everything else must be granted explicitly.
func (c Config) ScopePolicy() (*scope.Policy, error) {
	u, err := url.Parse(c.Target.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("config: target.baseURL: %w", err)
	}
	entries := []scope.Entry{targetEntry(u)}
	for _, e := range c.Scope.Include {
		entries = append(entries, scope.Entry{
			Scheme:     e.Scheme,
			Host:       e.Host,
			Ports:      e.Ports,
			PathPrefix: e.PathPrefix,
		})
	}
	return scope.New(entries, c.Scope.AllowPrivateAddresses)
}

// targetEntry grants exactly the target's scheme, host and port.
func targetEntry(u *url.URL) scope.Entry {
	e := scope.Entry{Scheme: u.Scheme, Host: u.Hostname()}
	if p := u.Port(); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			e.Ports = []int{n}
		}
	}
	return e
}

// CrawlEnabled reports whether the crawler runs. It defaults to on: without
// it, an application with no specification has no surface at all.
func (c Config) CrawlEnabled() bool {
	return c.Discovery.Crawl.Enabled == nil || *c.Discovery.Crawl.Enabled
}

// CrawlLimits returns the crawler's page and depth limits.
func (c Config) CrawlLimits() (pages, depth int) {
	pages, depth = c.Discovery.Crawl.MaxPages, c.Discovery.Crawl.MaxDepth
	if pages == 0 {
		pages = discovery.DefaultCrawlPages
	}
	if depth == 0 {
		depth = discovery.DefaultCrawlDepth
	}
	return pages, depth
}

// BrowserLimits returns the browser's page, depth and request limits.
func (c Config) BrowserLimits() (pages, depth, requests int) {
	b := c.Discovery.Browser
	pages, depth, requests = b.MaxPages, b.MaxDepth, b.MaxRequests
	if pages == 0 {
		pages = discovery.DefaultBrowserPages
	}
	if depth == 0 {
		depth = discovery.DefaultBrowserDepth
	}
	if requests == 0 {
		requests = discovery.DefaultBrowserMaxRequests
	}
	return pages, depth, requests
}

// AccessPolicy compiles the declared access policy. Validate has already
// checked every pattern.
func (c Config) AccessPolicy() (*access.Policy, error) {
	return access.New(c.Access.Protected, c.Access.Public)
}

// AccessRules compiles access.owned and access.roles.
func (c Config) AccessRules() (*access.Rules, error) {
	owned := make([]access.OwnedSpec, 0, len(c.Access.Owned))
	for _, o := range c.Access.Owned {
		owned = append(owned, access.OwnedSpec{Paths: o.Paths, ReachableBy: o.ReachableBy})
	}
	roles := make([]access.RoleSpec, 0, len(c.Access.Roles))
	for _, r := range c.Access.Roles {
		roles = append(roles, access.RoleSpec{Paths: r.Paths, Allow: r.Allow})
	}
	return access.NewRules(owned, roles)
}

// RecordRecipes maps records[] onto creation recipes.
func (c Config) RecordRecipes() []record.Recipe {
	out := make([]record.Recipe, 0, len(c.Records))
	for _, r := range c.Records {
		body := make(map[string]record.Value, len(r.Create.Body))
		for k, v := range r.Create.Body {
			body[k] = record.Value{Literal: v.Value, Self: v.Self, Random: v.Random}
		}
		out = append(out, record.Recipe{
			Type: r.Type, CreatePath: r.Create.Path, Body: body,
			IDPointer: r.ID, DeletePath: r.Delete, As: r.As,
		})
	}
	return out
}
