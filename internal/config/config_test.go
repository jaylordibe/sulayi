package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, yaml string) (Config, error) {
	t.Helper()
	return Parse(strings.NewReader(yaml), "test.yaml")
}

const minimal = `
apiVersion: sulayi/v1alpha1
target:
  baseURL: http://localhost:3000
`

func TestMinimalConfigLoadsWithDefaults(t *testing.T) {
	cfg, err := parse(t, minimal)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Assessment.Profile != "standard" {
		t.Errorf("default profile = %q, want standard", cfg.Assessment.Profile)
	}
	if cfg.Assessment.MaxRequests != DefaultMaxRequests || DefaultMaxRequests != 1000 {
		t.Errorf("default maxRequests = %d, want 1000", cfg.Assessment.MaxRequests)
	}
	if cfg.Assessment.MaxDurationMinutes != DefaultMaxDurationMinutes || DefaultMaxDurationMinutes != 30 {
		t.Errorf("default maxDurationMinutes = %d, want 30", cfg.Assessment.MaxDurationMinutes)
	}
	if !cfg.ShouldExcludeAuthEndpoints() {
		t.Error("authentication endpoints must be excluded by default")
	}
	if cfg.Output.Dir != ".sulayi" {
		t.Errorf("default output dir = %q", cfg.Output.Dir)
	}
}

// A typo must be a loud error, not a silently ignored setting.
func TestUnknownFieldsAreRejected(t *testing.T) {
	_, err := parse(t, minimal+"\nassessment:\n  profil: discovery\n")
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	if !strings.Contains(err.Error(), "profil") {
		t.Errorf("error does not name the offending field: %v", err)
	}
}

// The intrusive profile can change or destroy data, so selecting it is not by
// itself authorization to use it.
func TestAggressiveProfileRequiresDisposableTarget(t *testing.T) {
	_, err := parse(t, minimal+"\nassessment:\n  profile: aggressive\n")
	if err == nil {
		t.Fatal("aggressive profile accepted against a target not declared disposable")
	}
	if !strings.Contains(err.Error(), "target.disposable") {
		t.Errorf("error does not explain what is required: %v", err)
	}

	cfg, err := parse(t, "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://localhost:3000\n"+
		"  disposable: true\nassessment:\n  profile: aggressive\n")
	if err != nil {
		t.Fatalf("aggressive profile against a disposable target rejected: %v", err)
	}
	if cfg.Profile() != "aggressive" {
		t.Errorf("profile = %q", cfg.Profile())
	}
}

func TestInvalidProfileIsRejected(t *testing.T) {
	_, err := parse(t, minimal+"\nassessment:\n  profile: reckless\n")
	if err == nil || !strings.Contains(err.Error(), "safe, standard, aggressive") {
		t.Fatalf("error = %v, want the valid profiles listed", err)
	}
}

// A pre-Sulayi profile name is refused, never translated: the profiles permit
// different things, so mapping one silently would change what a run may do.
func TestLegacyProfileNamesAreRefused(t *testing.T) {
	for legacy, closest := range map[string]string{
		"discovery": "safe", "verification": "safe", "intrusive": "aggressive",
	} {
		_, err := parse(t, minimal+"\nassessment:\n  profile: "+legacy+"\n")
		if err == nil || !strings.Contains(err.Error(), "pre-Sulayi") || !strings.Contains(err.Error(), closest) {
			t.Errorf("profile %q: error = %v, want a migration message naming %q", legacy, err, closest)
		}
	}
}

func TestLegacyAuthorizeIntrusiveIsRefused(t *testing.T) {
	for _, v := range []string{"true", "false"} {
		_, err := parse(t, minimal+"\nassessment:\n  authorizeIntrusive: "+v+"\n")
		if err == nil || !strings.Contains(err.Error(), "target.disposable") {
			t.Errorf("authorizeIntrusive: %s: error = %v, want a migration message", v, err)
		}
	}
}

func TestBudgetBoundsAreEnforced(t *testing.T) {
	for _, body := range []string{
		"maxRequests: 0", "maxRequests: 100001", "maxDurationMinutes: 0", "maxDurationMinutes: 1441",
	} {
		if _, err := parse(t, minimal+"\nassessment:\n  "+body+"\n"); err == nil {
			t.Errorf("%s was accepted", body)
		}
	}
}

func TestTargetValidation(t *testing.T) {
	cases := map[string]string{
		"missing":            "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: \"\"\n",
		"unsupported scheme": "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: file:///etc/passwd\n",
		"no host":            "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://\n",
		"embedded creds":     "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://u:p@x.test\n",
	}
	for name, doc := range cases {
		if _, err := parse(t, doc); err == nil {
			t.Errorf("%s: accepted an invalid target", name)
		}
	}
}

func TestUnsupportedAPIVersionIsRejected(t *testing.T) {
	_, err := parse(t, "apiVersion: sulayi/v99\ntarget:\n  baseURL: http://x.test\n")
	if err == nil || !strings.Contains(err.Error(), "apiVersion") {
		t.Fatalf("error = %v, want an apiVersion rejection", err)
	}
}

// A configuration from before the rename gets a migration message, not the
// generic "unsupported" one, so the fix is obvious.
func TestLegacyAPIVersionNamesTheMigration(t *testing.T) {
	_, err := parse(t, "apiVersion: appsec/v1alpha1\ntarget:\n  baseURL: http://x.test\n")
	if err == nil || !strings.Contains(err.Error(), "renamed to Sulayi") ||
		!strings.Contains(err.Error(), CurrentAPIVersion) {
		t.Fatalf("error = %v, want a rename migration message naming %s", err, CurrentAPIVersion)
	}
}

func TestPacingBoundsAreEnforced(t *testing.T) {
	cases := []string{
		"\nassessment:\n  concurrency: 0\n",
		"\nassessment:\n  concurrency: 999\n",
		"\nassessment:\n  requestsPerSecond: 0\n",
		"\nassessment:\n  timeoutSeconds: 0\n",
		"\nassessment:\n  timeoutSeconds: 100000\n",
	}
	for _, c := range cases {
		if _, err := parse(t, minimal+c); err == nil {
			t.Errorf("accepted out-of-range pacing: %s", c)
		}
	}
}

func TestMutuallyExclusiveDiscoverySources(t *testing.T) {
	_, err := parse(t, minimal+"\ndiscovery:\n  openAPIFile: ./a.json\n  openAPIURL: http://x.test/s.json\n")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want a mutual-exclusion error", err)
	}
}

func TestErrorCodePointerMustBeAJSONPointer(t *testing.T) {
	if _, err := parse(t, minimal+"\noutcome:\n  errorCodePointer: errorCode\n"); err == nil {
		t.Fatal("accepted a pointer without a leading slash")
	}
	if _, err := parse(t, minimal+"\noutcome:\n  errorCodePointer: /errorCode\n"); err != nil {
		t.Fatalf("rejected a valid pointer: %v", err)
	}
}

// The target's own origin is always in scope; nothing else is.
func TestScopePolicyAlwaysIncludesTheTarget(t *testing.T) {
	cfg, err := parse(t, "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://localhost:3000\n"+
		"scope:\n  allowPrivateAddresses: true\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pol, err := cfg.ScopePolicy()
	if err != nil {
		t.Fatalf("ScopePolicy: %v", err)
	}
	if !pol.CheckURL("http://localhost:3000/api/x").Allowed {
		t.Error("the target's own origin is not in scope")
	}
	if pol.CheckURL("http://localhost:9200/").Allowed {
		t.Error("a different port on the target host is in scope")
	}
	if pol.CheckURL("http://evil.test/").Allowed {
		t.Error("an unrelated host is in scope")
	}
}

// Alias expansion is a classic exponential-blowup denial of service.
func TestOversizedInputIsRefused(t *testing.T) {
	huge := strings.Repeat("#", MaxConfigBytes+10)
	if _, err := Parse(strings.NewReader(huge), "big.yaml"); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

func TestMalformedYAMLProducesAReadableError(t *testing.T) {
	_, err := parse(t, "target:\n  baseURL: [unclosed\n")
	if err == nil {
		t.Fatal("malformed YAML accepted")
	}
	if !strings.Contains(err.Error(), "test.yaml") {
		t.Errorf("error does not name the file: %v", err)
	}
}

// Identity configuration is where a credential could most easily be committed
// by accident, so every rejection here is a guard rail rather than a nicety.
func TestIdentityConfigurationIsValidated(t *testing.T) {
	const head = "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://localhost:3000\n"
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "valid bearer identity",
			yaml: head + `identities:
  - id: admin
    label: Administrator
    authentication:
      type: bearer
      credential:
        env: SULAYI_ADMIN_TOKEN
`,
		},
		{
			name: "valid api key identity with a canary",
			yaml: head + `identities:
  - id: service
    authentication:
      type: apiKey
      header: X-API-Key
      valuePrefix: "Token "
      credential:
        file: /run/secrets/key
    liveness:
      method: GET
      path: /api/me
      expectStatus: [200]
`,
		},
		{
			name: "duplicate ids",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
  - id: admin
    authentication:
      type: bearer
      credential: {env: B_TOKEN}
`,
			wantErr: "duplicates",
		},
		{
			name: "reserved id",
			yaml: head + `identities:
  - id: anonymous
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
`,
			wantErr: "reserved",
		},
		{
			name: "unsupported scheme",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: oauth2
      credential: {env: A_TOKEN}
`,
			wantErr: "not one of bearer, apiKey",
		},
		{
			name: "api key without a header",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: apiKey
      credential: {env: A_TOKEN}
`,
			wantErr: "header is required",
		},
		{
			name: "header name with a colon",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: apiKey
      header: "X-Key: injected"
      credential: {env: A_TOKEN}
`,
			wantErr: "not a valid HTTP header name",
		},
		{
			name: "no credential source",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: bearer
      credential: {}
`,
			wantErr: "one of env or file is required",
		},
		{
			name: "both credential sources",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: bearer
      credential: {env: A_TOKEN, file: /tmp/t}
`,
			wantErr: "exactly one of env or file",
		},
		{
			name: "a literal credential value is not a field at all",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: bearer
      token: "supersecret"
      credential: {env: A_TOKEN}
`,
			wantErr: "unknown field",
		},
		{
			name: "unsafe canary method",
			yaml: head + `identities:
  - id: admin
    authentication:
      type: bearer
      credential: {env: A_TOKEN}
    liveness:
      method: DELETE
      path: /api/me
`,
			wantErr: "must be a safe method",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.yaml)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid configuration rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// The configuration schema has no field that accepts a credential value. This
// asserts the absence rather than trusting it, because "there is no way to write
// a secret here" is the property the whole credential design rests on.
func TestConfigurationCannotCarryACredentialValue(t *testing.T) {
	cfg, err := parse(t, "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: http://localhost:3000\n"+
		`identities:
  - id: admin
    authentication:
      type: bearer
      credential:
        env: SULAYI_ADMIN_TOKEN
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ids := cfg.IdentityModels()
	if len(ids) != 1 {
		t.Fatalf("identities = %d, want 1", len(ids))
	}
	if ids[0].Auth.Credential.Env != "SULAYI_ADMIN_TOKEN" {
		t.Errorf("credential reference lost in mapping: %+v", ids[0].Auth.Credential)
	}
	// The mapped identity carries a reference, never material.
	rendered := fmt.Sprintf("%+v", ids[0])
	if strings.Contains(rendered, "supersecret") {
		t.Error("an identity rendered credential material")
	}
}

// Resource fixtures address somebody's real data, so every reference and every
// value is checked before a request can be built from it.
func TestResourceConfigurationIsValidated(t *testing.T) {
	const head = "apiVersion: sulayi/v1alpha1\n" +
		"target:\n  baseURL: http://localhost:3000\n" +
		"identities:\n" +
		"  - id: user-a\n    authentication:\n      type: bearer\n      credential: {env: A_TOKEN}\n" +
		"  - id: user-b\n    authentication:\n      type: bearer\n      credential: {env: B_TOKEN}\n"

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "valid fixture",
			yaml: head + `resources:
  - id: order-a
    type: order
    owner: user-a
    crossOwnerAccess: denied
    values:
      orderId: "abc123"
`,
		},
		{
			name: "valid shared fixture with mutation",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: allowed
    values: {orderId: "abc123"}
    operations: ["GET /api/orders/{orderId}"]
    nonOwners: [user-b]
    mutation:
      values:
        status: "sulayi-marker"
`,
		},
		{
			name: "unknown owner",
			yaml: head + `resources:
  - id: order-a
    owner: ghost
    crossOwnerAccess: denied
    values: {orderId: "abc123"}
`,
			wantErr: "is not a configured identity",
		},
		{
			name: "missing expectation",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    values: {orderId: "abc123"}
`,
			wantErr: "crossOwnerAccess",
		},
		{
			name: "duplicate fixture ids",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
  - id: order-a
    owner: user-b
    crossOwnerAccess: denied
    values: {orderId: "2"}
`,
			wantErr: "duplicates",
		},
		{
			name: "traversal in a value",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "../../admin"}
`,
			wantErr: "path separator",
		},
		{
			name: "empty values",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {}
`,
			wantErr: "values is required",
		},
		{
			name: "owner listed as its own non-owner",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
    nonOwners: [user-a]
`,
			wantErr: "cannot be its own non-owner",
		},
		{
			name: "mutation with no values",
			yaml: head + `resources:
  - id: order-a
    owner: user-a
    crossOwnerAccess: denied
    values: {orderId: "1"}
    mutation: {}
`,
			wantErr: "mutation.values is required",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.yaml)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("valid configuration rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// Everything configurable is configured, by definition. Provenance must say so
// rather than being left blank, because "how do we know who owns this" is a
// question the report has to answer.
func TestConfiguredFixturesRecordTheirProvenance(t *testing.T) {
	cfg, err := parse(t, "apiVersion: sulayi/v1alpha1\n"+
		"target:\n  baseURL: http://localhost:3000\n"+
		"identities:\n  - id: user-a\n    authentication:\n      type: bearer\n"+
		"      credential: {env: A_TOKEN}\n"+
		"resources:\n  - id: order-a\n    owner: user-a\n    crossOwnerAccess: denied\n"+
		"    values: {orderId: \"1\"}\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fx := cfg.ResourceFixtures()
	if len(fx) != 1 {
		t.Fatalf("fixtures = %d, want 1", len(fx))
	}
	if fx[0].Provenance != "configured" {
		t.Errorf("provenance = %q, want configured", fx[0].Provenance)
	}
}

// A malformed state-changing operation is a configuration error, caught before
// anything runs, not a run that silently treats the operation as read-only.
func TestStateChangingOperationsMustNameAMethodAndPath(t *testing.T) {
	for _, bad := range []string{`"logout"`, `"GET logout"`, `"/logout"`, `""`} {
		if _, err := parse(t, minimal+"\nassessment:\n  stateChangingOperations: ["+bad+"]\n"); err == nil {
			t.Errorf("stateChangingOperations [%s] was accepted", bad)
		}
	}
	if _, err := parse(t, minimal+"\nassessment:\n  stateChangingOperations: [\"GET /logout\", \"get /orders/{id}/cancel\"]\n"); err != nil {
		t.Errorf("valid state-changing operations rejected: %v", err)
	}
}

// The reference configurations are run by the reference workflow against the
// real starters; one that stopped parsing would fail there, weekly, instead of
// here.
func TestReferenceConfigurationsAreValid(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "evals", "reference", "*.sulayi.yaml"))
	mvp, _ := filepath.Glob(filepath.Join("..", "..", "evals", "mvp", "*.sulayi.yaml"))
	files = append(files, mvp...)
	if len(files) == 0 {
		t.Fatal("no reference configuration found")
	}
	for _, f := range files {
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}
