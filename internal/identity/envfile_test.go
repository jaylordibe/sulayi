package identity

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, ".env.sulayi.local")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseEnvGrammar(t *testing.T) {
	got, err := parseEnv(strings.Join([]string{
		"# a comment",
		"",
		"PLAIN=value",
		"export EXPORTED=yes",
		"SPACED = padded  ",
		"INLINE=kept # dropped",
		"HASH=a#b",
		`DOUBLE="with \"quotes\" and \n newline"`,
		`SINGLE='literal $HOME \n'`,
		`MULTI="line one`,
		`line two"`,
		"EMPTY=",
		"NOEXPAND=$PLAIN",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"PLAIN":    "value",
		"EXPORTED": "yes",
		"SPACED":   "padded",
		"INLINE":   "kept",
		"HASH":     "a#b",
		"DOUBLE":   "with \"quotes\" and \n newline",
		"SINGLE":   `literal $HOME \n`,
		"MULTI":    "line one\nline two",
		"EMPTY":    "",
		"NOEXPAND": "$PLAIN",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// A malformed file is reported by line, and the report never contains what the
// line held: a credentials file's errors are printed to a terminal and a CI log.
func TestParseErrorsNeverEchoContent(t *testing.T) {
	const secret = "hunter2-SECRET-value"
	for _, body := range []string{
		"not an assignment " + secret,
		"9BAD=" + secret,
		`OPEN="` + secret,
		`Q="` + secret + `" trailing`,
		"S='" + secret,
	} {
		_, err := parseEnv("OK=1\n" + body)
		if err == nil {
			t.Errorf("%q parsed", body)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error repeats the file's content: %q", err)
		}
		if !strings.Contains(err.Error(), "line 2") {
			t.Errorf("the error does not name the line: %q", err)
		}
	}
}

// Only names the configuration references are kept. An application's own .env
// passed by mistake lends Sulayi nothing it does not use.
func TestOnlyReferencedNamesAreLoaded(t *testing.T) {
	p := writeEnv(t, t.TempDir(), "SULAYI_ALICE_TOKEN=a\nDB_PASSWORD=prod\nJWT_SECRET=sign\n")
	ef, err := LoadEnvFile(p, []string{"SULAYI_ALICE_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := ef.Lookup("SULAYI_ALICE_TOKEN"); !ok || v != "a" {
		t.Errorf("referenced name: %q, %v", v, ok)
	}
	for _, n := range []string{"DB_PASSWORD", "JWT_SECRET"} {
		if ef.Has(n) {
			t.Errorf("%s was loaded although nothing references it", n)
		}
	}
	if ef.Ignored != 2 {
		t.Errorf("ignored = %d, want 2", ef.Ignored)
	}
}

// File values never enter the process environment, so no child process can
// inherit them.
func TestFileValuesNeverEnterTheProcessEnvironment(t *testing.T) {
	const name = "SULAYI_TEST_FILE_ONLY_7d1c"
	p := writeEnv(t, t.TempDir(), name+"=from-file\n")
	ef, err := LoadEnvFile(p, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ef.Lookup(name); !ok {
		t.Fatal("the file value is not resolvable")
	}
	if _, ok := os.LookupEnv(name); ok {
		t.Fatal("a file value was placed in the process environment")
	}
	for _, kv := range os.Environ() {
		if strings.Contains(kv, "from-file") {
			t.Fatal("a file value appears in os.Environ")
		}
	}
}

// A variable set in the shell overrides the file, as every dotenv loader does.
func TestProcessEnvironmentOverridesTheFile(t *testing.T) {
	const name = "SULAYI_TEST_OVERRIDE_3e9a"
	t.Setenv(name, "from-shell")
	p := writeEnv(t, t.TempDir(), name+"=from-file\n")
	ef, err := LoadEnvFile(p, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ef.Lookup(name); v != "from-shell" {
		t.Errorf("lookup = %q, want the shell's value", v)
	}
}

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.test"},
		{"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// A file git tracks is already in the repository's history. It is refused,
// whatever it holds.
func TestTrackedCredentialsFileIsRefused(t *testing.T) {
	dir := gitRepo(t)
	p := writeEnv(t, dir, "SULAYI_ALICE_TOKEN=a\n")
	for _, args := range [][]string{{"add", "-f", filepath.Base(p)}, {"commit", "-q", "-m", "oops"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	_, err := LoadEnvFile(p, []string{"SULAYI_ALICE_TOKEN"})
	if err == nil || !strings.Contains(err.Error(), "tracked by git") {
		t.Fatalf("err = %v, want a refusal because git tracks the file", err)
	}
}

// An untracked file that no ignore rule covers is one `git add .` from being
// committed, which is worth saying.
func TestUnignoredCredentialsFileIsWarnedAbout(t *testing.T) {
	dir := gitRepo(t)
	p := writeEnv(t, dir, "SULAYI_ALICE_TOKEN=a\n")
	ef, err := LoadEnvFile(p, []string{"SULAYI_ALICE_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ef.Warnings, " "), "no ignore rule covers it") {
		t.Errorf("warnings = %v, want a warning that the file is not ignored", ef.Warnings)
	}

	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env.*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ef, err = LoadEnvFile(p, []string{"SULAYI_ALICE_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(ef.Warnings, " "), "ignore rule") {
		t.Errorf("an ignored file was warned about: %v", ef.Warnings)
	}
}

func TestLooselyPermissionedCredentialsFileIsWarnedAbout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not enforced on Windows")
	}
	p := writeEnv(t, t.TempDir(), "SULAYI_ALICE_TOKEN=a\n")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	ef, err := LoadEnvFile(p, []string{"SULAYI_ALICE_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ef.Warnings, " "), "readable by users other than its owner") {
		t.Errorf("warnings = %v", ef.Warnings)
	}
}

func TestCredentialsFileErrorsNameThePathNotTheContent(t *testing.T) {
	if _, err := LoadEnvFile(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("a missing file was accepted")
	}
	if _, err := LoadEnvFile(t.TempDir(), nil); err == nil {
		t.Error("a directory was accepted")
	}
}

// A credential source resolves through the lookup it is given, so a --env file
// is used without ever being exported.
func TestCredentialSourceResolvesThroughTheLookup(t *testing.T) {
	src := CredentialSource{Env: "SULAYI_TEST_LOOKUP_ONLY"}
	s, err := src.ResolveWith(func(n string) (string, bool) {
		return "value", n == "SULAYI_TEST_LOOKUP_ONLY"
	})
	if err != nil || s.Expose() != "value" {
		t.Fatalf("ResolveWith = %v, %v", s, err)
	}
	if _, err := src.ResolveWith(func(string) (string, bool) { return "", false }); err == nil ||
		!strings.Contains(err.Error(), "SULAYI_TEST_LOOKUP_ONLY") {
		t.Errorf("a missing name: err = %v, want one naming the variable", err)
	}
}
