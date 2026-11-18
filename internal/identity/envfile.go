package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// MaxEnvFileBytes bounds a credentials file. It holds a handful of test
// accounts, not a database dump.
const MaxEnvFileBytes = 1 << 20

// Lookup returns the value of a named credential and whether it exists.
type Lookup func(name string) (string, bool)

// ProcessEnv looks a name up in the process environment.
func ProcessEnv(name string) (string, bool) { return os.LookupEnv(name) }

// EnvFile is a credentials file given with --env, held in memory only.
//
// Its values never enter the process environment, so no child process can
// inherit one, however its environment is later built. Only the names the
// configuration references are kept: a file passed by mistake — an
// application's own .env, with its database password and signing keys — can
// lend Sulayi nothing it does not use.
type EnvFile struct {
	path   string
	values map[string]string
	// Ignored counts entries the configuration does not reference.
	Ignored int
	// Warnings are non-fatal concerns about how the file is stored.
	Warnings []string
}

// Path returns the file's path.
func (e *EnvFile) Path() string { return e.path }

// Lookup resolves a name: the process environment first, then the file. A
// variable set in the shell overriding the file is the convention every dotenv
// loader follows, and it lets one run override one account without editing the
// file.
func (e *EnvFile) Lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv(name); ok {
		return v, true
	}
	if e == nil {
		return "", false
	}
	v, ok := e.values[name]
	return v, ok
}

// Has reports whether the file itself defines a name.
func (e *EnvFile) Has(name string) bool {
	if e == nil {
		return false
	}
	_, ok := e.values[name]
	return ok
}

// LoadEnvFile reads a credentials file, keeping only the referenced names.
//
// It refuses a file that git tracks, because a committed credential is already
// leaked. Every error names a line number or a path and never a value, so it
// can be printed as it is.
func LoadEnvFile(path string, referenced []string) (*EnvFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the credentials file %s: %w", path, unwrapPathError(err))
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot read the credentials file %s: %w", path, unwrapPathError(err))
	}
	if info.IsDir() {
		return nil, fmt.Errorf("the credentials file %s is a directory", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxEnvFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the credentials file %s: %w", path, unwrapPathError(err))
	}
	if len(data) > MaxEnvFileBytes {
		return nil, fmt.Errorf("the credentials file %s exceeds %d bytes", path, MaxEnvFileBytes)
	}

	if tracked, err := gitTracked(path); err == nil && tracked {
		return nil, fmt.Errorf("the credentials file %s is tracked by git, so its contents are already "+
			"in the repository's history. Remove it from git, rotate what it held, and add it to .gitignore", path)
	}

	parsed, err := parseEnv(string(data))
	if err != nil {
		return nil, fmt.Errorf("the credentials file %s: %w", path, err)
	}

	wanted := make(map[string]bool, len(referenced))
	for _, n := range referenced {
		wanted[n] = true
	}
	ef := &EnvFile{path: path, values: map[string]string{}}
	for k, v := range parsed {
		if wanted[k] {
			ef.values[k] = v
		} else {
			ef.Ignored++
		}
	}

	if permissionsEnforced() {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			ef.Warnings = append(ef.Warnings, fmt.Sprintf("the credentials file %s is mode %o and is "+
				"readable by users other than its owner", path, perm))
		}
	}
	if ignored, err := gitIgnored(path); err == nil && !ignored {
		ef.Warnings = append(ef.Warnings, fmt.Sprintf("the credentials file %s is inside a git "+
			"repository and no ignore rule covers it, so it could be committed by accident", path))
	}
	return ef, nil
}

// parseEnv reads KEY=VALUE lines.
//
// The grammar is deliberately small: comments, blank lines, an optional
// "export " prefix, and values that are unquoted, single-quoted (literal) or
// double-quoted (with \n, \", \\ and \$ escapes). ${NAME} in an unquoted or
// double-quoted value expands, as phpdotenv, python-dotenv and Compose all do,
// to the shell's NAME or else a NAME defined earlier in the file — an
// application's own .env commonly builds an address from its domain this way.
// There is no command substitution and no other form of expansion: a
// credentials file is data, and a loader that evaluated it would execute
// whatever the file said. Errors carry line numbers and names, never values.
func parseEnv(s string) (map[string]string, error) {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		n := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("line %d is not of the form NAME=value", n)
		}
		key := strings.TrimSpace(line[:eq])
		if !envPattern.MatchString(key) {
			return nil, fmt.Errorf("line %d does not start with a valid variable name", n)
		}
		raw := strings.TrimLeft(line[eq+1:], " \t")

		switch {
		case strings.HasPrefix(raw, `"`):
			// A double-quoted value may span lines.
			val, rest, consumed, err := doubleQuoted(raw[1:], lines[i+1:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", n, err)
			}
			if !trailingOK(rest) {
				return nil, fmt.Errorf("line %d has text after its closing quote", n)
			}
			i += consumed
			expanded, err := expand(val, out)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", n, err)
			}
			out[key] = expanded
		case strings.HasPrefix(raw, `'`):
			end := strings.IndexByte(raw[1:], '\'')
			if end < 0 {
				return nil, fmt.Errorf("line %d has an unterminated single-quoted value", n)
			}
			if !trailingOK(raw[end+2:]) {
				return nil, fmt.Errorf("line %d has text after its closing quote", n)
			}
			out[key] = raw[1 : end+1]
		default:
			// An unquoted value ends at an inline comment, which must be
			// preceded by whitespace so that a '#' inside a value survives.
			if idx := strings.Index(raw, " #"); idx >= 0 {
				raw = raw[:idx]
			}
			if idx := strings.Index(raw, "\t#"); idx >= 0 {
				raw = raw[:idx]
			}
			expanded, err := expand(strings.TrimSpace(raw), out)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", n, err)
			}
			out[key] = expanded
		}
	}
	return out, nil
}

// doubleQuoted reads a double-quoted value that may continue on later lines,
// returning the value, what followed the closing quote, and how many further
// lines it consumed.
func doubleQuoted(first string, more []string) (string, string, int, error) {
	var b strings.Builder
	s := first
	consumed := 0
	for {
		for j := 0; j < len(s); j++ {
			c := s[j]
			switch {
			case c == '\\' && j+1 < len(s):
				j++
				switch s[j] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '"', '\\':
					b.WriteByte(s[j])
				case '$':
					// An escaped dollar is literal and is not expanded.
					b.WriteByte(literalDollar)
				default:
					b.WriteByte('\\')
					b.WriteByte(s[j])
				}
			case c == '"':
				return b.String(), s[j+1:], consumed, nil
			default:
				b.WriteByte(c)
			}
		}
		if consumed >= len(more) {
			return "", "", 0, errors.New("unterminated double-quoted value")
		}
		b.WriteByte('\n')
		s = more[consumed]
		consumed++
	}
}

// literalDollar stands in for an escaped "$" until expansion has run.
const literalDollar = 0x00

// expand replaces ${NAME} with the shell's NAME or a NAME defined earlier in
// the file. An undefined name is an error naming the variable, never a value.
func expand(v string, defined map[string]string) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(v, "${")
		if i < 0 {
			b.WriteString(v)
			break
		}
		end := strings.IndexByte(v[i:], '}')
		if end < 0 {
			return "", errors.New("has an unterminated ${")
		}
		name := v[i+2 : i+end]
		if !envPattern.MatchString(name) {
			return "", errors.New("has a ${...} that is not a variable name")
		}
		val, ok := os.LookupEnv(name)
		if !ok {
			val, ok = defined[name]
		}
		if !ok {
			return "", fmt.Errorf("refers to ${%s}, which is not defined above it or in the environment", name)
		}
		b.WriteString(v[:i])
		b.WriteString(val)
		v = v[i+end+1:]
	}
	return strings.ReplaceAll(b.String(), string(rune(literalDollar)), "$"), nil
}

func trailingOK(rest string) bool {
	rest = strings.TrimSpace(rest)
	return rest == "" || strings.HasPrefix(rest, "#")
}

// unwrapPathError drops the path os.PathError repeats, so a message names the
// file once.
func unwrapPathError(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// gitTracked reports whether git tracks path. An error means it could not be
// determined — no git, or not inside a repository — and is not a refusal.
func gitTracked(path string) (bool, error) {
	code, err := runGit(path, "ls-files", "--error-unmatch", "--")
	if err != nil {
		return false, err
	}
	return code == 0, nil
}

// gitIgnored reports whether an ignore rule covers path.
func gitIgnored(path string) (bool, error) {
	code, err := runGit(path, "check-ignore", "-q", "--")
	if err != nil {
		return false, err
	}
	switch code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, fmt.Errorf("git check-ignore exited %d", code)
}

// runGit runs a read-only git query about one file, from the file's own
// directory, with a short deadline. It returns git's exit status, or an error
// when git could not answer — not installed, or the file is not inside a
// repository.
func runGit(path string, args ...string) (int, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}
	dir := filepath.Dir(abs)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	inRepo := exec.CommandContext(ctx, gitPath, "-C", dir, "rev-parse", "--is-inside-work-tree")
	if out, err := inRepo.Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
		return 0, errors.New("not inside a git work tree")
	}
	cmd := exec.CommandContext(ctx, gitPath, append(append([]string{"-C", dir}, args...), filepath.Base(abs))...)
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitCode(), nil
	default:
		return 0, err
	}
}
