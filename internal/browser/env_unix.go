//go:build !windows

package browser

import "github.com/jaylordibe/sulayi/internal/proc"

// browserEnv is the browser's whole environment: its home is its throwaway
// profile, so it reads and writes nothing of the operator's, and nothing else
// this process holds — a credential in particular — reaches it.
func browserEnv(profile string) []string {
	return append(proc.MinimalEnv([]string{"TMPDIR"}, nil), "HOME="+profile)
}
