//go:build windows

package browser

import "github.com/jaylordibe/sulayi/internal/proc"

// browserEnv is the browser's whole environment: the Windows folder variables
// Chrome needs to locate itself and its default profile, and nothing else this
// process holds — a credential in particular. The profile is isolated by
// --user-data-dir. Unlike on Unix, the user's folders cannot be redirected
// here: Chrome refuses remote debugging when it cannot establish that the
// profile it was given is not the default one.
func browserEnv(string) []string {
	return proc.MinimalEnv([]string{"SystemRoot", "SystemDrive", "windir", "TEMP", "TMP", "USERPROFILE",
		"APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
		"HOMEDRIVE", "HOMEPATH", "USERNAME", "USERDOMAIN", "COMPUTERNAME"}, nil)
}
