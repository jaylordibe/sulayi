// Package browser drives a locally installed Chrome or Chromium so that a
// single-page application's front end can be observed: which requests it
// makes, and which links exist only once it has rendered.
//
// The browser is given no network of its own. Every request a page makes is
// paused through the DevTools Fetch domain and handed to a Relay, which the
// caller implements with Sulayi's scope-enforcing HTTP client; the response is
// handed back to the page. Whatever interception does not cover — WebSockets,
// service workers, pop-ups, prefetches, the browser's own background traffic —
// has nowhere to go: every host name and address resolves to nothing, the
// proxy included, and every connection is sent to that proxy.
//
// The protocol runs over --remote-debugging-pipe, so no debugging port is ever
// open on the machine. Sulayi never downloads a browser; it uses the one the
// operator has, and keeps Chrome's sandbox on.
package browser

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/jaylordibe/sulayi/internal/proc"
)

// ErrNotFound reports that no Chrome or Chromium was found.
var ErrNotFound = errors.New("no Chrome or Chromium was found; install one or set discovery.browser.executable")

// startTimeout bounds how long the browser has to answer its first command.
const startTimeout = 30 * time.Second

// Find returns the browser executable to use: the configured one, or the first
// standard Chrome or Chromium installation found.
func Find(configured string) (string, error) {
	if configured != "" {
		// Absolute, because the browser is started in its profile directory
		// and a relative path would be resolved against that.
		abs, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("discovery.browser.executable: %w", err)
		}
		configured = abs
		info, err := os.Stat(configured)
		if err != nil {
			return "", fmt.Errorf("discovery.browser.executable: %w", err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("discovery.browser.executable is a directory, not a program")
		}
		return configured, nil
	}
	for _, c := range candidates() {
		if filepath.IsAbs(c) {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", ErrNotFound
}

func candidates() []string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		out := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
		if home != "" {
			out = append(out,
				filepath.Join(home, "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
				filepath.Join(home, "Applications/Chromium.app/Contents/MacOS/Chromium"))
		}
		return out
	case "windows":
		var out []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := os.Getenv(env); dir != "" {
				out = append(out, filepath.Join(dir, `Google\Chrome\Application\chrome.exe`),
					filepath.Join(dir, `Chromium\Application\chrome.exe`))
			}
		}
		return out
	default:
		return []string{"google-chrome-stable", "google-chrome", "chromium", "chromium-browser"}
	}
}

// Browser is one running browser process with a throwaway profile.
type Browser struct {
	conn    *conn
	cmd     *exec.Cmd
	profile string
	sink    net.Listener
	exited  chan struct{}
	// kill ends the browser's whole process group, through the command's
	// Cancel; it is the only way the process is stopped.
	kill context.CancelFunc

	closeOnce sync.Once
}

// Launch starts the browser at exe.
//
// The flags are the boundary, so each is here for a reason:
//
//   - --remote-debugging-pipe: the protocol over inherited pipes, no port.
//   - --host-resolver-rules: nothing resolves — no host name, and in the
//     Chrome this was verified against, no address literal either — so
//     nothing the page reaches outside interception can connect.
//   - --proxy-server and --proxy-bypass-list=<-loopback>: every connection,
//     loopback included, is sent to the proxy, which the rule above also
//     makes unreachable. The proxy's address is a Sulayi listener that
//     refuses everything, so that if a browser ever resolved it the
//     connection would still end in Sulayi, not at whatever else might be
//     listening on a fixed port.
//   - --disable-quic and the WebRTC policy: no UDP path around the proxy.
//   - the background-networking, sync, component-update and extension
//     switches: the browser has no traffic of its own.
//
// There is no --no-sandbox, and there never will be: the browser runs the
// target's code.
func Launch(ctx context.Context, exe string) (*Browser, error) {
	profile, err := os.MkdirTemp("", "sulayi-browser-")
	if err != nil {
		return nil, fmt.Errorf("cannot create the browser profile directory: %w", err)
	}
	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.RemoveAll(profile)
		return nil, fmt.Errorf("cannot open the browser's network sink: %w", err)
	}
	b := &Browser{profile: profile, sink: sink, exited: make(chan struct{})}
	go b.refuse()

	args := []string{
		"--headless=new",
		"--remote-debugging-pipe",
		"--user-data-dir=" + profile,
		"--host-resolver-rules=MAP * ~NOTFOUND",
		"--proxy-server=http://" + sink.Addr().String(),
		"--proxy-bypass-list=<-loopback>",
		"--disable-quic",
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-extensions",
		"--disable-default-apps",
		"--disable-domain-reliability",
		"--disable-breakpad",
		"--disable-crash-reporter",
		"--no-first-run",
		"--no-default-browser-check",
		"--no-pings",
		"--metrics-recording-only",
		"--mute-audio",
		"--hide-scrollbars",
		// The browser's home is its throwaway profile, so it must not look for
		// the operator's credential store: on macOS that is a keychain prompt
		// on the operator's screen, on Linux a keyring. Nothing is saved.
		"--use-mock-keychain",
		"--password-store=basic",
		"about:blank",
	}
	procCtx, kill := context.WithCancel(context.Background())
	b.kill = kill
	cmd := exec.CommandContext(procCtx, exe, args...)
	cmd.Dir = profile
	// The browser inherits nothing but what it needs to start; its home is its
	// throwaway profile, so it reads and writes nothing of the operator's.
	cmd.Env = append(proc.MinimalEnv([]string{"SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR",
		"LOCALAPPDATA", "PROGRAMDATA"}, nil), "HOME="+profile, "USERPROFILE="+profile)
	proc.Isolate(cmd)
	// The browser's diagnostics are kept, bounded, for the one case they are
	// needed: a browser that will not start says why.
	diag := &tail{max: 8 << 10}
	cmd.Stderr = diag
	p, err := attachPipes(cmd)
	if err != nil {
		kill()
		_ = b.cleanup()
		return nil, err
	}
	err = cmd.Start()
	// The child's ends belong to the child now; holding them open here would
	// keep the pipe alive after the browser exits.
	for _, f := range p.child {
		_ = f.Close()
	}
	if err != nil {
		_ = p.r.Close()
		_ = p.w.Close()
		kill()
		_ = b.cleanup()
		return nil, fmt.Errorf("the browser could not be started: %w", err)
	}
	r, w := p.r, p.w
	b.cmd = cmd
	b.conn = newConn(r, w)
	go func() {
		_ = cmd.Wait()
		close(b.exited)
	}()

	startCtx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	var version struct {
		Product string `json:"product"`
	}
	if err := b.conn.call(startCtx, "", "Browser.getVersion", struct{}{}, &version); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("the browser did not answer: %w%s", err, diag.said())
	}
	return b, nil
}

// tail keeps the last max bytes written to it.
type tail struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = t.buf[over:]
	}
	return len(p), nil
}

// said renders what the browser printed, for an error message.
func (t *tail) said() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.buf) == 0 {
		return " (the browser printed nothing)"
	}
	said := string(t.buf)
	if len(said) > 2048 {
		said = said[len(said)-2048:] // the end of a crash log is the part that says why
	}
	return "; the browser said: " + proc.Sanitize(said, 4096)
}

// refuse accepts and immediately closes every connection made to the proxy.
// Nothing is read from them.
func (b *Browser) refuse() {
	for {
		c, err := b.sink.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}

// Close ends the browser and deletes its profile. It is safe to call more than
// once and after the browser has exited on its own. The error reports a
// profile that could not be deleted: it holds what the target stored in the
// browser, so the caller tells the operator where it is.
func (b *Browser) Close() error {
	var err error
	b.closeOnce.Do(func() {
		if b.conn != nil {
			// Asked to close first; but a browser that stopped reading its
			// pipe would block the request itself, so the kill below never
			// waits on it.
			asked := make(chan struct{})
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = b.conn.call(ctx, "", "Browser.close", struct{}{}, nil)
				cancel()
				close(asked)
			}()
			select {
			case <-asked:
			case <-time.After(3 * time.Second):
				b.kill()
			}
			b.conn.close()
		}
		if b.cmd != nil && b.cmd.Process != nil {
			select {
			case <-b.exited:
			case <-time.After(3 * time.Second):
			}
			// The whole process group, whether or not the browser exited:
			// a renderer or helper may still be running.
			b.kill()
			if b.cmd.Cancel != nil {
				_ = b.cmd.Cancel()
			}
			select {
			case <-b.exited:
			case <-time.After(5 * time.Second):
			}
		}
		err = b.cleanup()
	})
	return err
}

func (b *Browser) cleanup() error {
	_ = b.sink.Close()
	// A helper process can hold a file open for a moment after the group is
	// killed, so removal is retried briefly.
	var err error
	for i := 0; i < 10; i++ {
		if err = os.RemoveAll(b.profile); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("the browser profile %s could not be deleted: %w", b.profile, err)
}

// Profile returns the throwaway profile directory, for tests.
func (b *Browser) Profile() string { return b.profile }
