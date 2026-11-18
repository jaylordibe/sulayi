//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// These tests run the real binary, because what they assert lives in the
// process: how it handles a signal, what it writes on the way out, and what
// exit status the operating system sees.

func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and signals the real binary")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is not available")
	}
	bin := filepath.Join(t.TempDir(), "sulayi")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// One interrupt stops the assessment, writes the report, says why, and exits 4.
func TestInterruptStopsTheRunAndStillReports(t *testing.T) {
	bin := buildBinary(t)

	var hits atomic.Int64
	first := make(chan struct{})
	var once sync.Once
	target := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		once.Do(func() { close(first) })
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
	}))

	var paths []string
	for i := 0; i < 40; i++ {
		paths = append(paths, fmt.Sprintf(`"/api/r%d":{"get":{"security":[{"bearer":[]}]}}`, i))
	}
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"openapi.json": `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{` +
			strings.Join(paths, ",") + `}}`,
		"sulayi.yaml": "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + target + "\n" +
			"discovery:\n  probeWellKnownPaths: false\n",
	})

	cmd := exec.Command(bin, "attack", "--spec", "openapi.json")
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the target was never contacted")
	}
	_ = cmd.Process.Signal(syscall.SIGINT)
	err := cmd.Wait()

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 4 {
		t.Fatalf("exit = %v, want status 4\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	atExit := hits.Load()
	time.Sleep(500 * time.Millisecond)
	if n := hits.Load() - atExit; n != 0 {
		t.Errorf("the target received %d request(s) after the process exited", n)
	}
	if !strings.Contains(stdout.String(), "STOPPED EARLY: the assessment was interrupted") {
		t.Errorf("the summary does not say the run was interrupted:\n%s", stdout.String())
	}
	reports, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "report.json"))
	logs, _ := filepath.Glob(filepath.Join(dir, ".sulayi", "runs", "*", "requests.jsonl"))
	if len(reports) != 1 || len(logs) != 1 {
		t.Errorf("report.json = %d, requests.jsonl = %d; an interrupted run must still write both",
			len(reports), len(logs))
	}
}

// A second interrupt ends the process at once, even while a fixture is being
// restored on its own bounded context, for an operator who will not wait.
func TestSecondInterruptExitsImmediately(t *testing.T) {
	bin := buildBinary(t)

	var mu sync.Mutex
	status := "paid"
	written := make(chan struct{})
	afterRead := make(chan struct{})
	var writeOnce, readOnce sync.Once
	target := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if caller == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPatch:
			if caller == "bob-token" {
				mu.Lock()
				status = "changed"
				mu.Unlock()
				writeOnce.Do(func() { close(written) })
			}
		case http.MethodGet:
			mu.Lock()
			changed := status == "changed"
			mu.Unlock()
			if changed && caller == "alice-token" {
				// The owner's read after the write: hold it, so the restoration
				// phase is still running when the second interrupt arrives.
				readOnce.Do(func() { close(afterRead) })
				time.Sleep(25 * time.Second)
			}
		}
		mu.Lock()
		body := `{"id":"o1","status":"` + status + `"}`
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"openapi.json": `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
		  "/api/orders/{orderId}":{
		    "get":{"security":[{"bearer":[]}],"parameters":[{"name":"orderId","in":"path","required":true}]},
		    "patch":{"security":[{"bearer":[]}],"parameters":[{"name":"orderId","in":"path","required":true}]}}}}`,
		"sulayi.yaml": "apiVersion: sulayi/v1alpha1\ntarget:\n  baseURL: " + target + "\n" +
			"discovery:\n  probeWellKnownPaths: false\n" +
			"identities:\n" +
			"  - id: alice\n    authentication:\n      type: bearer\n      credential:\n        env: SIGTEST_ALICE\n" +
			"  - id: bob\n    authentication:\n      type: bearer\n      credential:\n        env: SIGTEST_BOB\n" +
			"resources:\n  - id: order-alice\n    type: order\n    owner: alice\n    crossOwnerAccess: denied\n" +
			"    disposable: true\n    values:\n      orderId: o1\n    mutation:\n      values:\n        status: changed\n",
	})

	cmd := exec.Command(bin, "attack", "--spec", "openapi.json")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "SIGTEST_ALICE=alice-token", "SIGTEST_BOB=bob-token")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait := func(ch chan struct{}, what string) {
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("%s never happened\nstdout: %s\nstderr: %s", what, stdout.String(), stderr.String())
		}
	}
	wait(written, "the cross-owner write")
	_ = cmd.Process.Signal(syscall.SIGINT)
	wait(afterRead, "the owner's after-read")

	_ = cmd.Process.Signal(syscall.SIGINT)
	start := time.Now()
	err := cmd.Wait()
	took := time.Since(start)

	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the process exited cleanly after a second interrupt: %v", err)
	}
	ws, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Errorf("exit = %v, want termination by SIGINT", err)
	}
	if took > 3*time.Second {
		t.Errorf("the process took %s to exit after the second interrupt", took)
	}
	if !strings.Contains(stderr.String(), "Interrupt again to exit immediately") {
		t.Errorf("the first interrupt did not say how to exit immediately:\n%s", stderr.String())
	}
}
