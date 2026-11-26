// Command measure computes the MVP measurement for one target from its run
// directories and expected results, and prints it as Markdown and JSON.
//
//	go run ./evals/mvp/measure -target crapi -expected evals/mvp/crapi.expected.yaml run1 run2 run3
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jaylordibe/sulayi/evals/mvp"
)

func main() {
	target := flag.String("target", "", "target name")
	expected := flag.String("expected", "", "expected-results file; empty for a false-positive control")
	jsonOut := flag.String("json", "", "write the measurement as JSON to this file")
	commit := flag.String("commit", "", "the commit the runs and the expected file came from")
	flag.Parse()
	if *target == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: measure -target NAME [-expected FILE] [-json FILE] RUN_DIR...")
		os.Exit(2)
	}
	exp, err := mvp.LoadExpected(*expected)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var runs []mvp.Run
	for _, dir := range flag.Args() {
		r, err := mvp.LoadRun(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runs = append(runs, r)
	}
	m, err := mvp.Measure(*target, exp, runs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// The result names what it was scored against, so an expected file
	// edited after a run cannot pass for the one the run was scored with.
	m.Commit = *commit
	if *expected != "" {
		raw, err := os.ReadFile(*expected)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		sum := sha256.Sum256(raw)
		m.ExpectedSHA256 = hex.EncodeToString(sum[:])
	}
	fmt.Print(mvp.Markdown(m))
	if *jsonOut != "" {
		raw, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(*jsonOut, append(raw, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	// Traffic outside scope fails the measurement outright: the roadmap
	// requires zero.
	if m.OutOfScopeRequests > 0 {
		fmt.Fprintf(os.Stderr, "%d request(s) went outside scope\n", m.OutOfScopeRequests)
		os.Exit(1)
	}
}
