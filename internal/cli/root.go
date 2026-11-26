package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// Execute runs the CLI and returns a process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	return ExecuteContext(context.Background(), args, stdout, stderr)
}

// ExecuteContext runs the CLI under ctx. Cancelling ctx stops the assessment:
// planned work that has not started is recorded as cancelled, child processes
// are killed with their process groups, and a fixture already written to is
// still restored on its own bounded context.
func ExecuteContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := &cobra.Command{
		Use:   "sulayi",
		Short: "Assessment coverage and verification",
		Long: "Sulayi assesses an application you own or are explicitly\n" +
			"authorized to test.\n\n" +
			"It runs the security engines you already trust, refuses to overstate what\n" +
			"they found, and produces an account of what was tested, what was blocked,\n" +
			"what was never attempted, and why. It brings its own authentication and\n" +
			"cross-owner checks, which contribute to that account rather than replace it.\n\n" +
			"Sulayi does not prove the absence of vulnerabilities. A run\n" +
			"with no findings means only that the checks it executed produced none —\n" +
			"and the report always says how many that was, out of how many it saw.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       resolveVersion(),
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	root.AddCommand(newAttackCommand(stdout, stderr))
	root.AddCommand(newInitCommand(stdout, stderr))
	root.AddCommand(newDoctorCommand(stdout, stderr))
	root.AddCommand(newVerifyCommand(stdout, stderr))
	root.AddCommand(newReportCommand(stdout))
	root.AddCommand(newVersionCommand(stdout))

	if err := root.ExecuteContext(ctx); err != nil {
		var coded *exitError
		// errors.As rather than a type assertion, so a wrapped exit code keeps
		// its meaning instead of degrading to "invalid usage".
		if errors.As(err, &coded) {
			if coded.message != "" {
				fmt.Fprintln(stderr, coded.message)
			}
			return coded.code
		}
		fmt.Fprintf(stderr, "sulayi: %v\n", err)
		return ExitUsage
	}
	return ExitOK
}

// exitError carries a process exit code out through cobra, which distinguishes
// only error from no error.
type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, message: fmt.Sprintf("sulayi: "+format, args...)}
}

// Main is the entry point used by cmd/sulayi.
//
// The first interrupt or termination signal cancels the assessment rather than
// killing the process, so that it can stop its child processes, account for
// what it did not do and restore anything it changed. Default handling is then
// restored, so a second signal ends the process at once for an operator who
// does not want to wait.
func Main() {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	finished := make(chan struct{})
	go func() {
		select {
		case <-sigs:
			signal.Reset(os.Interrupt, syscall.SIGTERM)
			fmt.Fprintln(os.Stderr, "\nsulayi: stopping: finishing restoration of any changed fixture "+
				"and writing the report. Interrupt again to exit immediately.")
			cancel()
		case <-finished:
		}
	}()
	code := ExecuteContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	close(finished)
	signal.Stop(sigs)
	cancel()
	os.Exit(code)
}
