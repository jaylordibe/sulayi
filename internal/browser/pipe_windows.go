//go:build windows

package browser

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

type pipes struct {
	r, w  *os.File   // the parent's ends: read from and write to the browser
	child []*os.File // the browser's ends, closed in the parent once started
}

// attachPipes gives the browser its two pipes on Windows, where there are no
// numbered descriptors to inherit: the handles are made inheritable, passed
// with an explicit inheritance list so the browser receives those two and no
// other, and named to Chrome with --remote-debugging-io-pipes.
func attachPipes(cmd *exec.Cmd) (pipes, error) {
	toR, toW, err := os.Pipe()
	if err != nil {
		return pipes{}, fmt.Errorf("cannot create the browser pipe: %w", err)
	}
	fromR, fromW, err := os.Pipe()
	if err != nil {
		_ = toR.Close()
		_ = toW.Close()
		return pipes{}, fmt.Errorf("cannot create the browser pipe: %w", err)
	}
	in, out := syscall.Handle(toR.Fd()), syscall.Handle(fromW.Fd())
	for _, h := range []syscall.Handle{in, out} {
		if err := syscall.SetHandleInformation(h, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT); err != nil {
			for _, f := range []*os.File{toR, toW, fromR, fromW} {
				_ = f.Close()
			}
			return pipes{}, fmt.Errorf("cannot pass the browser pipe: %w", err)
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.AdditionalInheritedHandles = []syscall.Handle{in, out}
	cmd.SysProcAttr.NoInheritHandles = false
	cmd.Args = append(cmd.Args, fmt.Sprintf("--remote-debugging-io-pipes=%d,%d", uintptr(in), uintptr(out)))
	return pipes{r: fromR, w: toW, child: []*os.File{toR, fromW}}, nil
}
