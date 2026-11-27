//go:build !windows

package browser

import (
	"fmt"
	"os"
	"os/exec"
)

type pipes struct {
	r, w  *os.File   // the parent's ends: read from and write to the browser
	child []*os.File // the browser's ends, closed in the parent once started
}

// attachPipes gives the browser the two pipes --remote-debugging-pipe expects:
// it reads commands from descriptor 3 and writes replies to descriptor 4.
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
	cmd.ExtraFiles = []*os.File{toR, fromW}
	return pipes{r: fromR, w: toW, child: []*os.File{toR, fromW}}, nil
}
