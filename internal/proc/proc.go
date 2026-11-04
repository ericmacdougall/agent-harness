// Package proc ports harness/hooks/process.py: run a command with a deadline and, on timeout or
// cancellation, terminate its whole process group (TERM, a 2 s grace so git can drop its lock files,
// then KILL), and never let a descendant that escaped the group hold the caller on a pipe.
package proc

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"time"
)

const (
	// TerminationGrace matches TERMINATION_GRACE_SECONDS: git removes lock files from its TERM handler.
	TerminationGrace = 2 * time.Second
	// PipeGrace matches the 5 s bounded pipe cleanup in process.py.
	PipeGrace = 5 * time.Second
)

// ErrTimeout is returned when the deadline expired; the group has been terminated.
var ErrTimeout = errors.New("proc: timed out")

// Result is a finished command. Code is the exit status, or -1 when killed by a signal.
type Result struct {
	Code           int
	Stdout, Stderr []byte
}

// Options configure Run. Timeout 0 means no deadline.
type Options struct {
	Dir     string
	Env     []string
	Stdin   []byte
	Timeout time.Duration
}

// Run executes argv[0] with argv[1:] (no shell) and captures stdout and stderr.
func Run(argv []string, o Options) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("proc: empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = o.Dir, o.Env
	if o.Stdin != nil {
		cmd.Stdin = bytes.NewReader(o.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = PipeGrace // an escaped descendant holding our pipes cannot block Wait forever
	newGroup(cmd)
	if err := cmd.Start(); err != nil {
		return Result{Code: -1}, err
	}
	done := make(chan error, 1)
	go func() {
		defer func() { recover() }() // no goroutine may crash the harness (plan 3.1, F9)
		done <- cmd.Wait()
	}()
	var timer <-chan time.Time
	if o.Timeout > 0 {
		t := time.NewTimer(o.Timeout)
		defer t.Stop()
		timer = t.C
	}
	select {
	case err := <-done:
		return finish(cmd, err, &stdout, &stderr)
	case <-timer:
	}
	pid := cmd.Process.Pid
	signalGroup(pid, sigTerm)
	deadline := time.Now().Add(TerminationGrace)
	exited := false
	for time.Now().Before(deadline) {
		if !exited {
			select {
			case <-done:
				exited = true // keep waiting: descendants may still be handling TERM
			default:
			}
		}
		if !groupAlive(pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	signalGroup(pid, sigKill)
	if !exited {
		select {
		case <-done:
		case <-time.After(PipeGrace + time.Second):
		}
	}
	return Result{Code: -1, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, ErrTimeout
}

func finish(cmd *exec.Cmd, err error, stdout, stderr *bytes.Buffer) (Result, error) {
	r := Result{Code: cmd.ProcessState.ExitCode(), Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exitErr *exec.ExitError
	if err == nil || errors.As(err, &exitErr) {
		return r, nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return r, nil // the command finished; only an escaped descendant kept a pipe open
	}
	return r, err
}

var _ io.Writer = (*bytes.Buffer)(nil)
