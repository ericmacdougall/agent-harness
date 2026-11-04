// Package proc ports harness/hooks/process.py: run a command with a deadline and, on timeout, terminate
// its whole process group (TERM, a 2 s grace so git can drop its lock files, then KILL).
//
// Like process.run (communicate), a call finishes only when the leader has exited AND every holder of the
// output pipes has closed them. A descendant that keeps a pipe open therefore keeps the call running
// until the deadline, which then kills the group and reports ErrTimeout; it is never reported as success.
// A descendant that escaped the group cannot hold the caller longer than PipeGrace after the kill.
package proc

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
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

// Options configure Run. Timeout 0 means no deadline (and, as in Python, no bound on a pipe holder).
type Options struct {
	Dir     string
	Env     []string
	Stdin   []byte
	Timeout time.Duration
}

// lockedBuffer lets the timeout path snapshot output while a reader goroutine may still be writing.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

// Run executes argv[0] with argv[1:] (no shell) and captures stdout and stderr.
func Run(argv []string, o Options) (res Result, err error) {
	if len(argv) == 0 {
		return Result{}, errors.New("proc: empty argv")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = o.Dir, o.Env
	var closers []*os.File
	defer func() {
		// Close off the caller's path: on Windows Close waits for a write blocked on a pipe that an
		// escaped descendant holds, which must not hold the caller. There that Close goroutine and the
		// blocked stdin writer stay alive until the holding descendant exits (bounded by the process).
		for _, f := range closers {
			go f.Close()
		}
	}()
	pipe := func() (r, w *os.File, err error) {
		r, w, err = os.Pipe()
		if err == nil {
			closers = append(closers, r, w)
		}
		return
	}
	outR, outW, err := pipe()
	if err != nil {
		return Result{Code: -1}, err
	}
	errR, errW, err := pipe()
	if err != nil {
		return Result{Code: -1}, err
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	var inW *os.File
	if o.Stdin != nil {
		var inR *os.File
		if inR, inW, err = pipe(); err != nil {
			return Result{Code: -1}, err
		}
		cmd.Stdin = inR
	}
	newGroup(cmd)
	if err := cmd.Start(); err != nil {
		return Result{Code: -1}, err
	}
	// The child holds its own copies; ours must close or EOF never arrives.
	outW.Close()
	errW.Close()
	if cmd.Stdin != nil {
		cmd.Stdin.(*os.File).Close()
	}
	var stdout, stderr lockedBuffer
	var readers sync.WaitGroup
	for _, p := range []struct {
		r *os.File
		w io.Writer
	}{{outR, &stdout}, {errR, &stderr}} {
		readers.Add(1)
		go func(r *os.File, w io.Writer) {
			defer readers.Done()
			defer func() { recover() }() // no goroutine may crash the harness (plan 3.1, F9)
			io.Copy(w, r)
		}(p.r, p.w)
	}
	if inW != nil {
		go func() {
			defer func() { recover() }()
			inW.Write(o.Stdin) // EPIPE when the child exits without reading is expected
			inW.Close()
		}()
	}
	exited := make(chan error, 1)
	go func() {
		defer func() { recover() }()
		exited <- cmd.Wait()
	}()
	drained := make(chan struct{})
	go func() {
		readers.Wait()
		close(drained)
	}()
	var timer <-chan time.Time
	if o.Timeout > 0 {
		t := time.NewTimer(o.Timeout)
		defer t.Stop()
		timer = t.C
	}
	var waitErr error
	leaderDone := false
	for !leaderDone || drained != nil {
		select {
		case waitErr = <-exited:
			leaderDone = true
			exited = nil
		case <-drained:
			drained = nil
		case <-timer:
			terminate(cmd.Process.Pid, exited, leaderDone, &readers)
			return Result{Code: -1, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, ErrTimeout
		}
	}
	r := Result{Code: cmd.ProcessState.ExitCode(), Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exitErr *exec.ExitError
	if waitErr == nil || errors.As(waitErr, &exitErr) {
		return r, nil
	}
	return r, waitErr
}

// terminate signals the group TERM, waits up to TerminationGrace for it to empty, KILLs it, then waits
// a bounded time for the leader and the pipe readers. The deferred Close of the read ends unblocks any
// reader still held by an escaped descendant; Result reads a locked snapshot, so a late write is no race.
func terminate(pid int, exited <-chan error, leaderDone bool, readers *sync.WaitGroup) {
	signalGroup(pid, sigTerm)
	deadline := time.Now().Add(TerminationGrace)
	for time.Now().Before(deadline) && groupAlive(pid) {
		time.Sleep(50 * time.Millisecond)
	}
	signalGroup(pid, sigKill)
	bound := time.After(PipeGrace)
	if !leaderDone {
		select {
		case <-exited:
		case <-bound:
		}
	}
	done := make(chan struct{})
	go func() {
		readers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-bound:
	}
}
