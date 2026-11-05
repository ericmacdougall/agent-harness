package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// errStreamDrainBound ends the stdout stream when a descendant keeps the pipe
// open after the leader exited and no more data arrives within the drain bound.
// Consumers can tell it from a clean EOF.
var errStreamDrainBound = errors.New("provider output ended by the drain bound while a descendant held the pipe")

// processTree owns one provider child and everything it spawns (catalog A3-A6).
//
// Rules it holds in one place:
//   - A signal is never sent once the leader may have been reaped. On Linux and
//     macOS the leader's exit is observed without reaping it (waitid WNOWAIT,
//     kqueue NOTE_EXIT), so the zombie pins the pid and the group ID until the
//     tree has decided the group's fate. Elsewhere the exit is observed by
//     Wait and the old narrow window remains (documented, not hidden).
//   - The stop-on-exit decision happens only after the consumer has taken the
//     whole stream (or the consume bound passed, or a stop was requested), so a
//     leader that prints its final and exits cannot lose background work to a
//     decision made before the final was read.
//   - Output is pumped continuously, so a slow consumer never loses bytes that
//     are already in the pipe. The drain bound applies to idleness of the pipe,
//     not to the consumer.
//   - Termination escalates from a polite signal to a kill without sleeping
//     under a lock.
//
// Lock rule: stopOnExit must be lock-free (an atomic flag). It is called
// without t.mu held and must not take any application lock.
type processTree struct {
	cmd     *exec.Cmd
	stdout  *os.File
	signal  func(pid int, force bool) error
	release func()
	drain   time.Duration
	consume time.Duration

	pr       *io.PipeReader
	pw       *io.PipeWriter
	consumed chan struct{}
	consOnce sync.Once

	mu         sync.Mutex
	reaped     bool // true once signals are no longer permitted
	stopped    bool
	stopCh     chan struct{}
	stopOnExit func() bool

	exitSeen atomic.Bool
	exited   chan struct{} // leader exit observed
	done     chan struct{} // leader reaped, Err valid
	waitErr  error
}

type processTreeOptions struct {
	Signal       func(pid int, force bool) error // nil: platform default
	WaitDelay    time.Duration
	Drain        time.Duration // idle bound on the pipe after leader exit
	ConsumeGrace time.Duration // how long the decision waits for the consumer
}

const (
	defaultTreeWaitDelay = time.Second
	defaultTreeDrain     = 2 * time.Second
	defaultTreeConsume   = 7 * time.Second
)

// startProcessTree starts cmd and returns its tree. The caller must already have
// called configureProcess and may set cmd.Stderr; Stdout is delivered through
// Stdout(), never cmd.StdoutPipe.
func startProcessTree(cmd *exec.Cmd, stopOnExit func() bool) (*processTree, error) {
	return startProcessTreeWith(cmd, stopOnExit, processTreeOptions{})
}

func startProcessTreeWith(cmd *exec.Cmd, stopOnExit func() bool, opt processTreeOptions) (*processTree, error) {
	if cmd == nil {
		return nil, errors.New("process tree needs a command")
	}
	if opt.WaitDelay == 0 {
		opt.WaitDelay = defaultTreeWaitDelay
	}
	if opt.Drain == 0 {
		opt.Drain = defaultTreeDrain
	}
	if opt.ConsumeGrace == 0 {
		opt.ConsumeGrace = defaultTreeConsume
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = writer
	cmd.WaitDelay = opt.WaitDelay
	if err = cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	_ = writer.Close() // only descendants hold the write end now
	signal, release, err := treeSignaler(cmd)
	if opt.Signal != nil {
		signal = opt.Signal
	}
	if err != nil && opt.Signal == nil {
		// Without a way to signal the tree it cannot be supervised: stop the leader.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = reader.Close()
		return nil, err
	}
	pr, pw := io.Pipe()
	t := &processTree{
		cmd: cmd, stdout: reader, signal: signal, release: release,
		drain: opt.Drain, consume: opt.ConsumeGrace, pr: pr, pw: pw,
		consumed: make(chan struct{}), stopCh: make(chan struct{}), stopOnExit: stopOnExit,
		exited: make(chan struct{}), done: make(chan struct{}),
	}
	go t.pump()
	go t.wait()
	return t, nil
}

func (t *processTree) pump() {
	buf := make([]byte, 32<<10)
	discard := false
	var endErr error
	for {
		if t.exitSeen.Load() {
			// Idle bound, re-armed before every read so a slow consumer never
			// spends it.
			_ = t.stdout.SetReadDeadline(time.Now().Add(t.drain))
		}
		n, err := t.stdout.Read(buf)
		if n > 0 && !discard {
			if _, werr := t.pw.Write(buf[:n]); werr != nil {
				discard = true // consumer left; keep emptying so the child never blocks
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				endErr = errStreamDrainBound
			} else if err != io.EOF {
				endErr = err
			}
			break
		}
	}
	_ = t.stdout.Close()
	if endErr != nil {
		_ = t.pw.CloseWithError(endErr)
	} else {
		_ = t.pw.Close()
	}
}

func (t *processTree) wait() {
	pid := t.cmd.Process.Pid
	pinned := observeExit(pid) == nil
	var legacyErr error
	if !pinned {
		legacyErr = t.cmd.Wait() // old behaviour: Wait is the observation
	}
	t.exitSeen.Store(true)
	_ = t.stdout.SetReadDeadline(time.Now().Add(t.drain)) // unblock a pending read
	close(t.exited)
	if pinned {
		timer := time.NewTimer(t.consume)
		select {
		case <-t.consumed:
		case <-t.stopCh:
		case <-timer.C:
		}
		timer.Stop()
	}
	stop := t.stopOnExit != nil && t.stopOnExit()
	t.mu.Lock()
	if t.stopped || stop {
		_ = t.signal(pid, true)
	}
	t.reaped = true // conservative: set before the real reap
	t.mu.Unlock()
	err := legacyErr
	if pinned {
		err = t.cmd.Wait()
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil // a descendant holding stderr is not a leader failure
	}
	t.mu.Lock()
	t.waitErr = err
	t.mu.Unlock()
	if t.release != nil && (stop || t.stopped) {
		t.release()
	}
	close(t.done)
}

// Stdout is the child's output. It ends with io.EOF when every holder closed the
// pipe, or errStreamDrainBound when a descendant kept it open and idle.
func (t *processTree) Stdout() io.Reader { return &treeReader{t: t} }

type treeReader struct{ t *processTree }

func (r *treeReader) Read(p []byte) (int, error) {
	n, err := r.t.pr.Read(p)
	if err != nil {
		r.t.consOnce.Do(func() { close(r.t.consumed) })
	}
	return n, err
}

// Exited is closed once the leader's exit has been observed.
func (t *processTree) Exited() <-chan struct{} { return t.exited }

// Done is closed once the leader is reaped and Err is valid.
func (t *processTree) Done() <-chan struct{} { return t.done }

// Err is the leader's wait result. Valid after Done is closed.
func (t *processTree) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.waitErr
}

// Reaped reports whether signals are no longer permitted.
func (t *processTree) Reaped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reaped
}

// Terminate stops the whole group: a polite signal first, a kill after grace. It
// returns false without signalling when the tree already decided its fate; the
// group may then still hold unsupervised background work, and callers must treat
// false as "possibly alive, not supervised". It never sleeps under the lock.
func (t *processTree) Terminate(grace time.Duration) bool {
	t.mu.Lock()
	if t.reaped {
		t.mu.Unlock()
		return false
	}
	first := !t.stopped
	t.stopped = true
	_ = t.signal(t.cmd.Process.Pid, false)
	t.mu.Unlock()
	if first {
		close(t.stopCh)
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-t.done:
		return true
	case <-timer.C:
	}
	t.mu.Lock()
	if !t.reaped {
		_ = t.signal(t.cmd.Process.Pid, true)
	}
	t.mu.Unlock()
	<-t.done
	return true
}
