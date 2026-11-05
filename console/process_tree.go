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
//   - The stop-or-leave decision waits for the caller's verdict (Settle or
//     Release), a requested stop, or the consume bound; with no verdict the
//     tree stops. A leader that prints its final and exits therefore cannot
//     lose background work to a decision made before the final was read, and
//     a verdict of leave also ends the consumer's stream, because a descendant
//     that keeps writing would otherwise hold it open forever.
//   - Output is pumped continuously, so a slow consumer never loses bytes that
//     are already in the pipe. The drain bound applies to idleness of the pipe,
//     not to the consumer.
//   - Termination escalates from a polite signal to a kill without sleeping
//     under a lock.
//
// Leaving background work alone (a leave verdict) keeps draining the pipe with no
// idle bound, so a slow writer never gets SIGPIPE. Without a verdict, once the
// drain bound passes the read end is closed and a later write gets SIGPIPE, as it
// did before the tree existed.
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

	settled    chan struct{}
	setOnce    sync.Once
	verdict    atomic.Int32 // 0 none, 1 stop, 2 leave
	legacy     bool
	exitSeen   atomic.Bool
	boundHit   atomic.Bool
	noDeadline sync.Once
	exited     chan struct{} // leader exit observed
	done       chan struct{} // leader reaped, Err valid
	waitErr    error
}

type processTreeOptions struct {
	Signal       func(pid int, force bool) error // nil: platform default
	WaitDelay    time.Duration
	Drain        time.Duration // idle bound on the pipe after leader exit
	ConsumeGrace time.Duration // how long the decision waits for the consumer
	MergeStderr  bool          // send stderr into the same stream as stdout
	ForceLegacy  bool          // test hook: behave as on a platform without exit observation
}

const (
	defaultTreeWaitDelay = time.Second
	defaultTreeDrain     = 2 * time.Second
	defaultTreeConsume   = 7 * time.Second
)

// treeConsumeGrace is how long a tree waits for a verdict after its leader
// exits; a variable so tests can shorten it.
var treeConsumeGrace = defaultTreeConsume

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
		opt.ConsumeGrace = treeConsumeGrace
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = writer
	if opt.MergeStderr {
		cmd.Stderr = writer
	}
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
		legacy: opt.ForceLegacy, consumed: make(chan struct{}), stopCh: make(chan struct{}), stopOnExit: stopOnExit,
		exited: make(chan struct{}), done: make(chan struct{}), settled: make(chan struct{}),
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
		if t.exitSeen.Load() && !discard {
			// Idle bound, re-armed before every read so a slow consumer never
			// spends it. Where the pipe is not pollable (Windows) the bound is a
			// timer that closes the read end once, dropping unread bytes.
			if err := t.stdout.SetReadDeadline(time.Now().Add(t.drain)); errors.Is(err, os.ErrNoDeadline) {
				t.noDeadline.Do(func() { time.AfterFunc(t.drain, func() { t.boundHit.Store(true); _ = t.stdout.Close() }) })
			}
		}
		n, err := t.stdout.Read(buf)
		if n > 0 && !discard {
			if _, werr := t.pw.Write(buf[:n]); werr != nil {
				// The consumer left. Keep emptying the pipe with no idle bound so
				// the child never blocks and never receives SIGPIPE.
				discard = true
				_ = t.stdout.SetReadDeadline(time.Time{})
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && (discard || t.verdict.Load() == 2) {
				// Decided to leave background work alone: the idle bound no longer
				// applies. Keep emptying the pipe so a slow writer is never sent
				// SIGPIPE; the cost is a goroutine and an fd until the pipe closes.
				discard = true
				_ = t.stdout.SetReadDeadline(time.Time{})
				continue
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || t.boundHit.Load() {
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
	pinned := !t.legacy && observeExit(pid) == nil
	var legacyErr error
	if !pinned {
		legacyErr = t.cmd.Wait() // old behaviour: Wait is the observation
	}
	t.exitSeen.Store(true)
	if err := t.stdout.SetReadDeadline(time.Now().Add(t.drain)); errors.Is(err, os.ErrNoDeadline) { // unblock a pending read
		t.noDeadline.Do(func() { time.AfterFunc(t.drain, func() { t.boundHit.Store(true); _ = t.stdout.Close() }) })
	}
	close(t.exited)
	{
		// With a stopOnExit policy the stream being consumed triggers the
		// decision. Without one the caller must say, through Release, what to do
		// after it has weighed what it read; an explicit stop also triggers it.
		consumed := t.consumed
		if t.stopOnExit == nil {
			consumed = nil
		}
		timer := time.NewTimer(t.consume)
		expired := false
		select {
		case <-consumed:
		case <-t.settled:
		case <-t.stopCh:
		case <-timer.C:
			expired = true
		}
		timer.Stop()
		// Expiry with no verdict means nobody decided: the default below stops the
		// tree, so a caller that never settles loses background work after
		// ConsumeGrace. Production callers settle at the recorded final.
		_ = expired
	}
	var stop bool
	switch t.verdict.Load() {
	case 1:
		stop = true
	case 2:
		stop = false
	default:
		// No verdict: a tree nobody decided for has lost supervision, so stop it.
		stop = t.stopOnExit == nil || t.stopOnExit()
	}
	t.mu.Lock()
	if t.stopped || stop {
		_ = t.signal(pid, true)
	}
	t.reaped = true // signals stop being allowed here; on the pinned path the real reap follows
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
	if stop || t.stopped || t.verdict.Load() == 2 {
		// Decided: nothing needs the stream any more. Closing the consumer end
		// switches the pump to discarding, so it cannot stick on a write and a
		// descendant that keeps writing is neither blocked nor sent SIGPIPE.
		_ = t.pr.CloseWithError(io.ErrClosedPipe)
	}
	if t.release != nil {
		t.release() // the job handle has no kill-on-close flag, so leaving survivors alone is safe
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

// Release is the caller's verdict once it has finished with the stream: stop the
// group (supervision was lost with no final) or leave background work alone (a
// true final was recorded). The pump keeps emptying the pipe so the child never
// blocks. The first verdict wins.
func (t *processTree) Release(stop bool) {
	t.Settle(stop)
	_ = t.pr.CloseWithError(io.ErrClosedPipe)
	t.consOnce.Do(func() { close(t.consumed) })
}

// Settle records the verdict without closing the stream, so a caller that is
// still reading (for example right after it recorded a final) can let the tree
// decide at the leader's exit without waiting for the stream to end. The first
// verdict wins. It never blocks and is safe to call under a lock.
func (t *processTree) Settle(stop bool) {
	t.setOnce.Do(func() {
		if stop {
			t.verdict.Store(1)
		} else {
			t.verdict.Store(2)
		}
		close(t.settled)
	})
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
	if !t.BeginStop() {
		return false
	}
	t.FinishStop(grace)
	return true
}

// BeginStop sends the polite signal now and returns without waiting, so a caller
// that holds a lock still gets the stop on its way before it returns. It reports
// false when the tree already decided its fate.
func (t *processTree) BeginStop() bool {
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
	return true
}

// FinishStop waits up to grace for the tree to end, then kills the group, then
// waits for the leader to be reaped.
func (t *processTree) FinishStop(grace time.Duration) {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-t.done:
		return
	case <-timer.C:
	}
	t.mu.Lock()
	if !t.reaped {
		_ = t.signal(t.cmd.Process.Pid, true)
	}
	t.mu.Unlock()
	<-t.done
}
