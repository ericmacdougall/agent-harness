package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// processTree owns one provider child and everything it spawns.
//
// It exists to hold four rules that were scattered across callers (catalog
// A3 to A6):
//   - A signal is never sent after the leader was reaped, so a recycled group ID
//     cannot be hit. The reaped flag and every signal share one lock.
//   - Wait is bounded. A descendant that keeps stderr open cannot hang it, and a
//     descendant that keeps stdout open cannot hide the leader's death.
//   - On every path that loses supervision the whole group is stopped before the
//     leader is marked reaped.
//   - Termination escalates from a polite signal to a kill after a grace period
//     without sleeping while holding any lock.
type processTree struct {
	cmd     *exec.Cmd
	stdout  *os.File
	signal  func(pid int, force bool) error
	drain   time.Duration
	mu      sync.Mutex
	reaped  bool
	stopped bool
	// stopOnExit is evaluated under mu at the instant the leader is reaped. It
	// decides whether the group is stopped (no final seen) or left alone (a true
	// final was recorded, so background work belongs to the tool).
	stopOnExit func() bool
	exited     chan struct{}
	waitErr    error
}

const (
	defaultTreeWaitDelay = time.Second
	defaultTreeDrain     = 2 * time.Second
)

// startProcessTree starts cmd and returns its tree. The caller must already have
// called configureProcess. Stdout is delivered through Stdout(), never through
// cmd.StdoutPipe, because Wait must not close a pipe the reader is still using.
func startProcessTree(cmd *exec.Cmd, stopOnExit func() bool) (*processTree, error) {
	return startProcessTreeWith(cmd, stopOnExit, signalProcessGroup, defaultTreeWaitDelay, defaultTreeDrain)
}

func startProcessTreeWith(cmd *exec.Cmd, stopOnExit func() bool, signal func(int, bool) error, waitDelay, drain time.Duration) (*processTree, error) {
	if cmd == nil {
		return nil, errors.New("process tree needs a command")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = writer
	cmd.WaitDelay = waitDelay
	if err = cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	// Only descendants hold the write end now; leader exit plus every descendant
	// closing it is the only way the reader sees EOF on its own.
	_ = writer.Close()
	t := &processTree{cmd: cmd, stdout: reader, signal: signal, drain: drain, stopOnExit: stopOnExit, exited: make(chan struct{})}
	go t.wait()
	return t, nil
}

func (t *processTree) wait() {
	err := t.cmd.Wait()
	t.mu.Lock()
	// The leader is reaped but the flag is not set yet, so the group ID is still
	// ours. Decide the group's fate in this window.
	if t.stopped || (t.stopOnExit != nil && t.stopOnExit()) {
		_ = t.signal(t.cmd.Process.Pid, true)
	}
	t.reaped = true
	t.waitErr = err
	t.mu.Unlock()
	close(t.exited)
	// A descendant may hold stdout open forever. Unblock the reader after a bound.
	time.AfterFunc(t.drain, func() { _ = t.stdout.Close() })
}

// Stdout is the child's standard output. It returns EOF when every holder closed
// it, or an error once the drain bound after leader exit has passed.
func (t *processTree) Stdout() io.Reader { return t.stdout }

// Exited is closed once the leader has been reaped, whether or not stdout ended.
func (t *processTree) Exited() <-chan struct{} { return t.exited }

// Err is the leader's wait result. Valid after Exited is closed.
func (t *processTree) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.waitErr
}

// Reaped reports whether the leader has been reaped.
func (t *processTree) Reaped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reaped
}

// Terminate stops the whole group: a polite signal first, a kill after grace.
// It returns false without signalling when the leader was already reaped. It
// never sleeps while holding the lock.
func (t *processTree) Terminate(grace time.Duration) bool {
	t.mu.Lock()
	if t.reaped {
		t.mu.Unlock()
		return false
	}
	t.stopped = true
	_ = t.signal(t.cmd.Process.Pid, false)
	t.mu.Unlock()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-t.exited:
		return true
	case <-timer.C:
	}
	t.mu.Lock()
	if !t.reaped {
		_ = t.signal(t.cmd.Process.Pid, true)
	}
	t.mu.Unlock()
	<-t.exited
	return true
}
