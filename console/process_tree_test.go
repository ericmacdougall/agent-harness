//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// signalRecorder wraps the real group signal and checks the A5 invariant at the
// instant of each call: the leader must still exist (a zombie counts), because a
// reaped leader means the group ID may belong to someone else.
type signalRecorder struct {
	mu         sync.Mutex
	calls      []bool
	violations int
	pid        atomic.Int64
}

func (r *signalRecorder) signal(pid int, force bool) error {
	if !processExists(pid) {
		r.mu.Lock()
		r.violations++
		r.mu.Unlock()
	}
	r.mu.Lock()
	r.calls = append(r.calls, force)
	r.mu.Unlock()
	return signalProcessGroup(pid, force)
}

func (r *signalRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *signalRecorder) bad() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.violations
}

func processExists(pid int) bool {
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// processGone is true when the pid no longer exists or is only a zombie that an
// init without a reaper has not collected.
func processGone(pid int) bool {
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return true
	}
	state := strings.TrimSpace(string(out))
	return state == "" || strings.HasPrefix(state, "Z")
}

func waitGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if processGone(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return processGone(pid)
}

func shellTreeOpts(t *testing.T, script string, stopOnExit func() bool, rec *signalRecorder, drain time.Duration, stderr io.Writer) *processTree {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Stderr = stderr
	configureProcess(cmd)
	tree, err := startProcessTreeWith(cmd, stopOnExit, processTreeOptions{Signal: rec.signal, WaitDelay: 200 * time.Millisecond, Drain: drain, ConsumeGrace: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func shellTree(t *testing.T, script string, stopOnExit func() bool, rec *signalRecorder, drain time.Duration) *processTree {
	return shellTreeOpts(t, script, stopOnExit, rec, drain, nil)
}

func discardStream(tree *processTree) { go func() { _, _ = io.Copy(io.Discard, tree.Stdout()) }() }

func readPIDs(t *testing.T, tree *processTree, n int) []int {
	t.Helper()
	scanner := bufio.NewScanner(tree.Stdout())
	var pids []int
	for len(pids) < n && scanner.Scan() {
		pid, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil {
			t.Fatalf("not a pid line: %q", scanner.Text())
		}
		pids = append(pids, pid)
	}
	if len(pids) != n {
		t.Fatalf("read %d pids, want %d", len(pids), n)
	}
	discardStream(tree)
	return pids
}

func pidFromFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("descendant pid file never appeared")
	return 0
}

func killPID(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) }

// A5: once the tree decided, nothing may be signalled.
func TestTreeNoSignalAfterReap(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "exit 0", func() bool { return false }, rec, 100*time.Millisecond)
	discardStream(tree)
	select {
	case <-tree.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("leader never reaped")
	}
	if !tree.Reaped() {
		t.Fatal("Done closed but Reaped is false")
	}
	if tree.Terminate(100 * time.Millisecond) {
		t.Fatal("Terminate claimed to act on a decided tree")
	}
	if rec.count() != 0 {
		t.Fatalf("signals after reap: %d", rec.count())
	}
}

// A5 under a race: every signal sent while terminating around the leader's exit
// finds the leader still present (zombie pinned), never reaped.
func TestTreeSignalsNeverReachReapedLeader(t *testing.T) {
	total := 0
	for i := 0; i < 40; i++ {
		rec := &signalRecorder{}
		tree := shellTree(t, "sleep 0.02", nil, rec, 50*time.Millisecond)
		discardStream(tree)
		time.Sleep(time.Duration(i%5) * 8 * time.Millisecond)
		tree.Terminate(300 * time.Millisecond)
		<-tree.Done()
		total += rec.count()
		if rec.bad() != 0 {
			t.Fatalf("iteration %d: %d signal(s) sent after the leader was reaped", i, rec.bad())
		}
	}
	if total == 0 {
		t.Fatal("no signal was ever sent, so the invariant check proved nothing")
	}
}

// A6: a descendant holding stdout must not hide the leader's death or hang the
// reader, and the forced end is distinguishable from EOF.
func TestTreeLeaderDeathSeenWhileDescendantHoldsStdout(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "sleep 300 & echo $!; exit 0", func() bool { return false }, rec, 300*time.Millisecond)
	scanner := bufio.NewScanner(tree.Stdout())
	if !scanner.Scan() {
		t.Fatal("no pid line")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	t.Cleanup(func() { killPID(pid) })
	select {
	case <-tree.Exited():
	case <-time.After(3 * time.Second):
		t.Fatal("leader death not observed while a descendant holds the pipe")
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, tree.Stdout())
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if !errors.Is(err, errStreamDrainBound) {
			t.Fatalf("stream ended with %v, want the drain bound error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reader stayed blocked behind a descendant holding stdout")
	}
	<-tree.Done()
	if processGone(pid) {
		t.Fatal("background work was killed although the policy said leave it")
	}
	if rec.count() != 0 {
		t.Fatalf("unexpected signals: %d", rec.count())
	}
}

// A4: exit without a final stops the whole tree.
func TestTreeStopOnExitKillsDescendants(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "sleep 300 & echo $!; exit 0", func() bool { return true }, rec, 300*time.Millisecond)
	pids := readPIDs(t, tree, 1)
	t.Cleanup(func() { killPID(pids[0]) })
	<-tree.Done()
	if !waitGone(pids[0], 3*time.Second) {
		t.Fatal("descendant survived a stop-on-exit leader exit")
	}
	if rec.count() == 0 {
		t.Fatal("no signal was sent, so the check proved nothing")
	}
}

// Review finding 1: a leader that prints its final and exits immediately, with a
// consumer that is slow to read it, must keep its background work. The decision
// waits for the consumer; deciding at reap would kill it.
func TestTreeFinalReadAfterExitKeepsBackgroundWork(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	rec := &signalRecorder{}
	var final atomic.Bool
	script := "sleep 300 & echo $! > " + pidFile + "; echo final; exit 0"
	tree := shellTree(t, script, func() bool { return !final.Load() }, rec, 300*time.Millisecond)
	pid := pidFromFile(t, pidFile)
	t.Cleanup(func() { killPID(pid) })
	select {
	case <-tree.Exited():
	case <-time.After(3 * time.Second):
		t.Fatal("exit not observed")
	}
	time.Sleep(500 * time.Millisecond) // slow consumer: the leader is long gone
	scanner := bufio.NewScanner(tree.Stdout())
	for scanner.Scan() {
		if scanner.Text() == "final" {
			final.Store(true)
		}
	}
	<-tree.Done()
	if !final.Load() {
		t.Fatal("the final frame was lost")
	}
	if processGone(pid) {
		t.Fatal("background work was killed although the final was recorded")
	}
	if rec.count() != 0 {
		t.Fatalf("unexpected signals: %d", rec.count())
	}
}

// Review finding 2: a slow consumer must receive every byte already in the pipe
// even when a descendant keeps the pipe open past the drain bound.
func TestTreeSlowConsumerLosesNoBytes(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	rec := &signalRecorder{}
	const size = 40000
	script := "sleep 300 & echo $! > " + pidFile + "; head -c " + strconv.Itoa(size) + " /dev/zero; exit 0"
	tree := shellTree(t, script, func() bool { return false }, rec, 200*time.Millisecond)
	pid := pidFromFile(t, pidFile)
	t.Cleanup(func() { killPID(pid) })
	var got bytes.Buffer
	buf := make([]byte, 4096)
	for first := true; ; first = false {
		if first {
			time.Sleep(700 * time.Millisecond) // longer than the drain bound
		}
		n, err := tree.Stdout().Read(buf)
		got.Write(buf[:n])
		if err != nil {
			if !errors.Is(err, errStreamDrainBound) && err != io.EOF {
				t.Fatalf("unexpected stream error %v", err)
			}
			break
		}
	}
	if got.Len() != size {
		t.Fatalf("received %d bytes, want %d", got.Len(), size)
	}
}

// A stderr-holding descendant must not hang Wait, and a clean exit must not be
// reported as a failure because of the wait delay.
func TestTreeStderrHolderDoesNotHangWait(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	rec := &signalRecorder{}
	var sink bytes.Buffer
	tree := shellTreeOpts(t, "sleep 300 >/dev/null & echo $! > "+pidFile+"; exit 0", func() bool { return false }, rec, 100*time.Millisecond, &lockedWriter{w: &sink})
	pid := pidFromFile(t, pidFile)
	t.Cleanup(func() { killPID(pid) })
	discardStream(tree)
	select {
	case <-tree.Done():
	case <-time.After(4 * time.Second):
		t.Fatal("Wait hung behind a descendant holding stderr")
	}
	if err := tree.Err(); err != nil {
		t.Fatalf("clean leader exit reported as %v", err)
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// A3 and the group rule: terminate reaches every member of the group.
func TestTreeTerminateStopsWholeGroup(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "sleep 300 & echo $!; sleep 300 & echo $!; wait", nil, rec, 100*time.Millisecond)
	pids := readPIDs(t, tree, 2)
	t.Cleanup(func() { killPID(pids[0]); killPID(pids[1]) })
	if !tree.Terminate(2 * time.Second) {
		t.Fatal("Terminate reported nothing to stop")
	}
	for _, pid := range pids {
		if !waitGone(pid, 3*time.Second) {
			t.Fatalf("group member %d survived Terminate", pid)
		}
	}
	if rec.count() == 0 {
		t.Fatal("no signal recorded")
	}
}

// Escalation: a leader that ignores the polite signal is killed after grace, in
// bounded time.
func TestTreeTerminateEscalatesToKill(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "trap '' TERM; echo ready; while :; do sleep 1; done", nil, rec, 100*time.Millisecond)
	ready := bufio.NewScanner(tree.Stdout())
	if !ready.Scan() {
		t.Fatal("child never became ready")
	}
	discardStream(tree)
	start := time.Now()
	finished := make(chan struct{})
	go func() { tree.Terminate(300 * time.Millisecond); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Terminate never escalated to a kill; the leader ignores the polite signal")
	}
	elapsed := time.Since(start)
	if elapsed < 250*time.Millisecond {
		t.Fatalf("returned in %v, before the grace period", elapsed)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) < 2 || rec.calls[0] || !rec.calls[len(rec.calls)-1] {
		t.Fatalf("want polite then force, got %v", rec.calls)
	}
}

func legacyShellTree(t *testing.T, script string, rec *signalRecorder, legacy bool) *processTree {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	configureProcess(cmd)
	tree, err := startProcessTreeWith(cmd, nil, processTreeOptions{Signal: rec.signal, WaitDelay: 200 * time.Millisecond, Drain: 200 * time.Millisecond, ConsumeGrace: 3 * time.Second, ForceLegacy: legacy})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// Production passes no stopOnExit policy and settles the tree with Release.
// A leave verdict must keep background work, on the pinned path and on a platform
// without exit observation; a stop verdict must end it.
func TestTreeReleaseVerdictDecidesWithoutPolicy(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, stop := range []bool{false, true} {
			name := map[bool]string{false: "pinned", true: "legacy"}[legacy] + "/" + map[bool]string{false: "leave", true: "stop"}[stop]
			t.Run(name, func(t *testing.T) {
				rec := &signalRecorder{}
				tree := legacyShellTree(t, "sleep 300 & echo $!; exit 0", rec, legacy)
				pids := readPIDs(t, tree, 1)
				t.Cleanup(func() { killPID(pids[0]) })
				<-tree.Exited()
				time.Sleep(300 * time.Millisecond) // the verdict arrives after the exit
				tree.Release(stop)
				<-tree.Done()
				if stop {
					if !waitGone(pids[0], 3*time.Second) {
						t.Fatal("stop verdict left the descendant running")
					}
				} else if processGone(pids[0]) {
					t.Fatal("leave verdict killed background work")
				}
			})
		}
	}
}
