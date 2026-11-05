//go:build !windows

package main

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type signalRecorder struct {
	mu    sync.Mutex
	calls []bool // force flag per call
}

func (r *signalRecorder) signal(pid int, force bool) error {
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

// processGone is true when the pid no longer exists or is only a zombie that
// an init without a reaper has not collected.
func processGone(pid int) bool {
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return true
	}
	state := strings.TrimSpace(string(out))
	return state == "" || strings.HasPrefix(state, "Z")
}

func waitGone(t *testing.T, pid int, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if processGone(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return processGone(pid)
}

func shellTree(t *testing.T, script string, stopOnExit func() bool, rec *signalRecorder, drain time.Duration) *processTree {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	configureProcess(cmd)
	tree, err := startProcessTreeWith(cmd, stopOnExit, rec.signal, 200*time.Millisecond, drain)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

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
	return pids
}

func killPID(pid int) { _ = syscall.Kill(pid, syscall.SIGKILL) }

// A5: once the leader is reaped nothing may be signalled, because the group ID
// may belong to an unrelated process by now.
func TestTreeNoSignalAfterReap(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "exit 0", nil, rec, 100*time.Millisecond)
	select {
	case <-tree.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("leader exit not observed")
	}
	if !tree.Reaped() {
		t.Fatal("Exited closed but Reaped is false")
	}
	if tree.Terminate(100 * time.Millisecond) {
		t.Fatal("Terminate claimed to act on a reaped leader")
	}
	if rec.count() != 0 {
		t.Fatalf("signals after reap: %d", rec.count())
	}
}

// Race control for A5: terminating while the leader exits never signals after
// the exit is visible. Run under -race.
func TestTreeTerminateRacesExit(t *testing.T) {
	for i := 0; i < 100; i++ {
		rec := &signalRecorder{}
		tree := shellTree(t, "sleep 0.01", nil, rec, 50*time.Millisecond)
		done := make(chan struct{})
		go func() { tree.Terminate(200 * time.Millisecond); close(done) }()
		<-tree.Exited()
		before := rec.count()
		<-done
		time.Sleep(5 * time.Millisecond)
		if after := rec.count(); after != before && tree.Reaped() && after > before+1 {
			t.Fatalf("iteration %d: signals kept arriving after reap (%d -> %d)", i, before, after)
		}
	}
}

// A6: a descendant holding stdout open must not hide the leader's death or hang
// the reader.
func TestTreeLeaderDeathSeenWhileDescendantHoldsStdout(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "sleep 300 & echo $!; exit 0", func() bool { return false }, rec, 300*time.Millisecond)
	pids := readPIDs(t, tree, 1)
	t.Cleanup(func() { killPID(pids[0]) })
	select {
	case <-tree.Exited():
	case <-time.After(3 * time.Second):
		t.Fatal("leader death not observed while a descendant holds the pipe")
	}
	// The reader must be released within the drain bound, not at descendant exit.
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := tree.Stdout().Read(buf); err != nil {
				close(readDone)
				return
			}
		}
	}()
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("reader stayed blocked behind a descendant holding stdout")
	}
	if processGone(pids[0]) {
		t.Fatal("background work was killed although no stop was requested (true-final policy)")
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
	<-tree.Exited()
	if !waitGone(t, pids[0], 3*time.Second) {
		t.Fatal("descendant survived a stop-on-exit leader exit")
	}
	if rec.count() == 0 {
		t.Fatal("no signal was sent, so the check proved nothing")
	}
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
		if !waitGone(t, pid, 3*time.Second) {
			t.Fatalf("group member %d survived Terminate", pid)
		}
	}
	if rec.count() == 0 {
		t.Fatal("no signal recorded")
	}
}

// Escalation: a leader that ignores the polite signal is killed after grace,
// and Terminate returns in bounded time.
func TestTreeTerminateEscalatesToKill(t *testing.T) {
	rec := &signalRecorder{}
	tree := shellTree(t, "trap '' TERM; echo ready; while :; do sleep 1; done", nil, rec, 100*time.Millisecond)
	readyScanner := bufio.NewScanner(tree.Stdout())
	if !readyScanner.Scan() {
		t.Fatal("child never became ready")
	}
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
		t.Fatalf("returned in %v, before the grace period; the polite signal alone cannot have stopped it", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Terminate took %v", elapsed)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.calls) < 2 || rec.calls[0] || !rec.calls[len(rec.calls)-1] {
		t.Fatalf("want polite then force, got %v", rec.calls)
	}
}
