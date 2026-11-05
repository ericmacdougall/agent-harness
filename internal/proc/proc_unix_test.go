//go:build unix

package proc

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A timed-out command's descendants die too, including one that ignores TERM.
func TestTimeoutKillsTheWholeGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	script := `(trap '' TERM; sleep 60) & echo $! > ` + pidFile + `; sleep 60`
	start := time.Now()
	_, err := Run([]string{"sh", "-c", script}, Options{Timeout: 300 * time.Millisecond})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if elapsed > TerminationGrace+3*time.Second {
		t.Fatalf("took %v", elapsed)
	}
	raw, _ := os.ReadFile(pidFile)
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if perr != nil {
		t.Fatalf("child pid not recorded: %q", raw)
	}
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("TERM-ignoring descendant %d survived the timeout", pid)
	}
}

// A descendant that leaves the group and keeps stdout open makes the call time out (as Python's
// communicate does), and cannot hold Run longer than the deadline, the TERM grace and PipeGrace.
func TestEscapedDescendantTimesOutBounded(t *testing.T) {
	if _, err := os.Stat("/usr/bin/perl"); err != nil {
		t.Skip("perl needed for setsid")
	}
	start := time.Now()
	r, err := Run([]string{"sh", "-c", `perl -e 'use POSIX; setsid(); sleep 30' & echo done`}, Options{Timeout: time.Second})
	if !errors.Is(err, ErrTimeout) || !strings.HasPrefix(string(r.Stdout), "done") {
		t.Fatalf("got %+v %v", r, err)
	}
	if held := time.Since(start); held > time.Second+TerminationGrace+PipeGrace+2*time.Second {
		t.Fatalf("held for %v", held)
	}
}

// A backgrounded descendant in the group that keeps stdout open is not success after the leader exits:
// the call times out and the descendant is killed (red-team M2; tests/test_delivery_process.py contract).
func TestLeaderExitWithPipeHolderTimesOutAndKills(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	script := `(trap '' TERM; sleep 30; echo late) & echo $! > ` + pidFile + `; echo early`
	// The deadline exceeds PipeGrace, so an early "success" when the leader exits cannot hide here.
	r, err := Run([]string{"sh", "-c", script}, Options{Timeout: PipeGrace + 2*time.Second})
	if !errors.Is(err, ErrTimeout) || string(r.Stdout) != "early\n" {
		t.Fatalf("got %+v %v", r, err)
	}
	raw, _ := os.ReadFile(pidFile)
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if perr != nil {
		t.Fatalf("child pid not recorded: %q", raw)
	}
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("pipe-holding descendant %d survived", pid)
	}
}

// Large stdin to a child that never reads it must not hang Run after the child exits.
func TestUnreadStdinDoesNotHang(t *testing.T) {
	r, err := Run([]string{"sh", "-c", "exit 4"}, Options{Stdin: bytes.Repeat([]byte("x"), 1<<20), Timeout: 10 * time.Second})
	if err != nil || r.Code != 4 {
		t.Fatalf("got %+v %v", r, err)
	}
}
