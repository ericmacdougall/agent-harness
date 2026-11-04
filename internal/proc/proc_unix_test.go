//go:build unix

package proc

import (
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

// A descendant that leaves the group and keeps stdout open must not hold Run past PipeGrace.
func TestEscapedDescendantDoesNotHang(t *testing.T) {
	if _, err := os.Stat("/usr/bin/perl"); err != nil {
		t.Skip("perl needed for setsid")
	}
	start := time.Now()
	r, err := Run([]string{"sh", "-c", `perl -e 'use POSIX; setsid(); sleep 30' & echo done`}, Options{Timeout: 20 * time.Second})
	if err != nil || r.Code != 0 || !strings.HasPrefix(string(r.Stdout), "done") {
		t.Fatalf("got %+v %v", r, err)
	}
	if time.Since(start) > PipeGrace+3*time.Second {
		t.Fatalf("held for %v", time.Since(start))
	}
}
