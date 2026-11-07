//go:build unix

package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunCappedTimeoutKillsDescendantBeforeReturn(t *testing.T) {
	dir, pidFile := installFakeGit(t, "")
	g := &Git{GitDir: dir}
	_, err := g.runCapped(time.Second, 1024, "ls-remote")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout, got %v", err)
	}
	assertFakeGitDescendantGone(t, pidFile)
}

func TestRunCappedEnforcesOutputCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\nprintf 12345\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	g := &Git{GitDir: dir}
	if out, err := g.runCapped(5*time.Second, 4, "ls-remote"); !errors.Is(err, ErrOutputTooBig) || out != nil {
		t.Fatalf("over cap: got output %q, error %v", out, err)
	}
	out, err := g.runCapped(5*time.Second, 5, "ls-remote")
	if err != nil || string(out) != "12345" {
		t.Fatalf("at cap: got output %q, error %v", out, err)
	}
}

func TestFetchCappedCancellationKillsDescendantBeforeReturn(t *testing.T) {
	gitDir := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, pidFile := installFakeGit(t, "echo payload > "+filepath.Join(gitDir, "payload"))
	g := &Git{GitDir: gitDir}
	err := g.FetchCapped("/remote", "refs/heads/main:refs/remotes/origin/main", 0)
	if !errors.Is(err, ErrFetchTooBig) {
		t.Fatalf("want ErrFetchTooBig, got %v", err)
	}
	assertFakeGitDescendantGone(t, pidFile)
}

func installFakeGit(t *testing.T, beforeWait string) (dir, pidFile string) {
	t.Helper()
	dir = t.TempDir()
	pidFile = filepath.Join(dir, "child.pid")
	script := `#!/bin/sh
(trap '' TERM; exec sleep 60) &
echo $! > ` + pidFile + `
` + beforeWait + `
exec sleep 60
`
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if got, err := exec.LookPath("git"); err != nil || got != filepath.Join(dir, "git") {
		t.Fatalf("fake git not selected: %q %v", got, err)
	}
	return dir, pidFile
}

func assertFakeGitDescendantGone(t *testing.T, pidFile string) {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("fake git did not record its child: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("invalid child pid %q: %v", raw, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	// The kill has already happened when the transport returns; a dead child can still show as a zombie
	// until init reaps it, and kill(pid, 0) succeeds on a zombie. Allow a short bounded reap window and
	// treat a zombie as gone; a live process (any other state) fails.
	deadline := time.Now().Add(time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) || zombie(pid) {
			return
		}
		if err != nil {
			t.Fatalf("checking descendant %d: %v", pid, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d survived transport cancellation", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// zombie reports whether pid is a dead process awaiting its reaper (Linux /proc, else ps).
func zombie(pid int) bool {
	if raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		if i := strings.LastIndexByte(string(raw), ')'); i >= 0 && i+2 < len(raw) {
			return raw[i+2] == 'Z'
		}
		return false
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}
