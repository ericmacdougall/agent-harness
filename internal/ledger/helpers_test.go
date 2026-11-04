package ledger_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bin is the harness binary built once for the black-box tests (a development build, so the
// HARNESS_LEDGER_FAKE_* test hooks are honoured).
var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ledger-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin = filepath.Join(dir, "harness")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	out, err := exec.Command("go", "build", "-o", bin, "github.com/ericmacdougall/agent-harness/cmd/harness").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// world is an isolated HOME plus a git repository.
type world struct {
	t    *testing.T
	home string
	repo string
	env  []string
}

func gitEnv(home string) []string {
	return []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "TZ=UTC", "LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "HARNESS_LEDGER_FAKE_MACHINE_ID=machine-A"}
}

func newWorld(t *testing.T) *world {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("0a black-box tests need POSIX file modes and flock (Windows: compile + lock primitive only)")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, home: filepath.Join(root, "home"), repo: filepath.Join(root, "repo")}
	os.MkdirAll(w.home, 0o700)
	os.MkdirAll(w.repo, 0o755)
	w.env = gitEnv(w.home)
	w.git(w.repo, "init", "-q", "-b", "main")
	return w
}

// git runs git with the world's environment and fails the test on error.
func (w *world) git(dir string, args ...string) string {
	w.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir, cmd.Env = dir, w.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

type result struct {
	code           int
	stdout, stderr string
}

// run executes the harness binary in dir with the world's env plus extra.
func (w *world) run(dir string, extra []string, args ...string) result {
	w.t.Helper()
	return w.runStdin(dir, extra, "", args...)
}

func (w *world) runStdin(dir string, extra []string, stdin string, args ...string) result {
	w.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, w.env...), extra...)
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		w.t.Fatal(err)
	}
	return result{code, o.String(), e.String()}
}

// ok runs a tickets command that must succeed.
func (w *world) ok(dir string, extra []string, args ...string) string {
	w.t.Helper()
	r := w.run(dir, extra, append([]string{"tickets"}, args...)...)
	if r.code != 0 {
		w.t.Fatalf("tickets %v: exit %d\nstdout %s\nstderr %s", args, r.code, r.stdout, r.stderr)
	}
	return r.stdout
}

func (w *world) jsonOK(dir string, extra []string, args ...string) map[string]any {
	w.t.Helper()
	out := w.ok(dir, extra, append(args, "--json")...)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		w.t.Fatalf("tickets %v: not JSON: %q", args, out)
	}
	return m
}

// newTicket creates a ticket and returns its handle.
func (w *world) newTicket(dir string, extra []string, title string, more ...string) string {
	w.t.Helper()
	m := w.jsonOK(dir, extra, append([]string{"new", "--title", title}, more...)...)
	return m["ticket"].(map[string]any)["handle"].(string)
}

func (w *world) commonDir() string {
	return strings.TrimSpace(w.git(w.repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
}

func (w *world) ownRefs() []string {
	out := strings.TrimSpace(w.git(w.repo, "for-each-ref", "--format=%(refname)", "refs/goodqa/"))
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func titles(m map[string]any) []string {
	var out []string
	for _, x := range m["tickets"].([]any) {
		out = append(out, x.(map[string]any)["title"].(string))
	}
	return out
}
