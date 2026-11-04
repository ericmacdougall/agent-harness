// Package store keeps ledger ops as pack commits on hidden refs and reads them back with validation.
// Every git call goes through one wrapper (Git.run): the git on PATH, an isolated gitx environment (no
// global/system config, hooks pointed at the null device, no signing, no prompts, no lazy fetch, no auto
// maintenance), a hard deadline, and --git-dir pinned to the ledger's common dir.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/gitx"
	"github.com/ericmacdougall/agent-harness/internal/proc"
)

// Timeouts for local and transport git calls.
const (
	LocalTimeout     = 20 * time.Second
	TransportTimeout = 120 * time.Second
)

// Identity of every pack commit.
const (
	CommitName  = "goodqa-ledger"
	CommitEmail = "ledger@goodqa.invalid"
)

// Settings added on top of gitx.BaseSettings for every ledger git call.
var ledgerSettings = []gitx.Setting{{Key: "maintenance.auto", Value: "false"}, {Key: "gc.auto", Value: "0"},
	{Key: "protocol.version", Value: "2"}, {Key: "core.askPass", Value: ""}, {Key: "credential.helper", Value: ""}}

// GitError is a failed git invocation. Its text names the subcommand and exit code only (stderr can
// carry paths and remote URLs).
type GitError struct {
	Sub    string
	Code   int
	Stderr string
}

func (e *GitError) Error() string { return fmt.Sprintf("git %s failed (exit %d)", e.Sub, e.Code) }

// Git runs ledger git commands against one git dir.
type Git struct {
	GitDir string
	// Env, when set, replaces the computed environment (tests use it to prove isolation); never set in
	// production.
	extraEnv []string
}

// Env returns the environment every ledger git call uses.
func Env(extra ...string) []string {
	env := gitx.Default(gitx.Options{Isolated: true, Settings: ledgerSettings})
	add := []string{"LC_ALL=C", "SSH_ASKPASS_REQUIRE=never", "GIT_SSH_COMMAND=ssh -o BatchMode=yes"}
	if runtime.GOOS != "windows" {
		add = append(add, "GIT_ASKPASS=/usr/bin/false", "SSH_ASKPASS=/usr/bin/false")
	}
	return append(append(env, add...), extra...)
}

// run executes git --git-dir=<GitDir> args... with stdin, returning stdout.
func (g *Git) run(timeout time.Duration, stdin []byte, extraEnv []string, args ...string) ([]byte, error) {
	argv := append([]string{"git", "--git-dir=" + g.GitDir}, args...)
	res, err := proc.Run(argv, proc.Options{Env: Env(append(g.extraEnv, extraEnv...)...), Stdin: stdin, Timeout: timeout})
	if err != nil {
		if errors.Is(err, proc.ErrTimeout) {
			return nil, fmt.Errorf("git %s timed out after %s", args[0], timeout)
		}
		return nil, fmt.Errorf("git %s could not run: %w", args[0], err)
	}
	if res.Code != 0 {
		return res.Stdout, &GitError{Sub: args[0], Code: res.Code, Stderr: string(res.Stderr)}
	}
	return res.Stdout, nil
}

// CommonDir resolves the git common dir for cwd, or returns ok=false outside a repository.
func CommonDir(cwd string) (string, bool, error) {
	res, err := proc.Run([]string{"git", "rev-parse", "--path-format=absolute", "--git-common-dir"},
		proc.Options{Dir: cwd, Env: Env(), Timeout: LocalTimeout})
	if err != nil {
		return "", false, fmt.Errorf("git rev-parse could not run: %w", err)
	}
	if res.Code != 0 {
		return "", false, nil
	}
	dir := strings.TrimSpace(string(res.Stdout))
	if !filepath.IsAbs(dir) {
		return "", false, errors.New("git returned a relative common dir")
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", false, err
	}
	return real, true, nil
}

// ObjectFormat returns the hex length of object ids (40 for sha1, 64 for sha256).
func (g *Git) ObjectFormat() (int, error) {
	out, err := g.run(LocalTimeout, nil, nil, "rev-parse", "--show-object-format")
	if err != nil {
		return 0, err
	}
	switch strings.TrimSpace(string(out)) {
	case "sha1":
		return 40, nil
	case "sha256":
		return 64, nil
	}
	return 0, errors.New("unknown object format")
}

// Config reads a repository-local boolean config value (false if unset).
func (g *Git) ConfigBool(key string) bool {
	out, err := g.run(LocalTimeout, nil, nil, "config", "--local", "--type=bool", "--get", key)
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// ConfigGet reads a repository-local config value.
func (g *Git) ConfigGet(key string) string {
	out, _ := g.run(LocalTimeout, nil, nil, "config", "--local", "--get", key)
	return strings.TrimSpace(string(out))
}

// InitBare creates a bare repository at dir with no templates (so no sample or planted hooks), hooks
// pointed at the null device, and the given role recorded in its config.
func InitBare(dir, role string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	res, err := proc.Run([]string{"git", "init", "--quiet", "--bare", "--template=", dir},
		proc.Options{Env: Env(), Timeout: LocalTimeout})
	if err != nil || res.Code != 0 {
		return errors.New("git init --bare failed")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	g := &Git{GitDir: dir}
	for _, kv := range [][2]string{{"core.hooksPath", gitx.DevNull}, {"goodqa.role", role}, {"gc.auto", "0"},
		{"receive.denyNonFastForwards", "true"}, {"receive.denyDeletes", "true"}} {
		if _, err := g.run(LocalTimeout, nil, nil, "config", "--local", kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

func zeroOID(n int) string { return strings.Repeat("0", n) }

func trimOID(b []byte, n int) (string, error) {
	s := strings.TrimSpace(string(b))
	if len(s) != n || strings.Trim(s, "0123456789abcdef") != "" {
		return "", errors.New("git returned a malformed object id")
	}
	return s, nil
}

func lines(b []byte) []string {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

var _ = bytes.Equal
