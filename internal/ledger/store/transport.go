package store

// Phase 0b transport: the only place a ledger git call may leave this machine. It is a separate
// environment from Env (which keeps protocol.allow=never so mirror work can never become a network
// request): ssh, https and file only, fsck on every transferred object, hooks off, no credential helper,
// no prompt, and a URL that is validated before git ever sees it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/gitx"
	"github.com/ericmacdougall/agent-harness/internal/proc"
)

// Transport bounds.
const (
	MaxRemoteLedgerRefs = 128
	FetchTimeout        = 120 * time.Second
	// MaxLsRemoteBytes caps what a remote may stream while listing refs (128 refs need about 20 KiB).
	MaxLsRemoteBytes = 256 << 10
)

var transportSettings = append(append([]gitx.Setting{}, ledgerSettings...),
	gitx.Setting{Key: "protocol.allow", Value: "never"},
	gitx.Setting{Key: "protocol.file.allow", Value: "always"},
	gitx.Setting{Key: "protocol.ssh.allow", Value: "always"},
	gitx.Setting{Key: "protocol.https.allow", Value: "always"},
	gitx.Setting{Key: "protocol.ext.allow", Value: "never"},
	gitx.Setting{Key: "protocol.fd.allow", Value: "never"},
	gitx.Setting{Key: "transfer.fsckObjects", Value: "true"},
	gitx.Setting{Key: "core.hooksPath", Value: gitx.DevNull},
	gitx.Setting{Key: "core.fsmonitor", Value: "false"},
)

// TransportEnv is the environment for push, fetch and ls-remote against a remote.
func TransportEnv(extra ...string) []string { return TransportEnvWith(nil, extra...) }

var (
	namedHelper = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
	pathHelper  = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)
)

// SafeHelpers keeps only credential helpers that cannot run an arbitrary command line: a bare helper name
// (osxkeychain, store, cache, manager, ...) or an absolute path without arguments. Shell helpers ("!cmd"),
// arguments and anything else are dropped.
func SafeHelpers(in []string) []string {
	var out []string
	for _, h := range in {
		if namedHelper.MatchString(h) || pathHelper.MatchString(h) {
			out = append(out, h)
		}
	}
	return out
}

// TransportEnvWith is TransportEnv plus the given (already vetted) credential helpers. Nothing else from the
// user's git configuration is read.
func TransportEnvWith(helpers []string, extra ...string) []string {
	settings := transportSettings
	if len(helpers) > 0 {
		settings = append(append([]gitx.Setting{}, transportSettings...), gitx.Setting{Key: "credential.helper", Value: ""})
		for _, h := range SafeHelpers(helpers) {
			settings = append(settings, gitx.Setting{Key: "credential.helper", Value: h})
		}
	}
	env := gitx.Default(gitx.Options{Isolated: true, Settings: settings})
	add := []string{"LC_ALL=C", "SSH_ASKPASS_REQUIRE=never", "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes",
		"GIT_ALLOW_PROTOCOL=ssh:https:file"}
	if runtime.GOOS != "windows" {
		add = append(add, "GIT_ASKPASS=/usr/bin/false", "SSH_ASKPASS=/usr/bin/false")
	}
	return append(append(env, add...), extra...)
}

func (g *Git) runT(timeout time.Duration, args ...string) ([]byte, error) {
	argv := append([]string{"git", "--git-dir=" + g.GitDir}, args...)
	res, err := proc.Run(argv, proc.Options{Env: TransportEnvWith(g.Helpers), Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("git %s could not run or timed out: %w", args[0], err)
	}
	if res.Code != 0 {
		return res.Stdout, &GitError{Sub: args[0], Code: res.Code, Stderr: string(res.Stderr)}
	}
	return res.Stdout, nil
}

var (
	scpURL   = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:[^/:\\\s-][^\s]*$`)
	unsafeCh = regexp.MustCompile(`[\x00-\x20\x7f\\]`)
)

// ValidateURL accepts ssh://, https:// and file:// URLs, scp-style host:path and absolute local paths, and
// refuses anything that could select a remote helper or an option: a leading dash, "::" (ext::, fd::,
// transport::), other schemes, embedded credentials, control characters and relative paths.
func ValidateURL(u string) error {
	switch {
	case u == "" || len(u) > 2048:
		return errors.New("remote URL is empty or too long")
	case strings.HasPrefix(u, "-"):
		return errors.New("remote URL may not start with a dash")
	case strings.Contains(u, "::"):
		return errors.New("remote helper URLs (ext::, fd::, transport::) are refused")
	case unsafeCh.MatchString(u):
		return errors.New("remote URL holds control characters, spaces or backslashes")
	}
	if i := strings.Index(u, "://"); i >= 0 {
		pu, err := url.Parse(u)
		if err != nil || pu.Host == "" && pu.Scheme != "file" {
			return errors.New("remote URL is malformed")
		}
		switch pu.Scheme {
		case "ssh", "https":
			if pu.User != nil {
				if _, hasPw := pu.User.Password(); hasPw {
					return errors.New("remote URLs with embedded credentials are refused")
				}
			}
			if strings.HasPrefix(pu.Host, "-") || (pu.User != nil && strings.HasPrefix(pu.User.Username(), "-")) {
				return errors.New("remote user and host may not start with a dash")
			}
			return nil
		case "file":
			if !strings.HasPrefix(pu.Path, "/") || (pu.Host != "" && pu.Host != "localhost") {
				return errors.New("file URL must be an absolute local path")
			}
			return nil
		}
		return fmt.Errorf("remote scheme %q is not allowed (ssh, https and file only)", pu.Scheme)
	}
	if filepath.IsAbs(u) {
		return nil
	}
	if scpURL.MatchString(u) {
		return nil
	}
	return errors.New("remote URL must be ssh://, https://, file://, user@host:path or an absolute path")
}

// LsRemote lists refs of remote matching pattern, refusing more than MaxRemoteLedgerRefs.
func (g *Git) LsRemote(remote, pattern string) (map[string]string, error) {
	if err := ValidateURL(remote); err != nil {
		return nil, err
	}
	out, err := g.runCapped(FetchTimeout, MaxLsRemoteBytes, "ls-remote", "--refs", "--", remote, pattern)
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, l := range lines(out) {
		oid, name, ok := strings.Cut(l, "\t")
		if !ok {
			continue
		}
		refs[name] = oid
		if len(refs) > MaxRemoteLedgerRefs {
			return nil, fmt.Errorf("the remote lists more than %d ledger refs; refusing", MaxRemoteLedgerRefs)
		}
	}
	return refs, nil
}

// FetchRefspec fetches one refspec (no tags, no FETCH_HEAD) from a validated remote into g.
func (g *Git) FetchRefspec(remote, refspec string) error {
	if err := ValidateURL(remote); err != nil {
		return err
	}
	_, err := g.runT(FetchTimeout, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules", "--", remote, refspec)
	return err
}

// PushRefs pushes refs (name:name, never forced) from g to a validated remote.
func (g *Git) PushRefs(remote string, refs []string) error {
	if err := ValidateURL(remote); err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}
	args := []string{"push", "--porcelain", "--no-verify", "--no-follow-tags", "--", remote}
	for _, r := range refs {
		if strings.HasPrefix(r, "+") || !strings.HasPrefix(r, RefPrefix) {
			return errors.New("only ledger refs are pushed, and never forced")
		}
		args = append(args, r+":"+r)
	}
	_, err := g.runT(TransportTimeout, args...)
	return err
}

// PushForeign copies one validated foreign writer ref from g into the repository at repo as a plain
// fast-forward (a rewritten history is refused by git itself). Like PushToRepo, it runs inside g so only
// g's own configuration decides where the data goes.
func (g *Git) PushForeign(repo, ref string) error {
	if !filepath.IsAbs(repo) || !filepath.IsAbs(g.GitDir) {
		return errors.New("paths must be absolute")
	}
	_, err := g.run(TransportTimeout, nil, nil, "push", "--quiet", "--no-verify", "--porcelain",
		"--receive-pack=git -c core.hooksPath="+gitx.DevNull+" -c receive.autogc=false -c receive.denyNonFastForwards=true"+
			" -c receive.denyDeletes=true -c receive.advertiseAlternates=false -c receive.fsckObjects=true"+
			" -c core.alternateRefsCommand=true receive-pack",
		repo, ref+":"+ref)
	return err
}

// DirSize sums the sizes of regular files under dir (best effort).
func DirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, e := d.Info(); e == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// ErrFetchTooBig means the fetch grew past its size cap and was stopped.
var ErrFetchTooBig = errors.New("the fetch exceeded its size cap and was stopped")

// FetchCapped is FetchRefspec with a watchdog: git offers no portable pack-size cap, so this stops the
// fetch once the (disposable) git directory holds more than maxBytes.
func (g *Git) FetchCapped(remote, refspec string, maxBytes int64) error {
	if err := ValidateURL(remote); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), FetchTimeout)
	defer cancel()
	argv := []string{"git", "--git-dir=" + g.GitDir, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head",
		"--no-recurse-submodules", "--", remote, refspec}
	stderr := &limitedWriter{max: 32 << 10}
	type runResult struct {
		res proc.Result
		err error
	}
	done := make(chan runResult, 1)
	go func() {
		res, err := proc.RunContext(ctx, argv, proc.Options{
			Env: TransportEnvWith(g.Helpers), Stdout: io.Discard, Stderr: stderr,
		})
		done <- runResult{res: res, err: err}
	}()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case result := <-done:
			if result.err != nil {
				if errors.Is(result.err, context.DeadlineExceeded) || errors.Is(result.err, proc.ErrTimeout) {
					return fmt.Errorf("git fetch timed out after %s", FetchTimeout)
				}
				return fmt.Errorf("git fetch could not run: %w", result.err)
			}
			if result.res.Code != 0 {
				return &GitError{Sub: "fetch", Code: 1, Stderr: stderr.String()}
			}
			if DirSize(g.GitDir) > maxBytes {
				return ErrFetchTooBig
			}
			return nil
		case <-tick.C:
			if DirSize(g.GitDir) > maxBytes {
				cancel()
				<-done
				return ErrFetchTooBig
			}
		}
	}
}

type limitedWriter struct {
	mu  sync.Mutex
	b   bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.max - w.b.Len(); room > 0 {
		if len(p) > room {
			w.b.Write(p[:room])
		} else {
			w.b.Write(p)
		}
	}
	return len(p), nil
}

func (w *limitedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// ErrOutputTooBig means a transport command produced more output than allowed and was stopped.
var ErrOutputTooBig = errors.New("the remote's listing exceeded its output cap (output cap); refusing")

// runCapped is runT with a hard cap on stdout: past maxOut bytes the whole process group is killed.
func (g *Git) runCapped(timeout time.Duration, maxOut int, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out := &capWriter{max: maxOut, cancel: cancel}
	stderr := &limitedWriter{max: 32 << 10}
	argv := append([]string{"git", "--git-dir=" + g.GitDir}, args...)
	res, err := proc.RunContext(ctx, argv, proc.Options{
		Env: TransportEnvWith(g.Helpers), Stdout: out, Stderr: stderr,
	})
	if out.Over() {
		return nil, ErrOutputTooBig
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, proc.ErrTimeout) {
			return nil, fmt.Errorf("git %s timed out after %s", args[0], timeout)
		}
		return out.Bytes(), &GitError{Sub: args[0], Code: 1, Stderr: stderr.String()}
	}
	if res.Code != 0 {
		return out.Bytes(), &GitError{Sub: args[0], Code: 1, Stderr: stderr.String()}
	}
	return out.Bytes(), nil
}

type capWriter struct {
	mu     sync.Mutex
	b      bytes.Buffer
	max    int
	over   bool
	cancel context.CancelFunc
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.b.Len()+len(p) > w.max {
		w.over = true
		w.cancel()
		return len(p), nil
	}
	return w.b.Write(p)
}

func (w *capWriter) Over() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.over
}

func (w *capWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.b.Bytes()...)
}
