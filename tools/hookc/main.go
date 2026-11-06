// Command hookc is the thin hook client for hookd (GoodQA goodqa#14859).
//
//	hookc [--deadline SECONDS] [--gate] /abs/path/to/hook.py [args...]
//
// It forwards the hook payload on stdin, with its argv, environment, cwd, umask, pid and ppid, to the
// resident server at $HOOKD_RUN_DIR/hookd.sock (default ~/.agent-harness/run/hookd). It then prints the
// server's stdout and stderr and exits with the hook's exit code.
//
// --deadline is the hook's host timeout (settings.json "timeout"). hookc keeps ONE overall deadline, a little
// under it, across the connect, the served run and any cold run, so it always answers before the host gives up
// (a host timeout on a hook without onFailure: block is a non-blocking error, that is an allow). When no verdict
// can be had in time, a gate (--gate, or a name in the gates list) exits 2 (block) and any other hook exits 1.
//
// It never fails open. Before the hook has run anywhere, doubt sends it to the cold hook,
// `python3 <script> [args...]`, with the same stdin. Doubt covers:
//   - no socket, or a socket or directory not owned by this uid
//   - a socket or directory open to group or others
//   - no accept within min(2 s, T/4)
//   - a server "fallback" answer (busy, stale, interpreter, env, locale, ...), a garbage reply or a size overflow
//
// A served run that used up its time (server "timeout", or no reply by the deadline) is not rerun cold: the cold
// run would need the same time again and be cut off by the host. If the cold hook cannot start, dies on a
// signal or passes the deadline, a gate exits 2 and others exit 1.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	proto       = 1
	maxStdin    = 8*1024*1024 + 1
	maxReply    = 4 * 1024 * 1024
	maxHeader   = 64 * 1024
	acceptLimit = 2 * time.Second
	defaultT    = 10.0 // seconds: Claude's default when a settings entry names no timeout
)

// gates are the hooks registered with onFailure: block; a client-side failure on them must block. install.py
// also passes --gate for those and for enforcing hooks without onFailure (provenance ask-gate).
var gates = map[string]bool{
	"command_guard_hook.py": true, "kill_guard.py": true, "wal.py": true, "tier_gate.py": true,
	"commit_policy.py": true, "spec_flow.py": true, "merge_gate.py": true,
}

// call is one hook invocation: what to run and by when.
type call struct {
	script   string
	args     []string
	gate     bool
	limit    float64   // the host timeout T, seconds
	deadline time.Time // when hookc itself must have answered (a margin under T)
}

func main() { os.Exit(run(os.Args[1:], time.Now())) }

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: hookc [--deadline S] [--gate] /abs/hook.py [args...]")
	return 2
}

// margin is how long before the host timeout hookc must be done: the host kills at T, and hookc still has
// to print the verdict and exit.
func margin(limit float64) time.Duration {
	m := limit * 0.1
	if m < 0.2 {
		m = 0.2
	}
	if m > 1 {
		m = 1
	}
	return time.Duration(m * float64(time.Second))
}

func run(argv []string, start time.Time) int {
	c := call{limit: defaultT}
	for len(argv) > 0 && len(argv[0]) > 2 && argv[0][:2] == "--" {
		switch argv[0] {
		case "--gate":
			c.gate = true
			argv = argv[1:]
		case "--deadline", "--budget": // --budget N is the old settings form: the server's 40% share of T
			if len(argv) < 2 {
				return usage()
			}
			v, err := strconv.ParseFloat(argv[1], 64)
			if err != nil || v <= 0 || v > 600 {
				return usage()
			}
			if argv[0] == "--budget" {
				v = v / 0.4
			}
			c.limit = v
			argv = argv[2:]
		default:
			return usage()
		}
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return usage()
	}
	c.script, c.args = argv[0], argv[1:]
	c.gate = c.gate || gates[filepath.Base(c.script)]
	c.deadline = start.Add(time.Duration(c.limit*float64(time.Second)) - margin(c.limit))

	stdin, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdin+1))
	if err != nil {
		return cold(c, stdin, "stdin")
	}
	if len(stdin) > maxStdin || os.Getenv("HOOKC_DISABLE") == "1" {
		return cold(c, stdin, "")
	}
	code, out, errOut, why, spent := ask(c, stdin)
	if spent {
		return noVerdict(c, why)
	}
	if why != "" {
		return cold(c, stdin, why)
	}
	os.Stdout.Write(out)
	os.Stderr.Write(errOut)
	return code
}

// noVerdict ends a call that ran out of time: a gate blocks, any other hook reports a non-blocking error.
func noVerdict(c call, why string) int {
	name := filepath.Base(c.script)
	if c.gate {
		fmt.Fprintf(os.Stderr, "hookc: %s gave no verdict within its %gs hook timeout (%s); blocking "+
			"(fail-closed). Check `hookd.py status` and the host load, then retry.\n", name, c.limit, why)
		return 2
	}
	fmt.Fprintf(os.Stderr, "hookc: %s gave no verdict within its %gs hook timeout (%s)\n", name, c.limit, why)
	return 1
}

func runDir() string {
	if d := os.Getenv("HOOKD_RUN_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".agent-harness", "run", "hookd")
}

// private reports whether path is owned by this uid, has no group/other permission bits, and has the kind want.
func private(path string, want os.FileMode) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() || fi.Mode().Perm()&0o077 != 0 {
		return false
	}
	return fi.Mode().Type() == want
}

func frame(w io.Writer, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(n[:]))
	if size > limit {
		return nil, errors.New("frame too large")
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}

type reply struct {
	V      int    `json:"v"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Exit   *int   `json:"exit"`
}

// python is the interpreter the cold path runs: `python3` on PATH, resolved. hookd answers "fallback:
// interpreter" unless it runs the same file, so a served verdict never comes from another Python.
func python() string {
	p, err := exec.LookPath("python3")
	if err != nil {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return p
}

func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ask returns the server's verdict, or a reason to fall back. spent is true when the hook may already have used
// its time on the server (no reply by the deadline, or a server timeout): then there is no time for a cold run.
func ask(c call, stdin []byte) (code int, out, errOut []byte, why string, spent bool) {
	dir := runDir()
	sock := filepath.Join(dir, "hookd.sock")
	if dir == "" || !private(dir, os.ModeDir) || !private(sock, os.ModeSocket) {
		return 0, nil, nil, "no-private-socket", false
	}
	accept := time.Duration(c.limit / 4 * float64(time.Second))
	if accept > acceptLimit {
		accept = acceptLimit
	}
	acceptBy := time.Now().Add(accept)
	if acceptBy.After(c.deadline) {
		acceptBy = c.deadline
	}
	conn, err := net.DialTimeout("unix", sock, time.Until(acceptBy))
	if err != nil {
		return 0, nil, nil, "connect", false
	}
	defer conn.Close()
	conn.SetDeadline(acceptBy)
	var ack reply
	b, err := readFrame(conn, maxHeader)
	if err != nil || json.Unmarshal(b, &ack) != nil || ack.V != proto {
		return 0, nil, nil, "no-accept", false
	}
	if ack.Status == "fallback" {
		return 0, nil, nil, "server:" + ack.Reason, false
	}
	if ack.Status != "accepted" {
		return 0, nil, nil, "no-accept", false
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, nil, nil, "cwd", false
	}
	old := syscall.Umask(0o022)
	syscall.Umask(old)
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if i := bytes.IndexByte([]byte(kv), '='); i > 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	// The served run gets the time left, less a little for the reply to travel; past the deadline hookc stops
	// waiting whatever the server does.
	budget := time.Until(c.deadline).Seconds() - 0.15
	if budget <= 0 {
		return 0, nil, nil, "deadline", true
	}
	header, _ := json.Marshal(map[string]any{
		"v": proto, "script": c.script, "args": c.args, "env": env, "cwd": cwd, "umask": old,
		"pid": os.Getpid(), "ppid": os.Getppid(), "budget": budget, "python": python(),
	})
	conn.SetDeadline(c.deadline)
	if frame(conn, header) != nil || frame(conn, stdin) != nil {
		return 0, nil, nil, "send", false
	}
	var rep reply
	b, err = readFrame(conn, maxHeader)
	if err != nil && timedOut(err) {
		return 0, nil, nil, "no reply from hookd", true
	}
	if err != nil || json.Unmarshal(b, &rep) != nil || rep.V != proto {
		return 0, nil, nil, "garbage", false
	}
	if rep.Status == "fallback" && rep.Reason == "timeout" {
		return 0, nil, nil, "hookd: timeout", true
	}
	if rep.Status != "ok" || rep.Exit == nil || *rep.Exit < 0 || *rep.Exit > 255 {
		return 0, nil, nil, "server:" + rep.Reason, false
	}
	out, err = readFrame(conn, maxReply)
	if err != nil {
		return 0, nil, nil, "truncated", timedOut(err)
	}
	errOut, err = readFrame(conn, maxReply)
	if err != nil {
		return 0, nil, nil, "truncated", timedOut(err)
	}
	return *rep.Exit, out, errOut, "", false
}

// cold runs the original hook as the settings entry used to, python3 <script> [args...], and stops it at the
// deadline.
func cold(c call, stdin []byte, why string) int {
	if why != "" && os.Getenv("HOOKC_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "hookc: cold path (%s)\n", why)
	}
	if time.Until(c.deadline) <= 0 {
		return noVerdict(c, "no time left for the cold run")
	}
	ctx, cancel := context.WithDeadline(context.Background(), c.deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", append([]string{c.script}, c.args...)...)
	cmd.Stdin = io.MultiReader(bytes.NewReader(stdin), os.Stdin)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.WaitDelay = 100 * time.Millisecond // stop copying stdin once the hook is gone
	err := cmd.Run()
	// A hook that exited on its own gave its verdict, even if the deadline passed just after: only a run that was
	// killed (or never started) after the deadline has none.
	if err == nil {
		return 0
	}
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return cmd.ProcessState.ExitCode() // exited; only the stdin copy was cut short
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Exited() {
			return ws.ExitStatus()
		}
	}
	if ctx.Err() != nil {
		return noVerdict(c, "the cold run passed the deadline")
	}
	fmt.Fprintf(os.Stderr, "hookc: the hook %s could not run (%v)\n", filepath.Base(c.script), err)
	if c.gate {
		return 2
	}
	return 1
}
