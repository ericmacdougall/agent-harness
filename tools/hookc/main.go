// Command hookc is the thin hook client for hookd (GoodQA goodqa#14859).
//
//	hookc [--budget SECONDS] /abs/path/to/hook.py [args...]
//
// It forwards the hook payload on stdin, with its argv, environment, cwd, umask, pid and ppid, to the
// resident server at $HOOKD_RUN_DIR/hookd.sock (default ~/.agent-harness/run/hookd). It then prints the
// server's stdout and stderr and exits with the hook's exit code.
//
// It never fails open. On any doubt it runs the cold hook itself, `python3 <script> [args...]`, with the same
// stdin, and passes that result through. Doubt covers:
//   - no socket, or a socket or directory not owned by this uid
//   - a socket or directory open to group or others
//   - no accept within 2 s
//   - a timeout, a garbage reply, a size overflow, or a server "fallback" answer
//
// If even the cold hook cannot start, or dies on a signal, a gate hook exits 2 (block) and others exit 1.
package main

import (
	"bytes"
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
)

// gates are the hooks registered with onFailure: block; a client-side failure on them must block.
var gates = map[string]bool{
	"command_guard_hook.py": true, "kill_guard.py": true, "wal.py": true, "tier_gate.py": true,
	"commit_policy.py": true, "spec_flow.py": true, "merge_gate.py": true,
}

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	budget := 20.0
	if len(argv) >= 2 && argv[0] == "--budget" {
		if v, err := strconv.ParseFloat(argv[1], 64); err == nil && v > 0 && v <= 600 {
			budget = v
		}
		argv = argv[2:]
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		fmt.Fprintln(os.Stderr, "usage: hookc [--budget S] /abs/hook.py [args...]")
		return 2
	}
	script, args := argv[0], argv[1:]
	gate := gates[filepath.Base(script)]

	stdin, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdin+1))
	if err != nil {
		return cold(script, args, stdin, gate, "stdin")
	}
	if len(stdin) > maxStdin || os.Getenv("HOOKC_DISABLE") == "1" {
		return cold(script, args, stdin, gate, "")
	}
	code, out, errOut, why := ask(script, args, stdin, budget)
	if why != "" {
		return cold(script, args, stdin, gate, why)
	}
	os.Stdout.Write(out)
	os.Stderr.Write(errOut)
	return code
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

// ask returns the server's verdict, or a non-empty reason to fall back to the cold hook.
func ask(script string, args []string, stdin []byte, budget float64) (int, []byte, []byte, string) {
	dir := runDir()
	sock := filepath.Join(dir, "hookd.sock")
	if dir == "" || !private(dir, os.ModeDir) || !private(sock, os.ModeSocket) {
		return 0, nil, nil, "no-private-socket"
	}
	conn, err := net.DialTimeout("unix", sock, acceptLimit)
	if err != nil {
		return 0, nil, nil, "connect"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(acceptLimit))
	var ack reply
	b, err := readFrame(conn, maxHeader)
	if err != nil || json.Unmarshal(b, &ack) != nil || ack.V != proto {
		return 0, nil, nil, "no-accept"
	}
	if ack.Status == "fallback" {
		return 0, nil, nil, "server:" + ack.Reason
	}
	if ack.Status != "accepted" {
		return 0, nil, nil, "no-accept"
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, nil, nil, "cwd"
	}
	old := syscall.Umask(0o022)
	syscall.Umask(old)
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if i := bytes.IndexByte([]byte(kv), '='); i > 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	header, _ := json.Marshal(map[string]any{
		"v": proto, "script": script, "args": args, "env": env, "cwd": cwd, "umask": old,
		"pid": os.Getpid(), "ppid": os.Getppid(), "budget": budget,
	})
	conn.SetDeadline(time.Now().Add(time.Duration(budget*float64(time.Second)) + 3*time.Second))
	if frame(conn, header) != nil || frame(conn, stdin) != nil {
		return 0, nil, nil, "send"
	}
	var rep reply
	b, err = readFrame(conn, maxHeader)
	if err != nil || json.Unmarshal(b, &rep) != nil || rep.V != proto {
		return 0, nil, nil, "garbage"
	}
	if rep.Status != "ok" || rep.Exit == nil || *rep.Exit < 0 || *rep.Exit > 255 {
		return 0, nil, nil, "server:" + rep.Reason
	}
	out, err := readFrame(conn, maxReply)
	if err != nil {
		return 0, nil, nil, "truncated"
	}
	errOut, err := readFrame(conn, maxReply)
	if err != nil {
		return 0, nil, nil, "truncated"
	}
	return *rep.Exit, out, errOut, ""
}

// cold runs the original hook exactly as the settings entry used to: python3 <script> [args...].
func cold(script string, args []string, stdin []byte, gate bool, why string) int {
	if why != "" && os.Getenv("HOOKC_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "hookc: cold path (%s)\n", why)
	}
	cmd := exec.Command("python3", append([]string{script}, args...)...)
	cmd.Stdin = io.MultiReader(bytes.NewReader(stdin), os.Stdin)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Exited() {
			return ws.ExitStatus()
		}
	}
	fmt.Fprintf(os.Stderr, "hookc: the hook %s could not run (%v)\n", filepath.Base(script), err)
	if gate {
		return 2
	}
	return 1
}
