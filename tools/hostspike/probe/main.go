// probe: spike hook. Usage: probe <mode> [label]. Modes: allow, deny2, crash, sleep, noout,
// cursor-allow, cursor-deny, codex-block-json. Logs one JSON line per call to $PROBE_LOG
// (default ./probe.jsonl): argv, cwd, stdin bytes (base64 + sha256), env marker NAMES only.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var marker = regexp.MustCompile(`^(CLAUDE|CODEX|CURSOR|AI_AGENT|AGENT|VSCODE|TERM_PROGRAM)`)

func main() {
	mode := "allow"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	in, _ := io.ReadAll(os.Stdin)
	sum := sha256.Sum256(in)
	var names []string
	for _, kv := range os.Environ() {
		k := strings.SplitN(kv, "=", 2)[0]
		if marker.MatchString(k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	cwd, _ := os.Getwd()
	rec := map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "argv": os.Args, "cwd": cwd,
		"mode": mode, "stdin_b64": base64.StdEncoding.EncodeToString(in), "stdin_sha256": hex.EncodeToString(sum[:]),
		"stdin_len": len(in), "env_marker_names": names, "pid": os.Getpid(), "ppid": os.Getppid()}
	path := os.Getenv("PROBE_LOG")
	if path == "" {
		path = "probe.jsonl"
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		b, _ := json.Marshal(rec)
		f.Write(append(b, '\n'))
		f.Close()
	}
	switch mode {
	case "deny2":
		fmt.Fprintln(os.Stderr, "PROBE DENY: blocked by spike hook")
		os.Exit(2)
	case "crash":
		panic("probe crash")
	case "sleep":
		time.Sleep(120 * time.Second)
	case "exit1":
		fmt.Fprintln(os.Stderr, "probe exit1")
		os.Exit(1)
	case "garbage":
		fmt.Println("not json {")
	case "noout":
		os.Exit(0)
	case "cursor-allow":
		fmt.Println(`{"permission":"allow"}`)
	case "cursor-deny":
		fmt.Println(`{"permission":"deny","user_message":"PROBE DENY","agent_message":"PROBE DENY: blocked by spike hook"}`)
	case "codex-block-json":
		fmt.Println(`{"decision":"block","reason":"PROBE DENY: blocked by spike hook"}`)
	}
}
