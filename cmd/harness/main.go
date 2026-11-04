// Command harness is the multi-call Go implementation of agent-harness (GoodQA #35674).
// P0: only the grammar, version and fail-safe refusals exist; no component is ported, so no hook or
// helper is dispatched here yet and Python remains authoritative.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/cli"
	"github.com/ericmacdougall/agent-harness/internal/guard"
	ledgercli "github.com/ericmacdougall/agent-harness/internal/ledger/cli"
	"github.com/ericmacdougall/agent-harness/internal/ledger/mcp"
	"github.com/ericmacdougall/agent-harness/internal/ledger/writer"
	"github.com/ericmacdougall/agent-harness/internal/pycompat"
)

// version is set by the release build with -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

//go:embed gates.json
var gatesJSON []byte

// gates maps a subcommand to the verbs that make it a fail-closed hook surface (gates.json, shared with
// tests/test_pyfront.py). Anything that goes wrong in a gate must block, never allow.
var gates = func() map[string][]string {
	var doc struct{ Gates map[string][]string }
	if err := json.Unmarshal(gatesJSON, &doc); err != nil || len(doc.Gates) == 0 {
		panic("harness: invalid embedded gates.json") // caught by TestGateTable at build time
	}
	return doc.Gates
}()

// isGate reports whether sub with args is a gate surface. Any argument matching a verb counts, so a flag
// placed before the verb cannot drop gate status; a CLI call misread as a gate only exits 2 instead of 1.
func isGate(sub string, args []string) bool {
	for _, verb := range gates[sub] {
		for _, a := range args {
			if a == verb {
				return true
			}
		}
	}
	return false
}

// testPanic forces a panic inside guard.Run; only tests set it, so no environment variable can.
var testPanic bool

func main() { guard.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(argv []string, stdout, stderr io.Writer) int {
	g, err := cli.Parse(argv)
	surface := g.Sub
	gate := isGate(g.Sub, g.Args)
	// The commit-policy adapter calls `tickets show --min-version`: a crash there must fail closed (exit 2).
	gate = gate || (g.Sub == "tickets" && len(g.Args) > 0 && g.Args[0] == "show" && hasFlag(g.Args, "--min-version"))
	writer.TestHooksAllowed = version == "dev"
	if err != nil {
		fmt.Fprintln(stderr, cli.Usage)
		fmt.Fprintf(stderr, "harness: error: %s\n", err)
		return 2
	}
	return guard.Run(surface, gate, stderr, func() int {
		if testPanic {
			panic("forced")
		}
		if g.Sub == "version" {
			return versionCmd(g.Args, stdout, stderr)
		}
		switch g.Sub {
		case "tickets":
			return ledgercli.Main(g.Args, ledgerEnv(stdout, stderr))
		case "ledger-mcp":
			return ledgerMCP(g.Args, stdout, stderr)
		}
		if gate {
			// Exit 2 blocks on all three hosts; exit 1/3 would let the action through on Codex and Claude.
			fmt.Fprintf(stderr, "harness %s hook: not ported to Go yet; refusing (switch this hook back to Python)\n", g.Sub)
			return guard.ExitGateBlock
		}
		fmt.Fprintf(stderr, "harness: %s is not ported to Go yet; use the Python helper\n", g.Sub)
		return 3
	})
}

func versionCmd(args []string, stdout, stderr io.Writer) int {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 1 || (len(args) == 1 && !asJSON) {
		fmt.Fprintln(stderr, "usage: harness version [--json]")
		return 2
	}
	rev, modified := "", false
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	self := ""
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(exe); err == nil {
			sum := sha256.Sum256(b)
			self = hex.EncodeToString(sum[:])
		}
	}
	if !asJSON {
		fmt.Fprintf(stdout, "harness %s (%s) %s\n", version, rev, runtime.Version())
		return 0
	}
	out, err := pycompat.Canonical(map[string]any{"version": version, "commit": rev, "modified": modified,
		"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "binary_sha256": self})
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
		if a == "--" {
			break
		}
	}
	return false
}

func ledgerEnv(stdout, stderr io.Writer) ledgercli.Env {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	return ledgercli.Env{Cwd: cwd, Stdin: os.Stdin, Stdout: stdout, Stderr: stderr, Getenv: os.Getenv}
}

func ledgerMCP(args []string, stdout, stderr io.Writer) int {
	slug := ""
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case strings.HasPrefix(a, "--slug="):
			slug = a[len("--slug="):]
		case a == "--slug" && i+1 < len(args):
			slug = args[i+1]
			i++
		default:
			fmt.Fprintln(stderr, "usage: harness ledger-mcp [--slug S]")
			return 2
		}
	}
	s := &mcp.Server{Env: ledgerEnv(io.Discard, io.Discard), Slug: slug}
	if err := s.Serve(os.Stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "harness ledger-mcp: stdin error")
		return 1
	}
	return 0
}
