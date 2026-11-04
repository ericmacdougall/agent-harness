// Command harness is the multi-call Go implementation of agent-harness (GoodQA #35674).
// P0: only the grammar, version and fail-safe refusals exist; no component is ported, so no hook or
// helper is dispatched here yet and Python remains authoritative.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/ericmacdougall/agent-harness/internal/cli"
	"github.com/ericmacdougall/agent-harness/internal/guard"
	"github.com/ericmacdougall/agent-harness/internal/pycompat"
)

// version is set by the release build with -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

// gateSubcommands refuse actions; anything that goes wrong in them must block, never allow.
var gateSubcommands = map[string]bool{"commit-policy": true, "spec-flow": true}

func main() { guard.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(argv []string, stdout, stderr io.Writer) int {
	g, err := cli.Parse(argv)
	surface := g.Sub
	gate := gateSubcommands[g.Sub] && len(g.Args) > 0 && g.Args[0] == "hook"
	if err != nil {
		fmt.Fprintln(stderr, cli.Usage)
		fmt.Fprintf(stderr, "harness: error: %s\n", err)
		return 2
	}
	return guard.Run(surface, gate, stderr, func() int {
		switch g.Sub {
		case "version":
			return versionCmd(g.Args, stdout, stderr)
		case "__panic_for_test":
			if os.Getenv("HARNESS_TEST_PANIC") == "1" {
				panic("forced")
			}
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
