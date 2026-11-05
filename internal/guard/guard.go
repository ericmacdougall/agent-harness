// Package guard owns the single top-level recover for every harness surface.
//
// An unrecovered Go panic exits 2, which every host treats as "block" and which collides with usage
// errors. Spikes (2026-11-04, Codex CLI 0.166, Claude Code 2.1.318/2.1.263) also showed that a gate hook
// exiting 1, timing out or printing garbage is FAIL-OPEN on Codex and Claude. So the exit code after a
// crash depends on the surface: a gate (a hook whose job is to refuse an action) fails closed with exit 2
// and a reason on stderr; everything else exits 1 like a Python traceback.
package guard

import (
	"fmt"
	"io"
	"os"
)

const (
	ExitCrash     = 1
	ExitGateBlock = 2
)

// Run calls fn and converts a panic into the surface's crash exit code. The message never includes paths
// or panic values, which may carry user data.
func Run(surface string, gate bool, stderr io.Writer, fn func() int) (code int) {
	defer func() {
		if r := recover(); r != nil {
			if gate {
				fmt.Fprintf(stderr, "harness %s: internal error; refusing the action (fail-closed gate)\n", surface)
				code = ExitGateBlock
				return
			}
			fmt.Fprintf(stderr, "harness %s: internal error\n", surface)
			code = ExitCrash
		}
	}()
	return fn()
}

// Exit is os.Exit, replaceable in tests.
var Exit = os.Exit
