// Package cli parses the harness global grammar with argparse-compatible observable behaviour:
// usage errors exit 2 with a "usage:" line on stderr, and both --opt=value and --opt value are accepted.
package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Hosts the harness supports as first-class.
var Hosts = []string{"claude", "codex", "cursor"}

// Global holds the canonical prefix: harness --host H --config-dir D [--entry E] <sub> args...
type Global struct {
	Host      string
	ConfigDir string
	Entry     string // "launcher" (default) or "py:<abs path>" for a Python front door
	Sub       string
	Args      []string
}

// UsageError is reported with exit code 2, as argparse does.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

const Usage = "usage: harness --host {claude,codex,cursor} --config-dir DIR [--entry {launcher,py:PATH}] SUBCOMMAND ...\n" +
	"       harness version [--json]\n       harness install --host HOST ...\n       harness tickets COMMAND ...\n       harness ledger-mcp [--slug S]"

// exempt subcommands may run without the global prefix.
// tickets and ledger-mcp are user/agent tools with their own flags; they are never hook entries or
// allow-rule prefixes for gates.
var exempt = map[string]bool{"version": true, "install": true, "tickets": true, "ledger-mcp": true}

func usage(format string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(format, a...)} }

// Parse reads argv (without the program name).
func Parse(argv []string) (Global, error) {
	var g Global
	i := 0
	take := func(name string) (string, error) {
		a := argv[i]
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			i++
			return v, nil
		}
		if i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "--") {
			return "", usage("argument %s: expected one argument", name)
		}
		v := argv[i+1]
		i += 2
		return v, nil
	}
	seen := map[string]bool{}
	for i < len(argv) && strings.HasPrefix(argv[i], "--") {
		name, _, _ := strings.Cut(argv[i], "=")
		if seen[name] {
			return g, usage("argument %s: given twice", name)
		}
		seen[name] = true
		var err error
		switch name {
		case "--host":
			g.Host, err = take(name)
		case "--config-dir":
			g.ConfigDir, err = take(name)
		case "--entry":
			g.Entry, err = take(name)
		default:
			// Abbreviations are deliberately rejected: a hook command must name options exactly.
			return g, usage("unrecognized arguments: %s", argv[i])
		}
		if err != nil {
			return g, err
		}
	}
	if i >= len(argv) {
		return g, usage("the following arguments are required: SUBCOMMAND")
	}
	g.Sub, g.Args = argv[i], argv[i+1:]
	if exempt[g.Sub] && g.Host == "" && g.ConfigDir == "" {
		return g, nil
	}
	if !contains(Hosts, g.Host) {
		return g, usage("argument --host: invalid choice: %q (choose from claude, codex, cursor)", g.Host)
	}
	if g.ConfigDir == "" || !filepath.IsAbs(g.ConfigDir) {
		return g, usage("argument --config-dir: an absolute path is required")
	}
	for _, seg := range strings.FieldsFunc(g.ConfigDir, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == "." || seg == ".." {
			return g, usage("argument --config-dir: path must not contain . or .. segments")
		}
	}
	// Hosts on Windows write either separator; keep one canonical spelling.
	g.ConfigDir = filepath.Clean(g.ConfigDir)
	switch {
	case g.Entry == "", g.Entry == "launcher":
		g.Entry = "launcher"
	case strings.HasPrefix(g.Entry, "py:") && filepath.IsAbs(g.Entry[3:]) && strings.HasSuffix(g.Entry, ".py"):
	default:
		return g, usage("argument --entry: expected launcher or py:<absolute .py path>")
	}
	return g, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// IsUsage reports whether err is a usage error.
func IsUsage(err error) bool {
	var u *UsageError
	return errors.As(err, &u)
}
