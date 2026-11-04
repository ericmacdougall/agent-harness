// Package cli implements `harness tickets ...`, the Phase 0a ledger command line.
package cli

import (
	"fmt"
	"strings"
)

// spec describes one command's flags: name -> takes a value. Repeatable value flags collect every value.
type spec map[string]bool

type parsed struct {
	flags map[string][]string
	pos   []string
}

func (p parsed) has(name string) bool { _, ok := p.flags[name]; return ok }

func (p parsed) get(name string) string {
	v := p.flags[name]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func (p parsed) all(name string) []string { return p.flags[name] }

// usageErr is reported with exit 2.
type usageErr struct{ msg string }

func (e usageErr) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageErr{fmt.Sprintf(format, a...)} }

// parseArgs accepts --flag, --flag=value and --flag value anywhere; "--" ends flags. Unknown flags and
// abbreviations are errors.
func parseArgs(args []string, s spec) (parsed, error) {
	p := parsed{flags: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			p.pos = append(p.pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "--") || a == "-" {
			p.pos = append(p.pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(a[2:], "=")
		takes, ok := s[name]
		if !ok {
			return p, usagef("unrecognized option --%s", name)
		}
		if !takes {
			if hasVal {
				return p, usagef("option --%s takes no value", name)
			}
			p.flags[name] = append(p.flags[name], "")
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return p, usagef("option --%s needs a value", name)
			}
			i++
			val = args[i]
		}
		p.flags[name] = append(p.flags[name], val)
	}
	return p, nil
}
