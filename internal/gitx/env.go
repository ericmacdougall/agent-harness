// Package gitx builds the environment the harness runs git with (port of git_safety.git_environment).
// Git is always the git on PATH (plan R1); this package only composes its environment.
package gitx

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// DevNull is Python's os.devnull, which the Python helpers pass to git ("nul" on Windows, not "NUL").
var DevNull = func() string {
	if runtime.GOOS == "windows" {
		return "nul"
	}
	return "/dev/null"
}()

var (
	authEnv     = []string{"GIT_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"}
	identityEnv = []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE"}
)

// Setting is one -c style key/value injected through GIT_CONFIG_COUNT.
type Setting struct{ Key, Value string }

// BaseSettings mirrors BASE_SETTINGS, in order (the order is visible in GIT_CONFIG_KEY_<n>).
func BaseSettings() []Setting {
	return []Setting{{"core.hooksPath", DevNull}, {"core.fsmonitor", "false"}, {"core.filemode", "true"},
		{"core.symlinks", "true"}, {"core.untrackedCache", "false"}, {"core.trustctime", "true"},
		{"core.checkStat", "default"}, {"commit.gpgsign", "false"}, {"tag.gpgsign", "false"}}
}

// Options match git_environment's keyword arguments.
type Options struct {
	Isolated         bool
	AllowHooks       bool
	PreserveIdentity bool
	Settings         []Setting
}

// Environment returns the git environment as a map, built from base (normally os.Environ()).
// Every GIT_* variable is dropped unless retained: auth/config routing (and identity on request) when
// not isolated, nothing when isolated.
func Environment(base []string, o Options) map[string]string {
	retained := map[string]bool{}
	if !o.Isolated {
		for _, k := range authEnv {
			retained[k] = true
		}
		if o.PreserveIdentity {
			for _, k := range identityEnv {
				retained[k] = true
			}
		}
	}
	env := map[string]string{}
	for _, kv := range base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if !strings.HasPrefix(k, "GIT_") || retained[k] {
			env[k] = v
		}
	}
	env["GIT_TERMINAL_PROMPT"] = "0"
	env["GIT_NO_REPLACE_OBJECTS"] = "1"
	env["GIT_NO_LAZY_FETCH"] = "1"
	if o.Isolated {
		env["GIT_CONFIG_NOSYSTEM"] = "1"
		env["GIT_CONFIG_GLOBAL"] = DevNull
	}
	var configured []Setting
	for _, s := range BaseSettings() {
		if o.AllowHooks && s.Key == "core.hooksPath" {
			continue
		}
		configured = append(configured, s)
	}
	configured = append(configured, o.Settings...)
	env["GIT_CONFIG_COUNT"] = strconv.Itoa(len(configured))
	for i, s := range configured {
		env["GIT_CONFIG_KEY_"+strconv.Itoa(i)] = s.Key
		env["GIT_CONFIG_VALUE_"+strconv.Itoa(i)] = s.Value
	}
	return env
}

// Environ is Environment as an exec.Cmd Env slice, sorted for determinism.
func Environ(base []string, o Options) []string {
	m := Environment(base, o)
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// Default is Environ(os.Environ(), o).
func Default(o Options) []string { return Environ(os.Environ(), o) }
