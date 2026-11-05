package gitx

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var base = []string{"HOME=/h", "PATH=/bin", "GIT_DIR=/evil", "GIT_INDEX_FILE=/i", "GIT_SSH_COMMAND=ssh -i k",
	"GIT_CONFIG_GLOBAL=/g", "GIT_AUTHOR_NAME=A", "GIT_CONFIG_COUNT=9", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_WORK_TREE=/w",
	"GITHUB_TOKEN=keep-not-git-prefixed"}

// Cross-implementation: the Go environment equals Python git_safety.git_environment for every option set.
func TestMatchesPythonGitEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Python git helpers do not run on Windows (plan D2)")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	hooks, _ := filepath.Abs("../../harness/hooks")
	cases := []Options{{}, {Isolated: true}, {AllowHooks: true}, {PreserveIdentity: true},
		{Isolated: true, PreserveIdentity: true}, {Settings: []Setting{{"remote.origin.url", "https://x/y.git"}, {"a.b", "c=d"}}}}
	for i, o := range cases {
		settings := [][2]string{}
		for _, s := range o.Settings {
			settings = append(settings, [2]string{s.Key, s.Value})
		}
		args, _ := json.Marshal(map[string]any{"isolated": o.Isolated, "allow_hooks": o.AllowHooks,
			"preserve_identity": o.PreserveIdentity, "settings": settings})
		cmd := exec.Command(py, "-I", "-c", `import json,sys
sys.path.insert(0, sys.argv[1])
from git_safety import git_environment
a = json.loads(sys.argv[2]); a["settings"] = tuple(tuple(s) for s in a["settings"])
print(json.dumps(git_environment(**a)))`, hooks, string(args))
		cmd.Env = base
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("case %d: python: %v", i, err)
		}
		var want map[string]string
		json.Unmarshal(out, &want)
		// The macOS python3 shim adds SDKROOT, CPATH and similar to its own environment before our code
		// runs; only keys that came from base or that git_environment sets (GIT_*) are compared.
		inBase := map[string]bool{}
		for _, kv := range base {
			k, _, _ := strings.Cut(kv, "=")
			inBase[k] = true
		}
		for k := range want {
			if !inBase[k] && !strings.HasPrefix(k, "GIT_") {
				delete(want, k)
			}
		}
		got := Environment(base, o)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("case %d %+v:\n go     %v\n python %v", i, o, got, want)
		}
	}
}

func TestScrubsRoutingButKeepsAuth(t *testing.T) {
	env := Environment(base, Options{})
	for _, k := range []string{"GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_AUTHOR_NAME"} {
		if _, ok := env[k]; ok {
			t.Errorf("%s survived", k)
		}
	}
	if env["GIT_SSH_COMMAND"] != "ssh -i k" || env["GITHUB_TOKEN"] == "" || env["GIT_CONFIG_KEY_0"] != "core.hooksPath" || env["GIT_CONFIG_VALUE_0"] != DevNull {
		t.Errorf("unexpected env %v", env)
	}
	if env["GIT_CONFIG_COUNT"] != "9" {
		t.Errorf("count %s", env["GIT_CONFIG_COUNT"])
	}
}

func TestWindowsKeysFoldLikeOsEnviron(t *testing.T) {
	defer func(old string) { goos = old }(goos)
	goos = "windows"
	env := Environment([]string{"Git_Dir=/evil", "git_index_file=/x", "=C:=C:\\w", "Path=C:\\bin"}, Options{})
	if _, ok := env["GIT_DIR"]; ok {
		t.Fatalf("mixed-case GIT_DIR survived: %v", env)
	}
	for k := range env {
		if strings.EqualFold(k, "git_dir") || strings.EqualFold(k, "git_index_file") || k == "" {
			t.Fatalf("unexpected key %q in %v", k, env)
		}
	}
	if env["PATH"] != "C:\\bin" {
		t.Fatalf("PATH not kept upper-cased: %v", env)
	}
}
