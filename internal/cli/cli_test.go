package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// abs builds an absolute path valid on the running OS.
func abs(parts ...string) string {
	root := "/"
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(os.TempDir()) + `\\`
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func TestParseCanonical(t *testing.T) {
	for _, argv := range [][]string{
		{"--host", "codex", "--config-dir", abs("h", ".codex"), "hook", "pre_tool_use"},
		{"--host=codex", "--config-dir=" + abs("h", ".codex"), "--entry=launcher", "hook", "pre_tool_use"},
	} {
		g, err := Parse(argv)
		if err != nil || g.Host != "codex" || g.ConfigDir != abs("h", ".codex") || g.Entry != "launcher" || g.Sub != "hook" || len(g.Args) != 1 {
			t.Errorf("%v: got %+v err %v", argv, g, err)
		}
	}
}

func TestParseExempt(t *testing.T) {
	g, err := Parse([]string{"version", "--json"})
	if err != nil || g.Sub != "version" || g.Args[0] != "--json" {
		t.Fatalf("got %+v err %v", g, err)
	}
}

func TestParseLedgerSubcommandsExempt(t *testing.T) {
	for _, argv := range [][]string{{"tickets", "new", "--title", "x"}, {"ledger-mcp"}} {
		g, err := Parse(argv)
		if err != nil || g.Sub != argv[0] || g.Host != "" || len(g.Args) != len(argv)-1 {
			t.Errorf("%v: got %+v err %v", argv, g, err)
		}
	}
}

func TestParseUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"--host", "vim", "--config-dir", abs("x"), "hook"},
		{"--host", "claude", "hook"},
		{"--host", "claude", "--config-dir", "rel", "hook"},
		{"--host", "claude", "--config-dir", abs("a") + "/../b", "hook"},
		{"--host", "claude", "--config-dir", abs("x"), "--entry", "py:rel.py", "hook"},
		{"--host", "claude", "--host", "codex", "--config-dir", abs("x"), "hook"},
		{"--ho", "claude", "--config-dir", abs("x"), "hook"},
		{"--host", "--config-dir", abs("x"), "hook"},
		{"--host", "claude", "--config-dir", abs("x")},
	}
	for _, argv := range cases {
		if _, err := Parse(argv); !IsUsage(err) {
			t.Errorf("%v: want usage error, got %v", argv, err)
		}
	}
}

func TestParseNormalizesSeparators(t *testing.T) {
	in := filepath.ToSlash(abs("h", "cfg"))
	g, err := Parse([]string{"--host", "cursor", "--config-dir", in, "hook", "x"})
	if err != nil || g.ConfigDir != abs("h", "cfg") {
		t.Fatalf("%s: got %q err %v", in, g.ConfigDir, err)
	}
}
