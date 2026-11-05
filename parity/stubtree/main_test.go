package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// A toy repo: tool.py prints a line; a black-box test runs it as a script, and lib_user.py imports it.
func toyRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "harness", "hooks"), 0o755)
	os.MkdirAll(filepath.Join(repo, "tests"), 0o755)
	os.WriteFile(filepath.Join(repo, "harness", "hooks", "tool.py"), []byte("import sys\nVALUE = 41\ndef helper():\n    return VALUE + 1\nif __name__ == '__main__':\n    print('python tool', *sys.argv[1:])\n"), 0o644)
	os.WriteFile(filepath.Join(repo, "tests", "test_tool.py"), []byte(`import subprocess, sys, unittest
from pathlib import Path
HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import tool
class T(unittest.TestCase):
    def test_script(self):
        out = subprocess.run([sys.executable, str(HOOKS / "tool.py"), "a b"], capture_output=True, text=True).stdout
        self.assertIn("tool a b", out)
    def test_library_import_is_python(self):
        self.assertEqual(tool.helper(), 42)
`), 0o644)
	return repo
}

func fakeGo(t *testing.T, body string) string {
	bin := filepath.Join(t.TempDir(), "harness")
	os.WriteFile(bin, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	return bin
}

func manifest(t *testing.T, min int) string {
	p := filepath.Join(t.TempDir(), "m.json")
	os.WriteFile(p, []byte(`{"group":"toy","host":"claude","entries":[{"script":"harness/hooks/tool.py","sub":["tool"],"min_calls":`+strconv.Itoa(min)+`}]}`), 0o644)
	return p
}

func TestStubReachesGoAndKeepsLibraryImport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX exec stubs")
	}
	// The fake Go echoes its canonical argv: host, config dir, entry, sub, original args.
	bin := fakeGo(t, `shift 6; printf '%s ' "go"; echo "$@"`)
	var out, errb bytes.Buffer
	code, err := run(toyRepo(t), bin, manifest(t, 1), false, nil, &out, &errb)
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v\n%s", code, err, errb.String())
	}
	if !strings.Contains(errb.String(), "tool.py reached Go 1 time(s)") {
		t.Fatalf("counter missing:\n%s", errb.String())
	}
}

// Failing control: if Go behaves differently the unmodified test fails; if nothing reaches Go, min_calls fails.
func TestDivergenceAndUnreachedStubFail(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX exec stubs")
	}
	var out, errb bytes.Buffer
	code, _ := run(toyRepo(t), fakeGo(t, `echo wrong`), manifest(t, 1), false, nil, &out, &errb)
	if code == 0 {
		t.Fatalf("a diverging Go passed:\n%s", errb.String())
	}
	errb.Reset()
	code, _ = run(toyRepo(t), fakeGo(t, `echo unused`), manifest(t, 1), false, []string{"tests.test_tool.T.test_library_import_is_python"}, &out, &errb)
	if code != 3 || !strings.Contains(errb.String(), "not Go parity") {
		t.Fatalf("unreached stub: code %d\n%s", code, errb.String())
	}
}
