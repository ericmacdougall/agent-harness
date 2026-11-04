package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type tcase struct {
	Name        string            `json:"name"`
	Impl        json.RawMessage   `json:"impl"`
	Raw         *string           `json:"raw"`
	RawTemplate *string           `json:"raw_template"`
	FileMode    *uint32           `json:"file_mode"`
	FileSymlink bool              `json:"file_symlink"`
	BinMode     *uint32           `json:"bin_mode"`
	BinSymlink  bool              `json:"bin_symlink"`
	BinMissing  bool              `json:"bin_missing"`
	Env         map[string]string `json:"env"`
	Group       string            `json:"group"`
	Host        string            `json:"host"`
	BadByte     bool              `json:"bad_byte"`
	LauncherDir *uint32           `json:"launcher_dir_mode"`
	Want        string            `json:"want"`
	Reason      string            `json:"reason"`
}

func TestSharedCases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission rules are Unix-only; Windows has no Python front door")
	}
	raw, err := os.ReadFile("../../parity/switchfile/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Cases []tcase }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 38 {
		t.Fatalf("only %d cases", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			dir := t.TempDir()
			// t.TempDir's leaf follows the umask (0775 under umask 002), which safeAncestors rightly refuses.
			mustOK(t, os.Chmod(dir, 0o700))
			bin := filepath.Join(dir, "launcher", "harness")
			other := filepath.Join(dir, "other", "harness")
			os.MkdirAll(filepath.Dir(bin), 0o700)
			os.MkdirAll(filepath.Dir(other), 0o700)
			if c.LauncherDir != nil {
				mustOK(t, os.Chmod(filepath.Dir(bin), os.FileMode(*c.LauncherDir)))
			}
			content := []byte("#!fake harness binary\n")
			sum := sha256.Sum256(content)
			sha := hex.EncodeToString(sum[:])
			os.WriteFile(other, content, 0o700)
			switch {
			case c.BinMissing:
			case c.BinSymlink:
				os.Symlink(other, bin)
			default:
				os.WriteFile(bin, content, 0o700)
				if c.BinMode != nil {
					os.Chmod(bin, os.FileMode(*c.BinMode))
				}
			}
			file := filepath.Join(dir, "impl.json")
			body := ""
			if c.Raw != nil {
				body = *c.Raw
			} else if c.RawTemplate != nil {
				body = strings.NewReplacer("$BIN", bin, "$OTHER", other, "$SHA", sha).Replace(*c.RawTemplate)
			} else if string(c.Impl) != "null" && len(c.Impl) > 0 {
				body = strings.NewReplacer("$BIN", bin, "$OTHER", other, "$SHA_UPPER", strings.ToUpper(sha), "$SHA", sha).Replace(string(c.Impl))
			}
			if body != "" {
				target := file
				if c.FileSymlink {
					target = file + ".real"
				}
				data := []byte(body)
				if c.BadByte {
					data = []byte(strings.ReplaceAll(body, "@BAD@", "\xff"))
				}
				mustOK(t, os.WriteFile(target, data, 0o600))
				if c.FileMode != nil {
					os.Chmod(target, os.FileMode(*c.FileMode))
				}
				if c.FileSymlink {
					os.Symlink(target, file)
				}
			}
			env := map[string]string{}
			for k, v := range c.Env {
				env[k] = strings.ReplaceAll(v, "$SHA", sha)
			}
			group, host := c.Group, c.Host
			if group == "" {
				group = "wal"
			}
			if host == "" {
				host = "claude"
			}
			d := Resolve(Request{Group: group, Host: host, Launcher: bin, File: file, Getenv: func(k string) string { return env[k] }})
			if d.Impl != c.Want || d.Reason != c.Reason {
				t.Fatalf("got %+v, want %s/%s", d, c.Want, c.Reason)
			}
		})
	}
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
