// Package impl resolves which implementation (go or python) serves a switch group, from the switch file
// ~/.agent-harness/impl.json, the workflow pin AGENT_HARNESS_IMPL_PIN and the hop marker
// AGENT_HARNESS_DISPATCHED (plan 3.6). compat/pyfront/frontdoor.py implements the same rules for the
// Python front door; both are driven by parity/switchfile/cases.json so they cannot drift apart.
//
// Missing, invalid or unsafe state means python. A pin that cannot be honoured, or a dispatch that would
// bounce back across a hop, is refused: hook surfaces then block (exit 2), CLI surfaces exit 1.
package impl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Go     = "go"
	Python = "python"
	Refuse = "refuse"

	PinEnv      = "AGENT_HARNESS_IMPL_PIN"
	DispatchEnv = "AGENT_HARNESS_DISPATCHED"
	MaxFile     = 64 << 10
)

// Groups are the switch groups of plan 3.5.
var Groups = []string{"wal", "policy", "spec", "watch", "review", "rescue", "delivery", "install"}

// Decision is the outcome; Reason is one of missing, invalid, unsafe, group, host, binary, sha, pin, loop
// (empty for a plain go decision). Python decisions with a reason other than "group" are fallbacks the
// caller records as an impl_fallback WAL entry.
type Decision struct {
	Impl, Reason, Binary, SHA256 string
}

// Request names the group and host, the expected launcher path for that host, the switch file and env.
type Request struct {
	Group, Host, Launcher, File string
	Getenv                      func(string) string
}

type hostEntry struct {
	Binary string `json:"binary"`
	SHA256 string `json:"sha256"`
}
type switchFile struct {
	Schema int                  `json:"schema"`
	Groups map[string]string    `json:"groups"`
	Hosts  map[string]hostEntry `json:"hosts"`
}

var (
	hexSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pinRE  = regexp.MustCompile(`^([a-z]+):(go|python):([0-9a-f]{64}|-)$`)
)

// DefaultFile is ~/.agent-harness/impl.json.
func DefaultFile() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".agent-harness", "impl.json")
}

// Resolve applies the rules in order: pin, switch file, binary checks, hop guard.
func Resolve(r Request) Decision {
	get := r.Getenv
	if get == nil {
		get = os.Getenv
	}
	d := resolve(r, get)
	if d.Impl == Go && get(DispatchEnv) != "" {
		return Decision{Impl: Refuse, Reason: "loop"}
	}
	return d
}

func resolve(r Request, get func(string) string) Decision {
	sf, state := load(r.File)
	if pin := get(PinEnv); pin != "" {
		m := pinRE.FindStringSubmatch(pin)
		if m == nil {
			return Decision{Impl: Refuse, Reason: "pin"}
		}
		if m[1] == r.Group {
			if m[2] == Python {
				return Decision{Impl: Python, Reason: "pin"}
			}
			if state != "" {
				return Decision{Impl: Refuse, Reason: "pin"}
			}
			bin, actual, why := verifiedBinary(sf, r)
			if why != "" || actual != m[3] {
				return Decision{Impl: Refuse, Reason: "pin"}
			}
			return Decision{Impl: Go, Reason: "pin", Binary: bin, SHA256: actual}
		}
	}
	if state != "" {
		return Decision{Impl: Python, Reason: state}
	}
	if sf.Groups[r.Group] != Go {
		return Decision{Impl: Python, Reason: "group"}
	}
	bin, actual, why := verifiedBinary(sf, r)
	if why != "" {
		return Decision{Impl: Python, Reason: why}
	}
	if actual != sf.Hosts[r.Host].SHA256 {
		return Decision{Impl: Python, Reason: "sha"}
	}
	return Decision{Impl: Go, Binary: bin, SHA256: actual}
}

// load returns the parsed file, or a state of missing, unsafe or invalid.
func load(path string) (switchFile, string) {
	var sf switchFile
	li, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return sf, "missing"
	}
	if err != nil || !li.Mode().IsRegular() || !private(li) {
		return sf, "unsafe"
	}
	f, err := openRegular(path)
	if err != nil {
		return sf, "unsafe"
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(fi, li) {
		return sf, "unsafe"
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil || len(raw) > MaxFile {
		return sf, "invalid"
	}
	parsed, ok := parse(raw)
	if !ok {
		return switchFile{}, "invalid"
	}
	sf = parsed
	return sf, ""
}

// parse reads exactly the keys Python reads. encoding/json struct decoding is avoided on purpose: it
// matches keys case-insensitively and Decoder ignores trailing data, both of which Python rejects.
func parse(raw []byte) (switchFile, bool) {
	var top map[string]any
	// encoding/json replaces invalid UTF-8 with U+FFFD; Python's strict decode rejects the file.
	if !utf8.Valid(raw) || json.Unmarshal(raw, &top) != nil {
		return switchFile{}, false
	}
	schema, ok := top["schema"].(float64)
	groups, gok := top["groups"].(map[string]any)
	hosts, hok := top["hosts"].(map[string]any)
	if !ok || schema != 1 || !gok || !hok || bytesHaveFloatSchema(raw) {
		return switchFile{}, false
	}
	sf := switchFile{Schema: 1, Groups: map[string]string{}, Hosts: map[string]hostEntry{}}
	for g, v := range groups {
		s, ok := v.(string)
		if !ok || !known(g) || (s != Go && s != Python) {
			return switchFile{}, false
		}
		sf.Groups[g] = s
	}
	for h, v := range hosts {
		m, ok := v.(map[string]any)
		if !ok {
			return switchFile{}, false
		}
		bin, bok := m["binary"].(string)
		sum, sok := m["sha256"].(string)
		if !bok || !sok || !filepath.IsAbs(bin) || !hexSHA.MatchString(sum) {
			return switchFile{}, false
		}
		sf.Hosts[h] = hostEntry{Binary: bin, SHA256: sum}
	}
	return sf, true
}

// bytesHaveFloatSchema rejects "schema": 1.0 or 1e0, which Python parses as a float, not the int 1.
func bytesHaveFloatSchema(raw []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return true
	}
	return strings.TrimSpace(string(top["schema"])) != "1"
}

func known(g string) bool {
	for _, x := range Groups {
		if x == g {
			return true
		}
	}
	return false
}

// verifiedBinary checks the host entry and hashes the binary; why is host or binary on failure.
func verifiedBinary(sf switchFile, r Request) (bin, sum, why string) {
	h, ok := sf.Hosts[r.Host]
	if !ok {
		return "", "", "host"
	}
	if h.Binary != r.Launcher { // exact: filepath.Clean and os.path.normpath disagree on a leading "//"
		return "", "", "binary"
	}
	li, err := os.Lstat(h.Binary)
	if err != nil || !li.Mode().IsRegular() || !safeBinary(li) || !safeAncestors(h.Binary) {
		return "", "", "binary"
	}
	f, err := openRegular(h.Binary)
	if err != nil {
		return "", "", "binary"
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !os.SameFile(fi, li) {
		return "", "", "binary"
	}
	hs := sha256.New()
	if _, err := io.Copy(hs, f); err != nil {
		return "", "", "binary"
	}
	return h.Binary, hex.EncodeToString(hs.Sum(nil)), ""
}
