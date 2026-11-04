package term

import (
	"strings"
	"testing"
)

func TestSanitizeInert(t *testing.T) {
	esc := "\x1b"
	cases := map[string]string{
		"osc8 hyperlink": "a" + esc + "]8;;http://evil" + esc + "\\click" + esc + "]8;;" + esc + "\\b",
		"osc bel title":  "a" + esc + "]0;pwned\x07b",
		"csi clear":      "a" + esc + "[2J" + esc + "[H" + esc + "[31mb",
		"csi cursor":     "a" + esc + "[10;20Hb",
		"dcs":            "a" + esc + "Pq#0;2;0;0;0" + esc + "\\b",
		"c1 csi":         "a\u009b2Jb",
		"c1 osc":         "a\u009d0;x\u009cb",
		"bare controls":  "a\x00\x07\x08\r\x7f\u0085b",
		"esc charset":    "a" + esc + "(Bb",
	}
	for name, in := range cases {
		got := Sanitize(in)
		if strings.ContainsAny(got, "\x1b\x07\x00\r\u009b\u009d\u009c\u0085\x7f\x08") {
			t.Errorf("%s: control survived: %q", name, got)
		}
		if !strings.HasPrefix(got, "a") || !strings.HasSuffix(got, "b") {
			t.Errorf("%s: text lost: %q", name, got)
		}
	}
	vis := Sanitize("x\u202eevil\u200bz\u2066\ufeff\U000e0041")
	for _, want := range []string{`\u{202e}`, `\u{200b}`, `\u{2066}`, `\u{feff}`, `\u{e0041}`} {
		if !strings.Contains(vis, want) {
			t.Errorf("missing visible escape %s in %q", want, vis)
		}
	}
	for _, r := range vis {
		if r > 0x7e {
			t.Errorf("invisible rune survived: %U", r)
		}
	}
	if Sanitize("keep\n\tthis") != "keep\n\tthis" {
		t.Error("newline/tab must be kept")
	}
	if Line("a\nb\tc") != "a b c" {
		t.Error("Line must fold whitespace")
	}
	long := Sanitize(strings.Repeat("x", 5000) + "\nshort")
	first, rest, _ := strings.Cut(long, "\n")
	if len(first) != MaxLine+len(" [line truncated]") || rest != "short" {
		t.Errorf("cap: %d %q", len(first), rest)
	}
	if got := Sanitize("ok\xffbad"); !strings.Contains(got, "\ufffd") {
		t.Errorf("invalid utf-8 not replaced: %q", got)
	}
}
