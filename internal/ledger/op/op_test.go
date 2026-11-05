package op

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLabelGoldenMatchesCPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/label_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Seed    int    `json:"seed"`
		Unicode string `json:"unicode"`
		Cases   []struct{ In, NFC, Key string }
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.Unicode != UnicodeVersion || len(g.Cases) < 400 {
		t.Fatalf("golden unicode %s cases %d (seed %d)", g.Unicode, len(g.Cases), g.Seed)
	}
	for i, c := range g.Cases {
		if got := NFC(c.In); got != c.NFC {
			t.Errorf("seed %d case %d NFC(%q) = %q, want %q", g.Seed, i, c.In, got, c.NFC)
		}
		if got := LabelKey(c.In); got != c.Key {
			t.Errorf("seed %d case %d LabelKey(%q) = %q, want %q", g.Seed, i, c.In, got, c.Key)
		}
	}
}

// Every code point (and every code point followed by a combining mark) normalizes like CPython.
func TestNFCAllCodePointsMatchCPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	ver, err := exec.Command(py, "-I", "-c", "import unicodedata;print(unicodedata.unidata_version)").Output()
	if err != nil || strings.TrimSpace(string(ver)) != UnicodeVersion {
		t.Skipf("python3 unicodedata %q differs from tables %s", strings.TrimSpace(string(ver)), UnicodeVersion)
	}
	var in strings.Builder
	n := 0
	for r := rune(0x20); r < 0x30000; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		in.WriteString(string(r) + "\u0301\u0323\n")
		n++
	}
	cmd := exec.Command(py, "-I", "-c", `import sys,unicodedata
data=sys.stdin.buffer.read().decode("utf-8").split("\n")
sys.stdout.buffer.write("\n".join(unicodedata.normalize("NFC",l)+"\t"+l.casefold() for l in data).encode("utf-8"))`)
	cmd.Stdin = strings.NewReader(in.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(string(out), "\n")
	lines := strings.Split(in.String(), "\n")
	if len(want) != len(lines) || n < 190000 {
		t.Fatalf("got %d results for %d lines", len(want), len(lines))
	}
	bad := 0
	for i, l := range lines {
		if got := NFC(l) + "\t" + CaseFold(l); got != want[i] && bad < 20 {
			bad++
			t.Errorf("%q: go %q python %q", l, got, want[i])
		}
	}
}

func TestNFCIdempotent(t *testing.T) {
	for _, s := range []string{"e\u0301", "\u1100\u1161\u11a8", "\u212b", "a\u0328\u0301\u0327x"} {
		once := NFC(s)
		if NFC(once) != once {
			t.Errorf("NFC not idempotent for %q", s)
		}
	}
	if LabelKey(" Stra\u00dfe ") != LabelKey("STRASSE") || LabelKey("Cafe\u0301") != LabelKey("caf\u00e9") {
		t.Error("label identity must casefold and compose")
	}
}

func TestULID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		u, err := NewULID(1762210965123)
		if err != nil || !ValidULID(u) || ULIDTime(u) != 1762210965123 || seen[u] {
			t.Fatalf("bad ulid %q %v", u, err)
		}
		seen[u] = true
	}
	for _, bad := range []string{"", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01jbq6z8k3f6m4q2t0wj4y9a7c", "01JBQ6Z8K3F6M4Q2T0WJ4Y9A7", "../../../../../../etc/pass"} {
		if ValidULID(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := NewULID(1 << 48); err == nil {
		t.Error("out-of-range time accepted")
	}
}

func TestTick(t *testing.T) {
	cases := []struct {
		last    HLC
		now     int64
		witness HLC
		want    HLC
	}{
		{HLC{100, 0}, 200, HLC{}, HLC{200, 0}},
		{HLC{300, 4}, 200, HLC{}, HLC{300, 5}}, // own clock never regresses (N10)
		{HLC{100, 0}, 200, HLC{250, 7}, HLC{250, 8}},
		{HLC{250, 2}, 200, HLC{250, 7}, HLC{250, 8}},
		{HLC{250, 9}, 200, HLC{250, 7}, HLC{250, 10}},
	}
	for _, c := range cases {
		got, err := Tick(c.last, c.now, c.witness)
		if err != nil || got != c.want || !c.last.Less(got) {
			t.Errorf("Tick(%v,%d,%v)=%v want %v", c.last, c.now, c.witness, got, c.want)
		}
	}
	if Witnessable(HLC{1000 + WitnessBound + 1, 0}, 1000) || !Witnessable(HLC{1000 + WitnessBound, 0}, 1000) {
		t.Error("witness bound")
	}
	if _, err := Tick(HLC{5, maxCtr - 1}, 5, HLC{}); err == nil {
		t.Error("counter overflow accepted")
	}
}

func TestHLCName(t *testing.T) {
	h := HLC{1762210965123, 7}
	got, err := ParseHLCName(h.Name())
	if err != nil || got != h {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"hlc-01-0", "hlc-1-+1", "hlc-1", "hlc--1-0", "hlc-1-0-0", "hlc-1-2147483648", "x-1-0"} {
		if _, err := ParseHLCName(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func mustOp(t *testing.T, kind, ticket string, payload Obj) *Op {
	t.Helper()
	id, _ := NewID(PrefixOp, 1762210965123)
	proj, _ := NewID(PrefixProject, 1762210000000)
	w, _ := NewID(PrefixWriter, 1762210000000)
	if ticket == "new" {
		ticket = PrefixTicket + id[len(PrefixOp):]
	}
	o := &Op{V: 1, ID: id, Project: proj, Writer: w, HLC: HLC{1762210965123, 0},
		Actor: Actor{Kind: "agent", Label: "claude-code"}, Ticket: ticket, Kind: kind, Payload: payload}
	return o
}

func TestParseRoundTripAndRejections(t *testing.T) {
	o := mustOp(t, KindTicketCreate, "new", TicketCreate("t \u202e\x1b[2J", "b", "task", "high", []string{"x"}, "todo", "unstarted"))
	line, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range line {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("op bytes not ASCII-escaped: %q", line)
		}
	}
	p, err := Parse(line)
	if err != nil || p.ID != o.ID || p.Str("title") != o.Payload[0].V {
		t.Fatalf("round trip: %v", err)
	}
	mutate := map[string]string{
		"duplicate key":  strings.Replace(string(line), `"v":1,`, `"v":1,"v":1,`, 1),
		"reordered":      strings.Replace(strings.Replace(string(line), `"v":1,`, ``, 1), `}`, `,"v":1}`, 1),
		"unknown field":  strings.Replace(string(line), `"v":1,`, `"v":1,"x":1,`, 1),
		"raw utf8":       strings.Replace(string(line), "\\u202e", "\u202e", 1),
		"version 2":      strings.Replace(string(line), `"v":1,`, `"v":2,`, 1),
		"bad label":      strings.Replace(string(line), `"label":"claude-code"`, `"label":"claude\u0000code"`, 1),
		"time mismatch":  strings.Replace(string(line), `"wall_ms":1762210965123`, `"wall_ms":1762210965124`, 1),
		"trailing":       string(line) + " ",
		"bad type":       strings.Replace(string(line), `"type":"task"`, `"type":"epic"`, 1),
		"path ticket id": strings.Replace(string(line), `"ticket":"tk_`, `"ticket":"tk_../`, 1),
	}
	for name, m := range mutate {
		if m == string(line) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := Parse([]byte(m)); err == nil {
			t.Errorf("%s accepted: %s", name, m)
		}
	}
	big := mustOp(t, KindTicketCreate, "new", TicketCreate("t", strings.Repeat("a", MaxBodyBytes+1), "task", "high", nil, "todo", "unstarted"))
	bl, _ := big.Encode()
	if _, err := Parse(bl); err == nil {
		t.Error("oversize body accepted")
	}
	unk := mustOp(t, "future.kind", "", Obj{{"z", "1"}, {"a", []any{"x"}}})
	ul, _ := unk.Encode()
	if p, err := Parse(ul); err != nil || Known(p.Kind) {
		t.Errorf("unknown kind must be preserved: %v", err)
	}
	if !bytes.Equal(p.Raw, line) {
		t.Error("raw bytes not kept")
	}
}
