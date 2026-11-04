package pycompat

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

type golden struct {
	Strings [][2]string `json:"strings"`
	Floats  [][2]string `json:"floats"`
	Structs [][2]string `json:"structs"`
}

func load(t *testing.T) golden {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	// Guard against a vacuous pass on an empty or truncated golden file.
	if len(g.Strings) < 50 || len(g.Floats) < 200 || len(g.Structs) < 5 {
		t.Fatalf("golden file too small: %d strings, %d floats, %d structs (seed 20261104)", len(g.Strings), len(g.Floats), len(g.Structs))
	}
	return g
}

func TestCanonicalStringsMatchCPython(t *testing.T) {
	for i, c := range load(t).Strings {
		got, err := Canonical(c[0])
		if err != nil || string(got) != c[1] {
			t.Errorf("case %d (seed 20261104): got %s err %v, want %s", i, got, err, c[1])
		}
	}
}

func TestFloatReprMatchesCPython(t *testing.T) {
	for i, c := range load(t).Floats {
		f, err := strconv.ParseFloat(c[0], 64)
		if err != nil {
			t.Fatalf("case %d: parse %s: %v", i, c[0], err)
		}
		got, err := FloatRepr(f)
		if err != nil || got != c[1] {
			t.Errorf("case %d (seed 20261104) %s: got %s err %v, want %s", i, c[0], got, err, c[1])
		}
	}
}

func decodeNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return i
			}
			u, _ := strconv.ParseUint(s, 10, 64)
			return u
		}
		f, _ := x.Float64()
		return f
	case []any:
		for i := range x {
			x[i] = decodeNumbers(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = decodeNumbers(x[k])
		}
	}
	return v
}

func TestCanonicalStructsMatchCPython(t *testing.T) {
	for i, c := range load(t).Structs {
		d := json.NewDecoder(strings.NewReader(c[0]))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		got, err := Canonical(decodeNumbers(v))
		if err != nil || !bytes.Equal(got, []byte(c[1])) {
			t.Errorf("case %d: got %s err %v, want %s", i, got, err, c[1])
		}
	}
}

func TestCanonicalRejectsWhatPythonRejects(t *testing.T) {
	for _, v := range []any{math.NaN(), math.Inf(1), "\xff", map[string]any{"\xff": 1}, struct{}{}} {
		if _, err := Canonical(v); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%#v: want ErrUnsupported, got %v", v, err)
		}
	}
}

// Documents why encoding/json must never feed a digest: it differs from CPython on these inputs.
func TestStdlibDiffersFromCPython(t *testing.T) {
	std, _ := json.Marshal("< \x7f")
	ours, _ := Canonical("< \x7f")
	if bytes.Equal(std, ours) {
		t.Fatalf("expected encoding/json to differ; both gave %s", std)
	}
}
