package redact

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type corpus struct {
	Source string        `json:"source"`
	Cases  []corpusEntry `json:"cases"`
}
type corpusEntry struct {
	Text  string
	Spans [][2]int
}

func (c *corpusEntry) UnmarshalJSON(b []byte) error {
	var raw [2]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &c.Text); err != nil {
		return err
	}
	return json.Unmarshal(raw[1], &c.Spans)
}

func load(t *testing.T) corpus {
	raw, err := os.ReadFile("testdata/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	hits := 0
	for _, e := range c.Cases {
		if len(e.Spans) > 0 {
			hits++
		}
	}
	if len(c.Cases) < 3000 || hits < 1000 || hits == len(c.Cases) {
		t.Fatalf("corpus not meaningful: %d cases, %d with matches (seed 20261104)", len(c.Cases), hits)
	}
	return c
}

func TestSourceMatchesPython(t *testing.T) {
	if got := load(t).Source; got != PythonSource {
		t.Fatalf("wal_note.py SECRET_PATTERN changed; port it:\n%s", got)
	}
}

func TestSpansMatchCPython(t *testing.T) {
	bad := 0
	for i, e := range load(t).Cases {
		got := Spans(e.Text)
		if len(got) == 0 && len(e.Spans) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, e.Spans) {
			bad++
			if bad <= 15 {
				t.Errorf("case %d %q (seed 20261104): go %v python %v", i, e.Text, got, e.Spans)
			}
		}
	}
	if bad > 0 {
		t.Errorf("%d mismatches", bad)
	}
}
