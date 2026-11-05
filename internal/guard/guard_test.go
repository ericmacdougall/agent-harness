package guard

import (
	"bytes"
	"strings"
	"testing"
)

func TestPanicExitCodes(t *testing.T) {
	for _, gate := range []bool{true, false} {
		var buf bytes.Buffer
		code := Run("commit-policy hook", gate, &buf, func() int { panic("secret /Users/x/path") })
		want := ExitCrash
		if gate {
			want = ExitGateBlock
		}
		if code != want {
			t.Errorf("gate=%v: code %d want %d", gate, code, want)
		}
		if strings.Contains(buf.String(), "secret") || strings.Contains(buf.String(), "/Users") {
			t.Errorf("stderr leaks panic value: %q", buf.String())
		}
	}
}

func TestNoPanicPassesCodeThrough(t *testing.T) {
	if c := Run("x", true, &bytes.Buffer{}, func() int { return 0 }); c != 0 {
		t.Fatalf("got %d", c)
	}
}
