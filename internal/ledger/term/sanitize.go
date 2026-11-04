// Package term makes untrusted ledger text inert for terminals and agents: it removes escape sequences
// and control characters and shows invisible formatting characters as visible escapes.
package term

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxLine is the longest line rendered; longer lines are cut and marked.
const MaxLine = 2000

// visible lists format characters that are rendered as \uXXXX instead of being passed through:
// bidi embeddings/overrides/isolates and zero-width characters (they can hide or reorder text).
func visible(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r >= 0x200B && r <= 0x200F,
		r == 0x2060, r == 0xFEFF, r == 0x061C, r == 0x180E, r >= 0x2061 && r <= 0x2064,
		r == 0x2028, r == 0x2029, r == 0x00AD, r >= 0xFFF9 && r <= 0xFFFB, r >= 0xE0000 && r <= 0xE007F:
		return true
	}
	return false
}

// Sanitize returns s with
//   - ESC sequences removed whole: CSI (ESC [ ... final), OSC/DCS/SOS/PM/APC (ESC ] P X ^ _ ... ST or BEL),
//     and any other two-byte ESC x; the 8-bit C1 introducers CSI/OSC/DCS (U+009B, U+009D, U+0090...) likewise;
//   - other C0 controls except \n and \t, DEL and C1 controls dropped; \r dropped;
//   - invalid UTF-8 replaced by U+FFFD;
//   - bidi and zero-width characters shown as \uXXXX;
//   - each line capped at MaxLine runes.
func Sanitize(s string) string {
	var b strings.Builder
	rs := []rune(strings.ToValidUTF8(s, "\ufffd"))
	n := len(rs)
	for i := 0; i < n; i++ {
		r := rs[i]
		switch {
		case r == 0x1b: // ESC
			i = skipEscape(rs, i)
		case r == 0x9b: // 8-bit CSI
			i = skipCSI(rs, i+1)
		case r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f: // 8-bit OSC, DCS, SOS, PM, APC
			i = skipString(rs, i+1)
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			// dropped
		case visible(r):
			fmt.Fprintf(&b, `\u{%x}`, r)
		default:
			b.WriteRune(r)
		}
	}
	return capLines(b.String())
}

// skipEscape returns the index of the last rune of the escape sequence starting at rs[i] == ESC.
func skipEscape(rs []rune, i int) int {
	if i+1 >= len(rs) {
		return i
	}
	switch rs[i+1] {
	case '[':
		return skipCSI(rs, i+2)
	case ']', 'P', 'X', '^', '_':
		return skipString(rs, i+2)
	default:
		// ESC followed by intermediates (0x20-0x2f) then a final byte.
		j := i + 1
		for j < len(rs) && rs[j] >= 0x20 && rs[j] <= 0x2f {
			j++
		}
		if j < len(rs) {
			return j
		}
		return len(rs) - 1
	}
}

// skipCSI consumes parameter and intermediate bytes then one final byte (0x40-0x7e).
func skipCSI(rs []rune, j int) int {
	for j < len(rs) {
		r := rs[j]
		if r >= 0x40 && r <= 0x7e {
			return j
		}
		if r < 0x20 || r > 0x7e {
			// Malformed: stop before the offending rune so it is processed normally.
			return j - 1
		}
		j++
	}
	return len(rs) - 1
}

// skipString consumes a control string up to BEL, ESC \ or 8-bit ST (U+009C), or the end of input.
func skipString(rs []rune, j int) int {
	for j < len(rs) {
		switch {
		case rs[j] == 0x07 || rs[j] == 0x9c:
			return j
		case rs[j] == 0x1b && j+1 < len(rs) && rs[j+1] == '\\':
			return j + 1
		}
		j++
	}
	return len(rs) - 1
}

func capLines(s string) string {
	if utf8.RuneCountInString(s) <= MaxLine {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if utf8.RuneCountInString(l) > MaxLine {
			lines[i] = string([]rune(l)[:MaxLine]) + " [line truncated]"
		}
	}
	return strings.Join(lines, "\n")
}

// Line sanitizes s and folds it onto one line (newlines and tabs become spaces), for titles and labels.
func Line(s string) string {
	return strings.NewReplacer("\n", " ", "\t", " ").Replace(Sanitize(s))
}
