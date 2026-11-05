package op

import (
	"sort"
	"strings"
)

// Hangul syllable constants (Unicode section 3.12).
const (
	hSBase, hLBase, hVBase, hTBase = 0xAC00, 0x1100, 0x1161, 0x11A7
	hLCount, hVCount, hTCount      = 19, 21, 28
	hNCount                        = hVCount * hTCount
	hSCount                        = hLCount * hNCount
)

func decompose(r rune, out []rune) []rune {
	if r >= hSBase && r < hSBase+hSCount {
		s := r - hSBase
		out = append(out, hLBase+s/hNCount, hVBase+(s%hNCount)/hTCount)
		if t := s % hTCount; t != 0 {
			out = append(out, hTBase+t)
		}
		return out
	}
	if d, ok := canonDecomp[r]; ok {
		for _, x := range d {
			out = decompose(x, out)
		}
		return out
	}
	return append(out, r)
}

// NFC returns the canonical composition of s (Unicode normalization form C), matching CPython's
// unicodedata.normalize("NFC", s) for the generated UnicodeVersion.
func NFC(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var d []rune
	for _, r := range s {
		d = decompose(r, d)
	}
	// Canonical ordering: stable sort each run of non-starters by combining class.
	for i := 0; i < len(d); {
		if combClass[d[i]] == 0 {
			i++
			continue
		}
		j := i
		for j < len(d) && combClass[d[j]] != 0 {
			j++
		}
		run := d[i:j]
		sort.SliceStable(run, func(a, b int) bool { return combClass[run[a]] < combClass[run[b]] })
		i = j
	}
	// Canonical composition.
	if len(d) == 0 {
		return ""
	}
	out := make([]rune, 0, len(d))
	starter := -1
	var lastCC uint8
	for _, r := range d {
		cc := combClass[r]
		if starter >= 0 {
			s := out[starter]
			blocked := len(out)-1 > starter && (lastCC == 0 || lastCC >= cc)
			if !blocked {
				if c, ok := compose2(s, r); ok {
					out[starter] = c
					continue
				}
			}
		}
		if cc == 0 {
			starter = len(out)
		}
		lastCC = cc
		out = append(out, r)
	}
	return string(out)
}

func compose2(a, b rune) (rune, bool) {
	if a >= hLBase && a < hLBase+hLCount && b >= hVBase && b < hVBase+hVCount {
		return hSBase + ((a-hLBase)*hVCount+(b-hVBase))*hTCount, true
	}
	if a >= hSBase && a < hSBase+hSCount && (a-hSBase)%hTCount == 0 && b > hTBase && b < hTBase+hTCount {
		return a + (b - hTBase), true
	}
	c, ok := primaryComposite[[2]rune{a, b}]
	return c, ok
}

// CaseFold is CPython str.casefold (full case folding).
func CaseFold(s string) string {
	var b strings.Builder
	for _, r := range s {
		if f, ok := caseFold[r]; ok {
			for _, x := range f {
				b.WriteRune(x)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// pyStrip is CPython str.strip() with no argument: it removes leading/trailing str.isspace() runes.
func pyStrip(s string) string {
	return strings.TrimFunc(s, isPySpace)
}

func isPySpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// LabelDisplay is the stored form of a label: NFC, trimmed.
func LabelDisplay(s string) string { return pyStrip(NFC(s)) }

// LabelKey is the identity of a label: NFC(casefold(NFC(s).strip())).
func LabelKey(s string) string { return NFC(CaseFold(pyStrip(NFC(s)))) }
