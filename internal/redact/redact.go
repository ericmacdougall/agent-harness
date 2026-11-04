// Package redact ports the harness secret detector (harness/hooks/wal_note.py SECRET_PATTERN).
//
// Python's str regexes are Unicode-aware and RE2's are not, so the translation spells classes out:
//   - \s is Python's str.isspace() set (adds \x1c-\x1f, \x85 and every Unicode separator), and \S its
//     complement. RE2's \s is ASCII only, which would let "Bearer <token>" through.
//   - \b is removed and checked in Go: every alternative but the PEM header starts with \b before a
//     word character, so a match is kept only if the rune before it is not a Python word character
//     (str.isalnum() or "_"). RE2's ASCII \b disagrees with Python next to letters such as é or 日.
//   - IGNORECASE folds Python applies and RE2 does not (k~U+212A, s~U+017F, i~U+0130/U+0131) are
//     spelled out by foldLikePython.
package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	pySpace    = `\t\n\v\f\r\x1c-\x1f\x{85}\p{Z}`
	pyS        = `[` + pySpace + `]`
	pyNotS     = `[^` + pySpace + `]`
	pythonText = `(?i)(?:\bgh[pousr]_[A-Za-z0-9_]+|\bgithub_pat_[A-Za-z0-9_]+|` +
		`\bsk-[A-Za-z0-9-]{12,}|\bAKIA[A-Z0-9]{12}|` +
		`\bBearer\s+\S+|\bxox[baprs]-[A-Za-z0-9-]{6,}|` +
		`\b(?:[a-z0-9]+[_-])*(?:password|passwd|secret|token|api[_-]?key|` +
		`access[_-]?key|private[_-]?key|credentials?)(?:[_-]value)?[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|` +
		`\b[a-z][a-z0-9]*(?:Secret|Token|Password|ApiKey|AccessKey|PrivateKey|Credentials?)` +
		`[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|` +
		`\b[a-z][a-z0-9+.-]*://[^\s/?#@]+@[^\s/?#]+|` +
		`-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)`
)

// PythonSource is the pattern text exactly as Python compiles it; tests compare it with wal_note.py.
const PythonSource = pythonText

// Secret matches what SECRET_PATTERN matches.
var Secret = regexp.MustCompile(translate(pythonText))

func translate(p string) string {
	p = foldLikePython(p)
	// Python's \b is applied by byteSpans; RE2's ASCII \b would also refuse a match that starts with a
	// folded non-ASCII letter such as the Kelvin sign.
	p = strings.ReplaceAll(p, `\b`, ``)
	p = strings.ReplaceAll(p, `[^\s/?#@]`, `[^`+pySpace+`/?#@]`)
	p = strings.ReplaceAll(p, `[^\s/?#]`, `[^`+pySpace+`/?#]`)
	p = strings.ReplaceAll(p, `\s`, pyS)
	p = strings.ReplaceAll(p, `\S`, pyNotS)
	return p
}

// pythonFolds are the non-ASCII characters CPython's IGNORECASE matches for an ASCII letter; RE2's
// (?i) does not apply them inside classes, and never pairs i with İ or ı.
var pythonFolds = map[rune]string{'i': `\x{130}\x{131}`, 'k': `\x{212a}`, 's': `\x{17f}`}

// foldLikePython rewrites literal i/k/s as classes with their Python folds, and appends the folds to any
// positive class that covers those letters. Escapes are copied untouched.
func foldLikePython(p string) string {
	var b strings.Builder
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\\':
			b.WriteRune(r)
			if i+1 < len(rs) {
				i++
				b.WriteRune(rs[i])
			}
		case r == '(' && i+1 < len(rs) && rs[i+1] == '?':
			// group syntax such as (?i) or (?: holds flags, not literal letters
			j := i + 2
			for j < len(rs) && rs[j] != ')' && rs[j] != ':' {
				j++
			}
			b.WriteString(string(rs[i : j+1]))
			i = j
		case r == '[':
			j := i + 1
			for j < len(rs) && rs[j] != ']' {
				if rs[j] == '\\' {
					j++
				}
				j++
			}
			class := string(rs[i : j+1])
			if !strings.HasPrefix(class, "[^") {
				extra := ""
				for _, l := range "iks" {
					if classCovers(class, l) {
						extra += pythonFolds[l]
					}
				}
				// Insert first: appending after a trailing "-" would create a range.
				class = "[" + extra + class[1:]
			}
			b.WriteString(class)
			i = j
		default:
			if f, ok := pythonFolds[unicode.ToLower(r)]; ok {
				b.WriteString("[" + string(r) + f + "]")
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// classCovers reports whether a simple class body (letters and a-z style ranges) includes l or its upper case.
func classCovers(class string, l rune) bool {
	body := []rune(class[1 : len(class)-1])
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' {
			i++
			continue
		}
		lo, hi := body[i], body[i]
		if i+2 < len(body) && body[i+1] == '-' && body[i+2] != ']' {
			hi = body[i+2]
			i += 2
		}
		if (l >= lo && l <= hi) || (unicode.ToUpper(l) >= lo && unicode.ToUpper(l) <= hi) {
			return true
		}
	}
	return false
}

// Contains reports whether s holds anything that looks like a credential.
func Contains(s string) bool { return len(byteSpans(s, 1)) > 0 }

// Spans returns match offsets in runes (Python str indexes), for parity tests and redaction callers.
func Spans(s string) [][2]int {
	var out [][2]int
	for _, m := range byteSpans(s, -1) {
		out = append(out, [2]int{utf8.RuneCountInString(s[:m[0]]), utf8.RuneCountInString(s[:m[1]])})
	}
	return out
}

// byteSpans is finditer with Python's Unicode \b at the match start.
func byteSpans(s string, limit int) [][2]int {
	var out [][2]int
	for pos := 0; pos <= len(s) && (limit < 0 || len(out) < limit); {
		loc := Secret.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if start > 0 && s[start] != '-' {
			if prev, _ := utf8.DecodeLastRuneInString(s[:start]); pyWord(prev) {
				_, size := utf8.DecodeRuneInString(s[start:])
				pos = start + size // Python finds no boundary here; resume at the next character
				continue
			}
		}
		out = append(out, [2]int{start, end})
		if end == start {
			end++
		}
		pos = end
	}
	return out
}

func pyWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }
