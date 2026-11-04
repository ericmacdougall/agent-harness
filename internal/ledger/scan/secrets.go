// Package scan refuses (or masks) secret-shaped text before it is appended to the ledger. It reuses the
// harness detector (internal/redact, the port of wal_note.SECRET_PATTERN) and adds ledger-local token
// shapes that are deliberately not in that shared pattern.
package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/redact"
)

// Finding locates one secret: the field it is in, the rune offset where it starts, and its type.
// It never carries the secret text.
type Finding struct {
	Field  string
	Offset int
	Type   string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s at offset %d (%s)", f.Field, f.Offset, f.Type)
}

type pattern struct {
	typ string
	re  *regexp.Regexp
}

// Ledger-local patterns (ASCII shapes, so RE2 semantics equal Python's here).
var local = []pattern{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"authorization_header", regexp.MustCompile(`(?i)\b(?:proxy-)?authorization[ \t]*:[ \t]*\S[^\n]*`)},
	{"github_pat", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`)},
	{"api_key", regexp.MustCompile(`\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}`)},
	{"slack_token", regexp.MustCompile(`\bxox[abpe]-[A-Za-z0-9-]{10,}`)},
	{"aws_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
}

// classify names a redact.Spans match from its leading text.
func classify(m string) string {
	l := strings.ToLower(m)
	switch {
	case strings.HasPrefix(l, "github_pat_"):
		return "github_pat"
	case len(l) > 3 && strings.HasPrefix(l, "gh") && l[3] == '_':
		return "github_token"
	case strings.HasPrefix(l, "sk-"):
		return "api_key"
	case strings.HasPrefix(l, "akia"):
		return "aws_key"
	case strings.HasPrefix(l, "bearer"):
		return "bearer_token"
	case strings.HasPrefix(l, "xox"):
		return "slack_token"
	case strings.HasPrefix(l, "-----begin"):
		return "private_key"
	case strings.Contains(l, "://"):
		return "url_credentials"
	}
	return "secret_assignment"
}

type span struct {
	start, end int // rune offsets
	typ        string
}

func spans(text string) []span {
	var out []span
	rs := []rune(text)
	for _, s := range redact.Spans(text) {
		out = append(out, span{s[0], s[1], classify(string(rs[s[0]:s[1]]))})
	}
	for _, p := range local {
		for _, loc := range p.re.FindAllStringIndex(text, -1) {
			out = append(out, span{runeIndex(text, loc[0]), runeIndex(text, loc[1]), p.typ})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].start != out[j].start {
			return out[i].start < out[j].start
		}
		return out[i].end > out[j].end
	})
	return out
}

func runeIndex(s string, byteOff int) int { return len([]rune(s[:byteOff])) }

// Scan returns one finding per secret-shaped span in each field (overlapping spans are merged).
func Scan(fields [][2]string) []Finding {
	var out []Finding
	for _, f := range fields {
		for _, s := range merge(spans(f[1])) {
			out = append(out, Finding{f[0], s.start, s.typ})
		}
	}
	return out
}

func merge(in []span) []span {
	var out []span
	for _, s := range in {
		if n := len(out); n > 0 && s.start < out[n-1].end {
			if s.end > out[n-1].end {
				out[n-1].end = s.end
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// Mask replaces every secret-shaped span with [REDACTED:<type>].
func Mask(text string) string {
	ms := merge(spans(text))
	if len(ms) == 0 {
		return text
	}
	rs := []rune(text)
	var b strings.Builder
	prev := 0
	for _, s := range ms {
		b.WriteString(string(rs[prev:s.start]))
		b.WriteString("[REDACTED:" + s.typ + "]")
		prev = s.end
	}
	b.WriteString(string(rs[prev:]))
	return b.String()
}
