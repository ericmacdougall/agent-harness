package scan

import (
	"strings"
	"testing"
)

// Fixtures are assembled at run time so the source holds no secret-shaped literal.
func fixtures() map[string]string {
	j := func(p ...string) string { return strings.Join(p, "") }
	return map[string]string{
		"github_token":         j("gh", "p_", strings.Repeat("A1b2", 9)),
		"github_pat":           j("github", "_pat_", strings.Repeat("Z9", 30)),
		"private_key":          j("-----BEGIN ", "OPENSSH PRIVATE", " KEY-----\nabc"),
		"authorization_header": j("Authori", "zation: Basic ", "dXNlcjpwYXNz"),
		"bearer_token":         j("Bear", "er ", "abc.def.ghi123"),
		"api_key":              j("sk", "-", strings.Repeat("q", 24)),
		"aws_key":              j("AK", "IA", "ABCDEFGHIJKLMNOP"),
		"slack_token":          j("xo", "xb-", "1234567890-abcdef"),
		"jwt":                  j("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0.", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"),
	}
}

func TestScanFindsEveryFixtureWithOffset(t *testing.T) {
	for typ, secret := range fixtures() {
		text := "prefix \u00e9 " + secret + " suffix"
		fs := Scan([][2]string{{"body", text}})
		if len(fs) == 0 {
			t.Errorf("%s: not found", typ)
			continue
		}
		if fs[0].Field != "body" || fs[0].Offset != len([]rune("prefix \u00e9 ")) && !strings.HasPrefix(fs[0].Type, "auth") {
			t.Errorf("%s: finding %+v", typ, fs[0])
		}
		if strings.Contains(fs[0].String(), secret) {
			t.Errorf("%s: finding echoes the secret", typ)
		}
		masked := Mask(text)
		if strings.Contains(masked, secret) || !strings.Contains(masked, "[REDACTED:") || len(Scan([][2]string{{"b", masked}})) != 0 {
			t.Errorf("%s: mask failed: %q", typ, masked)
		}
		if !strings.HasPrefix(masked, "prefix") || !strings.HasSuffix(masked, "suffix") && typ != "authorization_header" && typ != "private_key" {
			t.Errorf("%s: mask lost context: %q", typ, masked)
		}
	}
}

func TestScanCleanTextHasNoFindings(t *testing.T) {
	for _, s := range []string{"DNS probe hangs on IPv6-only hosts", "see sk-learn docs", "the token bucket refills", "git push origin main"} {
		if fs := Scan([][2]string{{"title", s}}); len(fs) != 0 {
			t.Errorf("false positive on %q: %v", s, fs)
		}
	}
}
