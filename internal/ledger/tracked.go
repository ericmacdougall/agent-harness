package ledger

// Best-effort "is this repository tracked by GoodQA" for sync-state. commit_policy.py is the authority;
// this reads the same repos patterns and applies the same URL spellings so the icon and the policy agree
// in the ordinary cases. A missing or unreadable policy means "not known", never "tracked".

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/gitx"
	"github.com/ericmacdougall/agent-harness/internal/proc"
)

// PolicyFileEnv overrides the commit policy path (tests, unusual installs).
const PolicyFileEnv = "HARNESS_COMMIT_POLICY_FILE"

var (
	portRe = regexp.MustCompile(`:\d+/`)
	scpRe  = regexp.MustCompile(`^(?:[^@/\s]+@)?([^/:\s]+):(.*)$`)
	gitRe  = regexp.MustCompile(`(?:\.git)?/*$`)
)

func policyPath() string {
	if p := os.Getenv(PolicyFileEnv); p != "" {
		return p
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".claude", "hooks", "commit_policy.json")
}

// trackedPatterns returns the repos patterns of every non-ledger ticket system.
func trackedPatterns() ([]*regexp.Regexp, bool) {
	p := policyPath()
	if p == "" {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 1<<20 {
		return nil, false
	}
	var doc struct {
		Systems map[string]struct {
			Adapter string   `json:"adapter"`
			Repos   []string `json:"repos"`
		} `json:"ticket_systems"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Systems == nil {
		return nil, false
	}
	var out []*regexp.Regexp
	for name, s := range doc.Systems {
		if s.Adapter == "ledger" || name == "ledger" {
			continue
		}
		for _, pat := range s.Repos {
			if re, err := regexp.Compile("(?i)" + pat); err == nil {
				out = append(out, re)
			}
		}
	}
	return out, true
}

// normalizedURLs mirrors commit_policy.py normalized_urls.
func normalizedURLs(raw string) []string {
	u := strings.TrimSpace(raw)
	var host, p string
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return nil
		}
		authority, pth := rest[:slash], rest[slash:]
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			authority = authority[at+1:]
		}
		if c := strings.LastIndexByte(authority, ':'); c >= 0 {
			authority = authority[:c]
		}
		host, p = authority, pth
	} else {
		m := scpRe.FindStringSubmatch(u)
		if m == nil || len(m[1]) == 1 {
			return nil
		}
		host, p = m[1], m[2]
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if un, err := url.PathUnescape(p); err == nil {
		p = un
	}
	p = strings.TrimLeft(path.Clean("/"+p), "/")
	p = gitRe.ReplaceAllString(p, "")
	if host == "" {
		return nil
	}
	return []string{"https://" + host + "/" + p + "/", host + ":" + p + "/"}
}

// RemoteURLs lists every fetch and push URL configured in the repository at cwd (raw, no insteadOf).
func RemoteURLs(cwd string) []string {
	env := gitx.Default(gitx.Options{Isolated: true})
	res, err := proc.Run([]string{"git", "-C", cwd, "config", "--get-regexp", `^remote\..*\.(url|pushurl)$`},
		proc.Options{Env: env, Timeout: 3 * time.Second})
	if err != nil || res.Code != 0 {
		return nil
	}
	var urls []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if _, v, ok := strings.Cut(line, " "); ok {
			v = strings.TrimSpace(v)
			if v != "" && !seen[v] {
				seen[v] = true
				urls = append(urls, v)
			}
		}
	}
	return urls
}

// Tracked reports whether any remote of the repository at cwd matches a GoodQA repos pattern, and whether
// the policy could be read (known).
func Tracked(cwd string) (tracked, known bool) {
	patterns, ok := trackedPatterns()
	if !ok {
		return false, false
	}
	var variants []string
	for _, u := range RemoteURLs(cwd) {
		variants = append(variants, u, portRe.ReplaceAllString(u, "/"))
		variants = append(variants, normalizedURLs(u)...)
	}
	for _, v := range variants {
		for _, re := range patterns {
			if re.MatchString(v) {
				return true, true
			}
		}
	}
	return false, true
}
