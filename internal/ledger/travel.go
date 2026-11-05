package ledger

// Phase 0b travel: carry a ledger through git as hidden refs, on explicit command only.
//
//   - Nothing is added to remote.<name>.push or remote.<name>.fetch, so ordinary git push and fetch never
//     move ledger refs.
//   - Push sends only this HOME's own writer refs, from the HOME mirror, never forced.
//   - Fetch goes into a disposable bare directory, is validated with the bounded reader, and only then
//     reaches the repository, as a fast-forward and never over an own ref. Fetched writers stay
//     unverified until trust-writer.
//   - Consent is bound to the exact remote URLs: if either changes, push and fetch refuse.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/scan"
	"github.com/ericmacdougall/agent-harness/internal/ledger/store"
)

const (
	travelFile    = "travel.json"
	fetchDirGlob  = ".fetch-"
	fetchStaleAge = time.Hour
	// FetchCap stops a fetch that grows its disposable directory past this size.
	FetchCap = int64(64) << 20
)

var remoteNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// TravelConfig is the recorded consent.
type TravelConfig struct {
	Remote     string
	Endpoint   string // sha256 of the fetch and push URLs consented to
	PushedMs   int64
	FetchedMs  int64
	PushedOps  map[string]int // writer -> ops at the last push
	FetchedOps map[string]int // writer -> ops at the last fetch
}

type travelJSON struct {
	V          int            `json:"v"`
	Ledger     string         `json:"ledger_project"`
	Remote     string         `json:"remote"`
	Endpoint   string         `json:"endpoint_sha256"`
	PushedMs   int64          `json:"pushed_ms"`
	FetchedMs  int64          `json:"fetched_ms"`
	PushedOps  map[string]int `json:"pushed_ops"`
	FetchedOps map[string]int `json:"fetched_ops"`
}

// ConsentError is returned by TravelEnable when the token is missing or wrong; its text is the warning.
type ConsentError struct{ Token, Remote, Fetch, Push string }

func (e *ConsentError) Error() string {
	return fmt.Sprintf("travel would publish this ledger, including every ticket, comment and its full history, "+
		"to everyone who can read remote %q, and publishing cannot be undone; ops carry writer ids, claimed actor labels "+
		"and wall times. The harness cannot tell whether the remote is public. To proceed run: "+
		"harness tickets travel enable --remote %s --yes-share %s. URLs: fetch %s, push %s", e.Remote, e.Remote, e.Token, shownURL(e.Fetch), shownURL(e.Push))
}

func endpointSum(fetch, push string) string {
	s := sha256.Sum256([]byte(fetch + "\n" + push))
	return hex.EncodeToString(s[:])
}

// URLToken is the consent token for a remote's URLs: the first 8 hex of the endpoint hash.
func URLToken(fetch, push string) string { return endpointSum(fetch, push)[:8] }

// endpoints reads a remote's fetch and push URLs once from the repository config (raw, no insteadOf).
func (l *Ledger) endpoints(remote string) (fetch, push string, err error) {
	if !l.InRepo {
		return "", "", wrap(ErrRefused, "a repo-less ledger has no git remote to travel through")
	}
	if !remoteNameRe.MatchString(remote) {
		return "", "", wrap(ErrUsage, "remote name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	return remoteURLs(l.Git, remote)
}

func remoteURLs(g *store.Git, remote string) (fetch, push string, err error) {
	fetch = g.ConfigGet("remote." + remote + ".url")
	if fetch == "" {
		return "", "", wrap(ErrNotFound, "no remote %q in this repository", remote)
	}
	push = g.ConfigGet("remote." + remote + ".pushurl")
	if push == "" {
		push = fetch
	}
	for _, u := range []string{fetch, push} {
		if verr := store.ValidateURL(u); verr != nil {
			return "", "", wrap(ErrRefused, "remote %q: %v", remote, verr)
		}
	}
	return fetch, push, nil
}

// ReadTravel returns the recorded consent, or nil.
func (l *Ledger) ReadTravel() *TravelConfig {
	d, err := l.homeDir(false)
	if err != nil {
		return nil
	}
	defer d.Close()
	b, err := d.ReadRegular(travelFile, stateMax)
	if err != nil {
		return nil
	}
	var j travelJSON
	if json.Unmarshal(b, &j) != nil || j.V != 1 || j.Ledger != l.Project || !remoteNameRe.MatchString(j.Remote) {
		return nil
	}
	if j.PushedOps == nil {
		j.PushedOps = map[string]int{}
	}
	if j.FetchedOps == nil {
		j.FetchedOps = map[string]int{}
	}
	return &TravelConfig{Remote: j.Remote, Endpoint: j.Endpoint, PushedMs: j.PushedMs, FetchedMs: j.FetchedMs,
		PushedOps: j.PushedOps, FetchedOps: j.FetchedOps}
}

func (l *Ledger) writeTravel(c *TravelConfig) error {
	j := travelJSON{V: 1, Ledger: l.Project, Remote: c.Remote, Endpoint: c.Endpoint, PushedMs: c.PushedMs,
		FetchedMs: c.FetchedMs, PushedOps: c.PushedOps, FetchedOps: c.FetchedOps}
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return l.replaceHome(travelFile, append(body, '\n'))
}

// TravelEnable records consent for remote. It refuses (with a ConsentError carrying the token) unless
// token equals URLToken of the remote's current URLs.
func (l *Ledger) TravelEnable(remote, token string) error {
	fetch, push, err := l.endpoints(remote)
	if err != nil {
		return err
	}
	want := URLToken(fetch, push)
	if token != want {
		return &ConsentError{Token: want, Remote: remote, Fetch: fetch, Push: push}
	}
	return l.writeTravel(&TravelConfig{Remote: remote, Endpoint: endpointSum(fetch, push),
		PushedOps: map[string]int{}, FetchedOps: map[string]int{}})
}

// consented returns the consent and the URLs it was given for, or an error when none or changed.
func (l *Ledger) consented() (*TravelConfig, string, string, error) {
	c := l.ReadTravel()
	if c == nil {
		return nil, "", "", wrap(ErrRefused, "travel is not enabled for this ledger (see `travel enable`)")
	}
	fetch, push, err := l.endpoints(c.Remote)
	if err != nil {
		return nil, "", "", err
	}
	if endpointSum(fetch, push) != c.Endpoint {
		return nil, "", "", wrap(ErrRefused, "the URL of remote %q changed since you consented; run `travel enable` again", c.Remote)
	}
	return c, fetch, push, nil
}

// TravelWriter is one writer row of `travel status`.
type TravelWriter struct {
	ID       string
	Class    string
	Ops      int
	Unpushed int // own writers: ops since the last push
	Bytes    int64
}

// TravelStatus lists the consent and the writers, with no network access.
func (l *Ledger) TravelStatus() (*TravelConfig, bool, []TravelWriter, error) {
	c := l.ReadTravel()
	ok := false
	if c != nil {
		if f, p, err := l.endpoints(c.Remote); err == nil && endpointSum(f, p) == c.Endpoint {
			ok = true
		}
	}
	in, err := l.Snapshot()
	if err != nil {
		return c, ok, nil, err
	}
	var ws []TravelWriter
	for _, r := range in.Refs {
		w := TravelWriter{ID: r.Writer, Class: in.Class(r.Writer), Ops: len(r.Ops)}
		for _, o := range r.Ops {
			w.Bytes += int64(len(o.Raw)) + 1
		}
		if w.Class == "self" && c != nil {
			w.Unpushed = w.Ops - c.PushedOps[r.Writer]
		}
		ws = append(ws, w)
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i].ID < ws[j].ID })
	return c, ok, ws, nil
}

// PushResult is what travel push did.
type PushResult struct{ Refs []string }

// TravelPush pushes this HOME's own writer refs (from the mirror) to the consented remote.
func (l *Ledger) TravelPush() (*PushResult, error) {
	c, _, push, err := l.consented()
	if err != nil {
		return nil, err
	}
	mirror := l.homeMirror()
	if mirror == nil {
		return nil, wrap(ErrRefused, "this HOME has no mirror of the ledger, so nothing of its own can be pushed")
	}
	classes, mirrored, _, err := l.classes()
	if err != nil {
		return nil, err
	}
	var refs []string
	counts := map[string]int{}
	total := store.UnverifiedViewBudget
	var writers []string
	for w, cl := range classes {
		if cl == "self" {
			writers = append(writers, w)
		}
	}
	sort.Strings(writers)
	for _, w := range writers {
		tip := mirrored[w]
		if tip == "" {
			continue
		}
		budget := store.UnverifiedBudget
		packs, err := mirror.ReadRefBudget(l.Project, w, tip, &budget, store.UnverifiedMaxChain)
		if err != nil {
			return nil, wrap(ErrRefused, "writer %s is too large or invalid to travel (a peer reads at most %d MiB and %d commits per writer): %v",
				w, store.UnverifiedBudget>>20, store.UnverifiedMaxChain, err)
		}
		if total -= store.UnverifiedBudget - budget; total < 0 {
			return nil, wrap(ErrRefused, "the ledger is larger than the %d MiB a peer reads in one view", store.UnverifiedViewBudget>>20)
		}
		var pairs [][2]string
		n := 0
		for _, p := range packs {
			for _, o := range p.Ops {
				pairs = append(pairs, [2]string{"op " + o.ID, string(o.Raw)})
				n++
			}
		}
		if found := scan.Scan(pairs); len(found) > 0 {
			return nil, &SecretError{Findings: found}
		}
		refs = append(refs, store.RefName(l.Project, w))
		counts[w] = n
	}
	if len(refs) == 0 {
		return &PushResult{}, nil
	}
	if err := mirror.PushRefs(push, refs); err != nil {
		return nil, wrap(ErrRefused, "the remote refused or could not take the ledger refs (not a fast-forward, a host that refuses non-branch refs, or unreachable): %v", err)
	}
	c.PushedMs, _ = Now()
	for w, n := range counts {
		c.PushedOps[w] = n
	}
	if err := l.writeTravel(c); err != nil {
		return nil, err
	}
	return &PushResult{Refs: refs}, nil
}

// FetchResult is what travel fetch did.
type FetchResult struct {
	Accepted []string
	Rejected map[string]string
	Skipped  []string
	Project  string
}

func cleanStale(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), fetchDirGlob) {
			if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > fetchStaleAge {
				os.RemoveAll(filepath.Join(dir, e.Name()))
			}
		}
	}
}

// fetchToTemp fetches the refs matching pattern into a new disposable bare directory under parent.
func fetchToTemp(parent, fetchURL, pattern, refspec string) (*store.Git, map[string]string, func(), error) {
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, nil, func() {}, wrap(ErrRefused, "cannot create %s: %v", parent, err)
	}
	cleanStale(parent)
	tmp, err := os.MkdirTemp(parent, fetchDirGlob)
	if err != nil {
		return nil, nil, func() {}, err
	}
	cleanup := func() { os.RemoveAll(tmp) }
	if err := store.InitBare(tmp, "fetch"); err != nil {
		cleanup()
		return nil, nil, func() {}, err
	}
	g := &store.Git{GitDir: tmp}
	if _, err := g.LsRemote(fetchURL, pattern); err != nil {
		cleanup()
		return nil, nil, func() {}, wrap(ErrRefused, "%v", err)
	}
	if err := g.FetchCapped(fetchURL, refspec, FetchCap); err != nil {
		cleanup()
		return nil, nil, func() {}, wrap(ErrRefused, "fetch failed: %v", err)
	}
	got, _, err := g.Refs()
	if err != nil || len(got) > store.MaxRemoteLedgerRefs {
		cleanup()
		return nil, nil, func() {}, wrap(ErrRefused, "the fetch returned too many or unreadable ledger refs")
	}
	return g, got, cleanup, nil
}

// TravelFetch fetches other writers' refs for this ledger's project.
func (l *Ledger) TravelFetch() (*FetchResult, error) {
	c, fetch, _, err := l.consented()
	if err != nil {
		return nil, err
	}
	home, err := l.homeDir(true)
	if err != nil {
		return nil, err
	}
	homePath := filepath.Dir(mustMirror(l.Project))
	home.Close()
	classes, _, _, err := l.classes()
	if err != nil {
		return nil, err
	}
	me := l.CurrentWriterID()
	g, got, cleanup, err := fetchToTemp(homePath, fetch, store.RefPrefix+l.Project+"/log/*", store.RefPrefix+l.Project+"/log/*:"+store.RefPrefix+l.Project+"/log/*")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	res := &FetchResult{Rejected: map[string]string{}, Project: l.Project}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		proj, w, ok := store.ParseRefName(name)
		switch {
		case !ok || proj != l.Project:
			res.Rejected[name] = "not a ledger ref of this project"
		case classes[w] == "self" || w == me:
			res.Skipped = append(res.Skipped, w)
		case classes[w] == "blocked":
			res.Skipped = append(res.Skipped, w)
		default:
			if why := validateAndLand(g, l.Root, proj, w, name, got[name]); why != "" {
				res.Rejected[w] = why
			} else {
				res.Accepted = append(res.Accepted, w)
				if refOps, err := countOps(g, proj, w, got[name]); err == nil {
					c.FetchedOps[w] = refOps
				}
			}
		}
	}
	c.FetchedMs, _ = Now()
	if err := l.writeTravel(c); err != nil {
		return nil, err
	}
	return res, nil
}

func mustMirror(project string) string {
	m, _ := MirrorDir(project)
	return m
}

func countOps(g *store.Git, proj, w, tip string) (int, error) {
	budget := store.UnverifiedBudget
	packs, err := g.ReadRefBudget(proj, w, tip, &budget, store.UnverifiedMaxChain)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range packs {
		n += len(p.Ops)
	}
	return n, nil
}

// validateAndLand validates one fetched ref with the bounded reader and copies it into the repository as a
// plain fast-forward. It returns "" on success or the reason it was rejected.
func validateAndLand(g *store.Git, repo, proj, w, name, tip string) string {
	budget := store.UnverifiedBudget
	if _, err := g.ReadRefBudget(proj, w, tip, &budget, store.UnverifiedMaxChain); err != nil {
		return "rejected by the bounded reader: " + sanitizeReason(err.Error())
	}
	if err := g.PushForeign(repo, name); err != nil {
		return "not a fast-forward of the ref already here (rewritten history), or it could not be copied"
	}
	return ""
}

func sanitizeReason(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

var errAdopt = errors.New("adopt")

// TravelAdopt creates this repository's ledger from a remote's ledger refs (a second machine joining an
// existing ledger). The fetched writers stay unverified, so the ledger cannot be used until they are
// reviewed with `writers --show` and trusted with `trust-writer`.
func TravelAdopt(loc Location, remote, token string) (*Ledger, *FetchResult, error) {
	common, inRepo, err := store.CommonDir(loc.Cwd)
	if err != nil {
		return nil, nil, err
	}
	if !inRepo {
		return nil, nil, wrap(ErrUsage, "adopting a remote ledger needs a git repository")
	}
	if !remoteNameRe.MatchString(remote) {
		return nil, nil, wrap(ErrUsage, "remote name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	if d, err := openGoodqa(common, false); err == nil {
		_, perr := readProjects(d)
		d.Close()
		if perr == nil {
			return nil, nil, wrap(ErrRefused, "this repository already has a ledger; use `travel fetch`")
		}
	}
	repo := &store.Git{GitDir: common}
	fetch, push, err := remoteURLs(repo, remote)
	if err != nil {
		return nil, nil, err
	}
	if want := URLToken(fetch, push); token != want {
		return nil, nil, &ConsentError{Token: want, Remote: remote, Fetch: fetch, Push: push}
	}
	home, err := LedgersHome()
	if err != nil {
		return nil, nil, err
	}
	g, got, cleanup, err := fetchToTemp(home, fetch, store.RefPrefix+"*/log/*", store.RefPrefix+"*:"+store.RefPrefix+"*")
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()
	projects := map[string]bool{}
	for name := range got {
		if p, _, ok := store.ParseRefName(name); ok {
			projects[p] = true
		}
	}
	if len(projects) != 1 {
		return nil, nil, wrap(ErrRefused, "the remote holds %d ledger projects; adopt needs exactly one", len(projects))
	}
	var project string
	for p := range projects {
		project = p
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	res := &FetchResult{Rejected: map[string]string{}, Project: project}
	slug, rootName := "", ""
	for _, name := range names {
		_, w, ok := store.ParseRefName(name)
		if !ok {
			continue
		}
		budget := store.UnverifiedBudget
		packs, err := g.ReadRefBudget(project, w, got[name], &budget, store.UnverifiedMaxChain)
		if err != nil {
			res.Rejected[w] = "rejected by the bounded reader: " + sanitizeReason(err.Error())
			continue
		}
		for _, p := range packs {
			for _, o := range p.Ops {
				if o.Kind == op.KindProjectCreate && strings.TrimPrefix(o.ID, op.PrefixOp) == strings.TrimPrefix(project, op.PrefixProject) {
					slug, rootName = o.Str("slug"), o.Str("name")
				}
			}
		}
	}
	_ = rootName
	if slug == "" || !op.ValidSlug(slug) {
		return nil, nil, wrap(ErrRefused, "the remote's ledger has no readable project root; nothing adopted")
	}
	if p, err := slugTaken(slug); err != nil {
		return nil, nil, err
	} else if p != "" {
		return nil, nil, wrap(ErrRefused, "slug %q is already used on this machine by %s", slug, p)
	}
	for _, name := range names {
		_, w, ok := store.ParseRefName(name)
		if !ok || res.Rejected[w] != "" {
			continue
		}
		if why := validateAndLand(g, common, project, w, name, got[name]); why != "" {
			res.Rejected[w] = why
		} else {
			res.Accepted = append(res.Accepted, w)
		}
	}
	if len(res.Accepted) == 0 {
		return nil, nil, wrap(ErrRefused, "no ledger ref from the remote passed validation")
	}
	mdir, _ := MirrorDir(project)
	if err := store.InitBare(mdir, "mirror"); err != nil {
		return nil, nil, wrap(ErrRefused, "mirror could not be created: %v", err)
	}
	d, err := openGoodqa(common, true)
	if err != nil {
		return nil, nil, err
	}
	l := &Ledger{Root: common, InRepo: true, Dir: d, Git: &store.Git{GitDir: common}, Project: project, Slug: slug}
	if err := l.Dir.PublishNew(projectsFile, projectsBody(project, slug)); err != nil {
		l.Close()
		return nil, nil, err
	}
	if err := writeMeta(project, slug, "mirror"); err != nil {
		l.warn = append(l.warn, "ledger registry entry could not be written: "+err.Error())
	}
	if err := l.writeTravel(&TravelConfig{Remote: remote, Endpoint: endpointSum(fetch, push),
		PushedOps: map[string]int{}, FetchedOps: map[string]int{}}); err != nil {
		l.warn = append(l.warn, "travel consent could not be recorded: "+err.Error())
	}
	return l, res, nil
}

// shownURL renders a URL for a consent prompt: credentials removed, control characters escaped, bounded.
func shownURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if at := strings.Index(strings.SplitN(rest, "/", 2)[0], "@"); at >= 0 {
			u = u[:i+3] + rest[at+1:]
		}
	}
	if len(u) > 200 {
		u = u[:200] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, u)
}
