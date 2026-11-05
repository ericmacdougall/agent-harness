// Package ledger is the Phase 0a local ticket ledger: an append-only op log in hidden git refs under a
// repository's common dir (or a private bare repository for repo-less ledgers), folded into a view that
// contains only self and trusted writers. All writes happen under <goodqa>/writer.lock.
package ledger

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/scan"
	"github.com/ericmacdougall/agent-harness/internal/ledger/store"
	"github.com/ericmacdougall/agent-harness/internal/ledger/writer"
	"github.com/ericmacdougall/agent-harness/internal/lock"
	"github.com/ericmacdougall/agent-harness/internal/pycompat"
	"github.com/ericmacdougall/agent-harness/internal/safefs"
)

// Version is the ledger format/CLI contract version checked by the commit-policy shim (--min-version).
const Version = "0.1.0"

// LockWait is how long a writer waits for writer.lock before reporting busy.
const LockWait = 10 * time.Second

// Test-only environment (refused in release builds; see writer.TestHooksAllowed).
const (
	FakeNowEnv        = "HARNESS_LEDGER_FAKE_NOW_MS"
	CrashAfterCASEnv  = "HARNESS_LEDGER_TEST_CRASH_AFTER_CAS"
	LockWaitEnv       = "HARNESS_LEDGER_TEST_LOCK_WAIT_MS"
	ViewBudgetEnv     = "HARNESS_LEDGER_TEST_VIEW_BUDGET"
	FailFirstFoldEnv  = "HARNESS_LEDGER_TEST_FAIL_FIRST_FOLD"
	FailPublishEnv    = "HARNESS_LEDGER_TEST_FAIL_BEFORE_PUBLISH"
	FailViewAfterEnv  = "HARNESS_LEDGER_TEST_FAIL_VIEW_AFTER_COMMIT"
	DirName           = "goodqa"
	projectsFile      = "projects.json"
	cacheFile         = "view.cache.json"
	lockFile          = "writer.lock"
	metaFile          = "meta.json"
	mirrorWritersFile = "mirror-writers.json"
	mirrorWritersLock = "mirror-writers.lock"
	cacheKeyFile      = "cache.key"
)

// Error kinds, mapped to exit codes by the CLI.
var (
	ErrUsage     = errors.New("usage")       // 2
	ErrRefused   = errors.New("refused")     // 3
	ErrNotFound  = errors.New("not_found")   // 3
	ErrAmbiguous = errors.New("ambiguous")   // 3
	ErrBusy      = errors.New("ledger busy") // 6
	ErrSecret    = errors.New("secret")      // 2
	ErrNoLedger  = errors.New("no ledger")   // 2
)

func wrap(kind error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, a...))
}

// CheckTestEnv refuses test-only variables in release builds, before any work is done.
func CheckTestEnv() error {
	if writer.TestHooksAllowed {
		return nil
	}
	for _, k := range []string{FakeNowEnv, CrashAfterCASEnv, LockWaitEnv, ViewBudgetEnv, FailFirstFoldEnv, FailPublishEnv, FailViewAfterEnv, writer.FakeMachineIDEnv} {
		if _, ok := os.LookupEnv(k); ok {
			return wrap(ErrUsage, "%s is a test-only variable, refused by builds without -tags ledgertest", k)
		}
	}
	return nil
}

// Now returns the current time in ms (or the development-build fake clock).
func Now() (int64, error) {
	if v, ok := os.LookupEnv(FakeNowEnv); ok {
		if !writer.TestHooksAllowed {
			return 0, writer.ErrTestHookInRelease
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, wrap(ErrUsage, "%s must be an integer", FakeNowEnv)
		}
		return n, nil
	}
	return time.Now().UnixMilli(), nil
}

// LedgersHome is ~/.agent-harness/ledgers.
func LedgersHome() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(h) {
		return "", errors.New("cannot resolve the home directory")
	}
	return filepath.Join(h, ".agent-harness", "ledgers"), nil
}

// Ledger is an opened ledger.
type Ledger struct {
	Root    string // git dir holding the refs: the repo common dir, or the repo-less bare repo
	InRepo  bool
	Dir     *safefs.Dir // <Root>/goodqa
	Git     *store.Git
	Project string
	Slug    string
	warn    []string

	cacheSecret []byte // this HOME's view-cache key; nil until loaded, empty when unavailable
	reviewing   bool   // WriterReview reads a trusted writer's full ops, not its reviewed prefix
}

// Warnings collected while opening or writing (printed by the CLI on stderr).
func (l *Ledger) Warnings() []string { return l.warn }

// Close releases the pinned directory.
func (l *Ledger) Close() {
	if l.Dir != nil {
		l.Dir.Close()
	}
}

// Location says where commands act: in a repository, or a repo-less ledger selected by slug.
type Location struct {
	Cwd  string
	Slug string // only for repo-less ledgers (outside any repository)
}

// projects.json entry.
type projectEntry struct {
	Project string `json:"project"`
	Slug    string `json:"slug"`
	Travel  struct {
		Mode string `json:"mode"`
	} `json:"travel"`
}

var projectsRe = regexp.MustCompile(`^[\[\]{}",:a-zA-Z0-9_ \n-]*$`)

func readProjects(d *safefs.Dir) (projectEntry, error) {
	b, err := d.ReadRegular(projectsFile, 64*1024)
	if err != nil {
		return projectEntry{}, err
	}
	if !projectsRe.Match(b) {
		return projectEntry{}, wrap(ErrRefused, "projects.json contains unexpected characters")
	}
	var ps []projectEntry
	if err := json.Unmarshal(b, &ps); err != nil || len(ps) != 1 {
		return projectEntry{}, wrap(ErrRefused, "projects.json is malformed (0a supports exactly one project)")
	}
	p := ps[0]
	if !op.ValidID(p.Project, op.PrefixProject) || !op.ValidSlug(p.Slug) || p.Travel.Mode != "local" {
		return projectEntry{}, wrap(ErrRefused, "projects.json has an invalid project id, slug or travel mode")
	}
	return p, nil
}

func projectsBody(project, slug string) []byte {
	b, _ := pycompat.Canonical([]any{map[string]any{"project": project, "slug": slug,
		"travel": map[string]any{"mode": "local"}}})
	return append(b, '\n')
}

// openGoodqa pins <root>/goodqa, refusing a symlink or a directory others can read.
func openGoodqa(root string, create bool) (*safefs.Dir, error) {
	p := filepath.Join(root, DirName)
	li, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) && !create {
		return nil, ErrNoLedger
	}
	if err == nil && li.Mode()&fs.ModeSymlink != 0 {
		return nil, wrap(ErrRefused, "%s is a symlink; refusing", DirName)
	}
	parent, err := safefs.OpenDir(root)
	if err != nil {
		return nil, wrap(ErrRefused, "cannot pin the git dir: %v", err)
	}
	defer parent.Close()
	var d *safefs.Dir
	if create {
		d, err = parent.MkdirPrivate(DirName)
	} else {
		d, err = safefs.OpenDir(p)
	}
	if err != nil {
		return nil, wrap(ErrRefused, "cannot open %s: %v", DirName, err)
	}
	li, err = os.Lstat(p)
	if err != nil || !li.IsDir() || li.Mode().Perm()&0o077 != 0 {
		d.Close()
		return nil, wrap(ErrRefused, "%s must be a private directory (mode 0700)", DirName)
	}
	return d, nil
}

// MaxUnverifiedRefs caps how many refs from writers that are not this machine's are read per view; the
// rest are listed as rejected without being read (anyone who can write the repository can plant refs).
const MaxUnverifiedRefs = 64

// Open opens the ledger for loc. It does not create anything.
func Open(loc Location) (*Ledger, error) {
	common, inRepo, err := store.CommonDir(loc.Cwd)
	if err != nil {
		return nil, err
	}
	root := common
	if !inRepo || loc.Slug != "" {
		if inRepo && loc.Slug != "" {
			// Inside a repository --slug may only name this repository's own ledger.
			l, err := openAt(common, true)
			if err != nil {
				return nil, err
			}
			if l.Slug != loc.Slug {
				l.Close()
				return nil, wrap(ErrNotFound, "this repository's ledger is %q, not %q", l.Slug, loc.Slug)
			}
			return l, nil
		}
		if loc.Slug == "" {
			return nil, wrap(ErrNoLedger, "not in a git repository; pass --slug to select a repo-less ledger")
		}
		if root, err = findRepoless(loc.Slug); err != nil {
			return nil, err
		}
	}
	return openAt(root, inRepo)
}

func openAt(root string, inRepo bool) (*Ledger, error) {
	d, err := openGoodqa(root, false)
	if err != nil {
		if errors.Is(err, ErrNoLedger) {
			return nil, wrap(ErrNoLedger, "no ledger here; run `harness tickets init`")
		}
		return nil, err
	}
	p, err := readProjects(d)
	if err != nil {
		d.Close()
		if errors.Is(err, fs.ErrNotExist) {
			return nil, wrap(ErrNoLedger, "no ledger here; run `harness tickets init`")
		}
		return nil, err
	}
	return &Ledger{Root: root, InRepo: inRepo, Dir: d, Git: &store.Git{GitDir: root}, Project: p.Project, Slug: p.Slug}, nil
}

type meta struct {
	Project string `json:"project"`
	Slug    string `json:"slug"`
	Role    string `json:"role"` // "ledger" (repo-less) or "mirror"
}

func readMeta(dir string) (meta, error) {
	d, err := safefs.OpenDir(dir)
	if err != nil {
		return meta{}, err
	}
	defer d.Close()
	b, err := d.ReadRegular(metaFile, 4096)
	if err != nil {
		return meta{}, err
	}
	var m meta
	if err := json.Unmarshal(b, &m); err != nil || !op.ValidID(m.Project, op.PrefixProject) || !op.ValidSlug(m.Slug) ||
		(m.Role != "ledger" && m.Role != "mirror") || filepath.Base(dir) != m.Project {
		return meta{}, errors.New("malformed meta.json")
	}
	return m, nil
}

// machineLedgers lists every ledger directory on this machine with its meta.
func machineLedgers() ([]meta, string, error) {
	home, err := LedgersHome()
	if err != nil {
		return nil, "", err
	}
	ents, err := os.ReadDir(home)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, home, nil
	}
	if err != nil {
		return nil, "", err
	}
	var out []meta
	for _, e := range ents {
		if !e.IsDir() || !op.ValidID(e.Name(), op.PrefixProject) {
			continue
		}
		if m, err := readMeta(filepath.Join(home, e.Name())); err == nil {
			out = append(out, m)
		}
	}
	return out, home, nil
}

func findRepoless(slug string) (string, error) {
	ms, home, err := machineLedgers()
	if err != nil {
		return "", err
	}
	var hits []string
	for _, m := range ms {
		if m.Slug == slug && m.Role == "ledger" {
			hits = append(hits, filepath.Join(home, m.Project, "repo.git"))
		}
	}
	switch len(hits) {
	case 0:
		return "", wrap(ErrNotFound, "no repo-less ledger with slug %q", slug)
	case 1:
		return hits[0], nil
	}
	return "", wrap(ErrAmbiguous, "several repo-less ledgers have slug %q", slug)
}

// MirrorDir is the bare mirror of a repository ledger: the store of record for this HOME's writers.
func MirrorDir(project string) (string, error) {
	home, err := LedgersHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, project, "mirror.git"), nil
}

// ---------------------------------------------------------------------------------------- view

// classes gives each writer of this checkout its fold class. mirrored maps each self writer of a
// repository ledger to its tip in this HOME's mirror ("" when the mirror holds nothing for it): those refs
// are read from the mirror, never from the repository, whose refs, objects, commit-graph and grafts travel
// with a copied .git.
func (l *Ledger) classes() (classes map[string]string, mirrored map[string]string, mirror *store.Git, err error) {
	m, _, err := writer.Load(l.Dir)
	if err != nil {
		return nil, nil, nil, err
	}
	// 0a folds only this machine's own writers. trust.json is not read: no 0a command writes it, and it
	// would travel with a copied .git. A repository ledger's writer counts as self only when this HOME's
	// registry recorded it (with the same lease); writer.json alone proves nothing. A repo-less ledger
	// already lives under this HOME.
	out := map[string]string{}
	mirrored = map[string]string{}
	var reg map[string]string
	if l.InRepo {
		reg = l.registry()
		mirror = l.homeMirror()
	}
	for _, e := range m.Writers {
		if !l.InRepo {
			out[e.Writer] = fold.ClassSelf
			continue
		}
		h, ok := reg[e.Writer]
		switch {
		case !ok:
		case e.Restored && e.Lease == "":
			// A restored writer's id and lease hash are not secret, so a planted "restored" entry proves
			// nothing by itself: the writer counts only through the copy of its ref in this HOME's mirror,
			// and that copy is what is read (the original checkout may still be appending to it).
			if tip := mirrorTip(mirror, l.Project, e.Writer); tip != "" {
				out[e.Writer] = fold.ClassSelf
				mirrored[e.Writer] = tip
			}
		case h == store.LeaseHash(e.Lease):
			out[e.Writer] = fold.ClassSelf
			if mirror != nil {
				// Read from the mirror, where this writer appends ("" = nothing written yet), never from
				// the repository's copy.
				mirrored[e.Writer] = mirrorTip(mirror, l.Project, e.Writer)
			}
		}
	}
	l.applyTrust(out)
	return out, mirrored, mirror, nil
}

func mirrorTip(mirror *store.Git, project, w string) string {
	if mirror == nil {
		return ""
	}
	tip, err := mirror.Tip(store.RefName(project, w))
	if err != nil {
		return ""
	}
	return tip
}

type snapshot struct {
	tips       map[string]string
	bad        []string
	classes    map[string]string
	key        string
	mirror     *store.Git
	fromMirror map[string]bool // refs read from the HOME mirror (own writers of a repository ledger)
}

func (l *Ledger) snapshot() (*snapshot, error) {
	refs, bad, err := l.Git.Refs()
	if err != nil {
		return nil, err
	}
	classes, mirrored, mirror, err := l.classes()
	if err != nil {
		return nil, err
	}
	fromMirror := map[string]bool{}
	src := map[string]any{}
	for w, tip := range mirrored {
		r := store.RefName(l.Project, w)
		if tip == "" {
			delete(refs, r) // the mirror has nothing for this writer, so neither does the view
			src[r] = "mirror"
			continue
		}
		refs[r], fromMirror[r], src[r] = tip, true, "mirror"
	}
	tips := map[string]any{}
	for r, t := range refs {
		tips[r] = t
	}
	cl := map[string]any{}
	for w, c := range classes {
		cl[w] = c
	}
	badAny := make([]any, len(bad))
	sort.Strings(bad)
	for i, b := range bad {
		badAny[i] = b
	}
	// The reviewed prefix of each trusted writer decides which of its ops fold, so it is part of the key.
	trust := map[string]any{}
	for w, e := range l.ReadTrust().Trusted {
		trust[w] = strconv.Itoa(e.Ops) + ":" + e.Digest
	}
	k, err := pycompat.Canonical(map[string]any{"v": Version, "project": l.Project, "tips": tips, "classes": cl, "bad": badAny, "sources": src, "trust": trust})
	if err != nil {
		return nil, err
	}
	return &snapshot{tips: refs, bad: bad, classes: classes, key: fold.HandleHash(string(k)), mirror: mirror, fromMirror: fromMirror}, nil
}

// readAll reads and validates every writer ref of the project. Refs of other projects and malformed names
// are reported, never read.
func (l *Ledger) readAll(s *snapshot) (fold.Input, error) {
	in := fold.Input{Project: l.Project, Classes: s.classes}
	names := make([]string, 0, len(s.tips))
	for r := range s.tips {
		names = append(names, r)
	}
	// Folded (self/trusted) refs are read first, so an op id that an unverified or blocked ref copies
	// can only ever reject that ref, never the folded ref whose op it collides with.
	folded := func(r string) bool {
		_, w, _ := store.ParseRefName(r)
		return fold.Folded(in.Class(w))
	}
	sort.Slice(names, func(i, j int) bool {
		if fi, fj := folded(names[i]), folded(names[j]); fi != fj {
			return fi
		}
		return names[i] < names[j]
	})
	seen := map[string][]byte{} // op id -> bytes, across refs
	unfolded := 0
	viewLeft := store.UnverifiedViewBudget // shared by every unverified ref in this view
	if v := os.Getenv(ViewBudgetEnv); v != "" && writer.TestHooksAllowed {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			viewLeft = n
		}
	}
	for _, r := range names {
		proj, w, _ := store.ParseRefName(r)
		if proj != l.Project {
			continue
		}
		if in.Class(w) == fold.ClassBlocked {
			continue // a blocked writer is never read and never uses the unverified budget
		}
		ref := fold.Ref{Writer: w}
		budget, chain := store.FoldedBudget, store.MaxChain
		if !folded(r) {
			if unfolded++; unfolded > MaxUnverifiedRefs || viewLeft <= 0 {
				ref.Rejected = fmt.Sprintf("read limit for refs from writers that are not this machine's reached "+
					"(%d refs or %d MiB per view); not read", MaxUnverifiedRefs, store.UnverifiedViewBudget>>20)
				in.Refs = append(in.Refs, ref)
				continue
			}
			budget, chain = min(store.UnverifiedBudget, viewLeft), store.UnverifiedMaxChain
		}
		allowed := budget
		g := l.Git
		if s.fromMirror[r] {
			g = s.mirror
		}
		packs, err := g.ReadRefBudget(proj, w, s.tips[r], &budget, chain)
		if !folded(r) {
			viewLeft -= allowed - budget // what was read, whether or not the ref was then rejected
		}
		if err != nil {
			ref.Rejected = err.Error()
			in.Refs = append(in.Refs, ref)
			continue
		}
		var ops []*op.Op
		dup := ""
		for _, p := range packs {
			for _, o := range p.Ops {
				if prev, ok := seen[o.ID]; ok {
					if !bytes.Equal(prev, o.Raw) {
						dup = "op id reused with different bytes"
					}
					continue
				}
				ops = append(ops, o)
			}
		}
		if dup == "" && in.Class(w) == fold.ClassTrusted && !l.reviewing {
			if n, ok := l.trustPrefix(w, ops); !ok {
				in.Classes[w] = fold.ClassUnverified // the reviewed prefix changed: not trusted
			} else if n < len(ops) {
				if in.Held == nil {
					in.Held = map[string]int{}
				}
				in.Held[w] = len(ops) - n // appended since the review: held back until reviewed again
				ops = ops[:n]
			}
		}
		if dup != "" {
			ref.Rejected = dup
		} else {
			for _, o := range ops {
				seen[o.ID] = o.Raw
			}
			ref.Ops = ops
		}
		in.Refs = append(in.Refs, ref)
	}
	return in, nil
}

type cacheDoc struct {
	Key       string          `json:"key"`
	View      json.RawMessage `json:"view"`
	ViewSHA   string          `json:"view_sha256"`
	LedgerVer string          `json:"ledger_version"`
	MAC       string          `json:"mac"`
}

// secret returns this HOME's view-cache key (~/.agent-harness/ledgers/<proj>/cache.key, 32 random bytes,
// 0600), creating it on first use. view.cache.json travels with a copied .git and its key inputs are not
// secret, so only a MAC under this key makes a cache this HOME's own. Nil means no cache is used.
func (l *Ledger) secret() []byte {
	if l.cacheSecret != nil {
		return l.cacheSecret
	}
	l.cacheSecret = []byte{}
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return nil
	}
	dir := filepath.Dir(mdir)
	if os.MkdirAll(dir, 0o700) != nil {
		return nil
	}
	d, err := safefs.OpenDir(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if b, err := d.ReadRegular(cacheKeyFile, 128); err == nil {
			k, err := hex.DecodeString(strings.TrimSpace(string(b)))
			if err != nil || len(k) != 32 {
				return nil
			}
			l.cacheSecret = k
			return k
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil
		}
		if d.PublishNew(cacheKeyFile, []byte(hex.EncodeToString(k)+"\n")) == nil {
			l.cacheSecret = k
			return k
		}
		// Another process created it first: read theirs.
	}
	return nil
}

func cacheMAC(secret []byte, key, viewSHA string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(key + "\n" + viewSHA))
	return hex.EncodeToString(m.Sum(nil))
}

func toGeneric(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var g any
	if err := dec.Decode(&g); err != nil {
		return nil, err
	}
	return numbersToInt(g)
}

func numbersToInt(v any) (any, error) {
	switch x := v.(type) {
	case json.Number:
		return strconv.ParseInt(string(x), 10, 64)
	case []any:
		for i := range x {
			y, err := numbersToInt(x[i])
			if err != nil {
				return nil, err
			}
			x[i] = y
		}
	case map[string]any:
		for k := range x {
			y, err := numbersToInt(x[k])
			if err != nil {
				return nil, err
			}
			x[k] = y
		}
	}
	return v, nil
}

func canonicalView(v *fold.View) ([]byte, error) {
	g, err := toGeneric(v)
	if err != nil {
		return nil, err
	}
	return pycompat.Canonical(g)
}

func (l *Ledger) loadCache(key string) *fold.View {
	b, err := l.Dir.ReadRegular(cacheFile, 64<<20)
	if err != nil {
		return nil
	}
	var doc cacheDoc
	if json.Unmarshal(b, &doc) != nil || doc.Key != key || doc.LedgerVer != Version {
		return nil
	}
	secret := l.secret()
	if len(secret) == 0 || !hmac.Equal([]byte(doc.MAC), []byte(cacheMAC(secret, doc.Key, doc.ViewSHA))) {
		return nil
	}
	var v fold.View
	if json.Unmarshal(doc.View, &v) != nil {
		return nil
	}
	c, err := canonicalView(&v)
	if err != nil || fold.HandleHash(string(c)) != doc.ViewSHA || !bytes.Equal(c, doc.View) || v.Slug != l.Slug {
		return nil
	}
	return &v
}

// cacheBytes renders the cache document for v under key: Python-canonical JSON of
// {key, ledger_version, mac, view, view_sha256}, mac being HMAC-SHA256(secret, key "\n" view_sha256).
func cacheBytes(secret []byte, key string, v *fold.View) ([]byte, error) {
	g, err := toGeneric(v)
	if err != nil {
		return nil, err
	}
	c, err := pycompat.Canonical(g)
	if err != nil {
		return nil, err
	}
	sha := fold.HandleHash(string(c))
	doc, err := pycompat.Canonical(map[string]any{"key": key, "ledger_version": Version, "view": g,
		"view_sha256": sha, "mac": cacheMAC(secret, key, sha)})
	if err != nil {
		return nil, err
	}
	return append(doc, '\n'), nil
}

func (l *Ledger) saveCache(key string, v *fold.View) {
	secret := l.secret()
	if len(secret) == 0 {
		return
	}
	b, err := cacheBytes(secret, key, v)
	if err != nil {
		return
	}
	prior, err := l.Dir.Snapshot(cacheFile, 64<<20)
	if errors.Is(err, fs.ErrNotExist) {
		prior = nil
	} else if err != nil {
		return
	}
	_ = l.Dir.Replace(cacheFile, b, prior) // a lost race only means the next reader rebuilds
}

// CacheFresh reports whether view.cache.json matches the current refs and trust inputs.
func (l *Ledger) CacheFresh() bool {
	s, err := l.snapshot()
	return err == nil && l.loadCache(s.key) != nil
}

// View returns the folded view (from the cache when its key matches), refusing a ledger whose project
// root op is missing or does not match projects.json.
func (l *Ledger) View() (*fold.View, error) {
	s, err := l.snapshot()
	if err != nil {
		return nil, err
	}
	if v := l.loadCache(s.key); v != nil {
		return v, nil
	}
	return l.rebuild(s)
}

func (l *Ledger) rebuild(s *snapshot) (*fold.View, error) {
	in, err := l.readAll(s)
	if err != nil {
		return nil, err
	}
	v := fold.Fold(in)
	if v.Slug == "" || v.Slug != l.Slug {
		return nil, wrap(ErrRefused, "project root op missing or does not match projects.json (%s must equal the ULID of its project.create)", l.Project)
	}
	l.saveCache(s.key, v)
	return v, nil
}

// Rebuild deletes the cache and folds from the refs.
func (l *Ledger) Rebuild() (*fold.View, error) {
	_ = os.Remove(filepath.Join(l.Root, DirName, cacheFile))
	s, err := l.snapshot()
	if err != nil {
		return nil, err
	}
	return l.rebuild(s)
}

// ---------------------------------------------------------------------------------------- writes

// AppendOptions configure Append.
type AppendOptions struct {
	RedactSecrets bool
}

// Result of an append.
type Result struct {
	Ops    []*op.Op
	Writer string
	View   *fold.View
}

func (l *Ledger) lock() (*lock.Lock, error) {
	wait := LockWait
	if v := os.Getenv(LockWaitEnv); v != "" && writer.TestHooksAllowed {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			wait = time.Duration(ms) * time.Millisecond
		}
	}
	lk, err := lock.Acquire(filepath.Join(l.Root, DirName, lockFile), lock.Wait(wait))
	if errors.Is(err, lock.ErrBusy) {
		return nil, wrap(ErrBusy, "another process holds the ledger lock (waited %s)", wait)
	}
	if err != nil {
		return nil, wrap(ErrRefused, "cannot take the ledger lock: %v", err)
	}
	return lk, nil
}

func (l *Ledger) currentWriter(now int64) (string, string, error) {
	mid, err := writer.MachineID()
	if err != nil {
		return "", "", err
	}
	ino, err := writer.Inode(l.Root)
	if err != nil {
		return "", "", err
	}
	var register func(w, lease string) error
	if l.InRepo {
		register = l.registerWriter // before writer.json records the new writer
	}
	w, lease, minted, err := writer.Resolve(l.Dir, writer.Fingerprint(mid, ino), now, register)
	if err != nil || !l.InRepo || minted {
		return w, lease, err
	}
	if l.registry()[w] != store.LeaseHash(lease) {
		return "", "", wrap(ErrRefused, "this checkout's writer %s is not in this account's ledger registry "+
			"(~/.agent-harness/ledgers/%s/%s): the repository was copied from another account or machine, or "+
			"that directory was removed, so its ledger is not trusted here", w, l.Project, mirrorWritersFile)
	}
	return w, lease, nil
}

// scanEnvelope refuses secret-shaped text in values that live outside an op's payload (the claimed actor
// label, project.create names). They are never masked: a masked label would not be a valid label.
func scanEnvelope(fields [][2]string) error {
	found := scan.Scan(fields)
	if len(found) == 0 {
		return nil
	}
	parts := make([]string, len(found))
	for j, f := range found {
		parts[j] = f.String()
	}
	return wrap(ErrSecret, "refusing to store secret-shaped text: %s", strings.Join(parts, "; "))
}

// scanDrafts refuses (or masks) secret-shaped text in every string payload member and the actor label.
func scanDrafts(ds []op.Draft, redact bool) error {
	for i := range ds {
		if err := scanEnvelope([][2]string{{"actor_label", ds[i].Actor.Label}}); err != nil {
			return err
		}
		var fields [][2]string
		for _, f := range ds[i].Payload {
			switch v := f.V.(type) {
			case string:
				fields = append(fields, [2]string{f.K, v})
			case []string:
				for _, s := range v {
					fields = append(fields, [2]string{f.K, s})
				}
			}
		}
		found := scan.Scan(fields)
		if len(found) == 0 {
			continue
		}
		if !redact {
			parts := make([]string, len(found))
			for j, f := range found {
				parts[j] = f.String()
			}
			return wrap(ErrSecret, "refusing to store secret-shaped text: %s (rewrite it, or pass --redact-secrets to mask it)", strings.Join(parts, "; "))
		}
		for j, f := range ds[i].Payload {
			switch v := f.V.(type) {
			case string:
				ds[i].Payload[j].V = scan.Mask(v)
			case []string:
				for k := range v {
					v[k] = scan.Mask(v[k])
				}
			}
		}
		for _, f := range ds[i].Payload {
			var vals []string
			switch v := f.V.(type) {
			case string:
				vals = []string{v}
			case []string:
				vals = v
			}
			for _, s := range vals {
				if len(scan.Scan([][2]string{{f.K, s}})) > 0 {
					return wrap(ErrSecret, "masking left secret-shaped text in %s", f.K)
				}
			}
		}
	}
	return nil
}

// Append validates drafts against the current view, assigns clocks and ids under the writer lock, writes
// one pack commit into this HOME's mirror (the repository itself when there is none), moves the writer ref
// there with compare-and-swap, copies it into the repository and refreshes the cache. check runs under the lock against the fresh view (e.g. "ticket exists").
func (l *Ledger) Append(drafts []op.Draft, opts AppendOptions, check func(*fold.View, []op.Draft) error) (*Result, error) {
	if err := scanDrafts(drafts, opts.RedactSecrets); err != nil {
		return nil, err
	}
	lk, err := l.lock()
	if err != nil {
		return nil, err
	}
	res, err := l.appendLocked(drafts, opts, check)
	lk.Close()
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (l *Ledger) appendLocked(drafts []op.Draft, opts AppendOptions, check func(*fold.View, []op.Draft) error) (*Result, error) {
	now, err := Now()
	if err != nil {
		return nil, err
	}
	w, lease, err := l.currentWriter(now)
	if err != nil {
		return nil, err
	}
	ref := store.RefName(l.Project, w)
	// Own writers append to this HOME's mirror (the repository only holds a copy); without a mirror the
	// repository is the only store.
	src, mirror := l.Git, l.homeMirror()
	if mirror != nil {
		src = mirror
	} else if l.InRepo {
		l.warn = append(l.warn, "mirror missing; ops are stored only in this repository")
	}
	for attempt := 0; attempt < 3; attempt++ {
		v, err := l.View()
		if err != nil {
			return nil, err
		}
		if me := v.WriterByID(w); me != nil && me.Rejected != "" {
			return nil, wrap(ErrRefused, "this writer's own ref failed validation (%s); refusing to append", me.Rejected)
		}
		if check != nil {
			if err := check(v, drafts); err != nil {
				return nil, err
			}
			// check may build payloads (ticket.create needs the fresh status list), so scan again here:
			// every byte that reaches mint has passed the secret scan.
			if err := scanDrafts(drafts, opts.RedactSecrets); err != nil {
				return nil, err
			}
		}
		tip, err := src.Tip(ref)
		if err != nil {
			return nil, err
		}
		var last op.HLC
		if tip != "" {
			if last, err = src.TipHLC(tip); err != nil { // authoritative last clock (N10)
				return nil, wrap(ErrRefused, "own ref tip unreadable: %v", err)
			}
		}
		ops, err := l.mint(drafts, w, last, now, v.Witness(w, now))
		if err != nil {
			return nil, err
		}
		commit, err := src.WritePack(tip, ops, lease)
		if err != nil {
			return nil, err
		}
		if err := src.CAS(ref, commit, tip); err != nil {
			if errors.Is(err, store.ErrCASFailed) {
				continue
			}
			return nil, err
		}
		if os.Getenv(CrashAfterCASEnv) == "1" && writer.TestHooksAllowed {
			os.Exit(9) // test hook: simulate a crash between update-ref and the cache write
		}
		if mirror != nil {
			l.syncRepo(mirror, ref, tip, commit)
		}
		nv, err := l.View()
		if os.Getenv(FailViewAfterEnv) == "1" && writer.TestHooksAllowed {
			err = errors.New("test hook: view refresh failed")
		}
		if err != nil {
			// The ops are already committed: say so, because a retry would append them twice.
			return nil, wrap(ErrRefused, "the change was committed (%s) but the view could not be refreshed; do not retry: %v", ops[0].ID, err)
		}
		return &Result{Ops: ops, Writer: w, View: nv}, nil
	}
	return nil, wrap(ErrBusy, "ledger ref kept moving; gave up after 3 attempts")
}

func (l *Ledger) mint(drafts []op.Draft, w string, last op.HLC, now int64, witness op.HLC) ([]*op.Op, error) {
	var ops []*op.Op
	for _, d := range drafts {
		h, err := op.Tick(last, now, witness)
		if err != nil {
			return nil, err
		}
		last = h
		id, err := op.NewID(op.PrefixOp, h.WallMs)
		if err != nil {
			return nil, err
		}
		ticket := d.Ticket
		if d.Kind == op.KindTicketCreate {
			ticket = op.PrefixTicket + strings.TrimPrefix(id, op.PrefixOp)
		}
		payload := append(op.Obj(nil), d.Payload...)
		if d.Kind == op.KindComment {
			cid, err := op.NewID(op.PrefixComment, h.WallMs)
			if err != nil {
				return nil, err
			}
			payload = op.Comment(cid, d.Payload[1].V.(string))
		}
		if d.Kind == op.KindProjectCreate {
			// Root rule: the project id is derived from (equals the ULID of) its project.create op.
			l.Project = op.PrefixProject + strings.TrimPrefix(id, op.PrefixOp)
		}
		project := l.Project
		o := &op.Op{V: 1, ID: id, Project: project, Writer: w, HLC: h, Actor: d.Actor, Ticket: ticket, Kind: d.Kind, Payload: payload}
		raw, err := o.Encode()
		if err != nil {
			return nil, err
		}
		parsed, err := op.Parse(raw) // every stored op passes the same validation a reader applies
		if err != nil {
			return nil, wrap(ErrUsage, "%v", err)
		}
		ops = append(ops, parsed)
	}
	return ops, nil
}

// registry returns this HOME's record of the writers minted on this machine for the ledger
// (~/.agent-harness/ledgers/<proj>/mirror-writers.json: writer -> sha256(lease)[:16]). It is the trust
// anchor for the self class of a repository ledger: writer.json travels with a copied .git, this file
// does not. A missing file is an empty registry.
func (l *Ledger) registry() map[string]string {
	out := map[string]string{}
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return out
	}
	d, err := safefs.OpenDir(filepath.Dir(mdir))
	if err != nil {
		return out
	}
	defer d.Close()
	raw := map[string]any{}
	if b, err := d.ReadRegular(mirrorWritersFile, 1<<20); err == nil && json.Unmarshal(b, &raw) == nil {
		for w, v := range raw {
			if h, ok := v.(string); ok && op.ValidID(w, op.PrefixWriter) && h != "" {
				out[w] = h
			}
		}
	}
	return out
}

// registryLockWait bounds how long a registration waits for another checkout of the same project.
const registryLockWait = 10 * time.Second

// registerWriter records (writer, lease hash) in this HOME's registry. It must succeed before a newly
// minted writer appends anything, or that writer's ops would not count as self.
func (l *Ledger) registerWriter(w, lease string) error {
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return err
	}
	dir := filepath.Dir(mdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return wrap(ErrRefused, "cannot create the ledger registry: %v", err)
	}
	d, err := safefs.OpenDir(dir)
	if err != nil {
		return wrap(ErrRefused, "cannot open the ledger registry: %v", err)
	}
	defer d.Close()
	// Several checkouts of one project share this file and each has its own writer.lock, so serialise the
	// read-modify-write on a lock beside the file. Replace alone is not enough: its check and rename are
	// not atomic, so two registrations can both pass the check and the later rename drops the earlier entry.
	lk, err := lock.Acquire(filepath.Join(dir, mirrorWritersLock), lock.Wait(registryLockWait))
	if err != nil {
		if errors.Is(err, lock.ErrBusy) {
			return wrap(ErrBusy, "the ledger registry is busy; try again")
		}
		return wrap(ErrRefused, "cannot lock the ledger registry: %v", err)
	}
	defer lk.Close()
	// Replace is still a compare-and-swap against the snapshot, so re-read and retry on a stale snapshot
	// (for example a non-cooperating writer).
	for attempt := 0; attempt < 5; attempt++ {
		cur := map[string]any{}
		prior, err := d.Snapshot(mirrorWritersFile, 1<<20)
		if err == nil {
			b, _ := d.ReadRegular(mirrorWritersFile, 1<<20)
			if json.Unmarshal(b, &cur) != nil {
				return wrap(ErrRefused, "%s is malformed", mirrorWritersFile)
			}
		} else {
			prior = nil
		}
		if cur[w] == store.LeaseHash(lease) {
			return nil
		}
		cur[w] = store.LeaseHash(lease)
		b, err := pycompat.Canonical(cur)
		if err != nil {
			return err
		}
		err = d.Replace(mirrorWritersFile, append(b, '\n'), prior)
		if err == nil {
			return nil
		}
		if !(errors.Is(err, safefs.ErrChanged) || errors.Is(err, safefs.ErrExists)) {
			return wrap(ErrRefused, "cannot write the ledger registry: %v", err)
		}
	}
	return wrap(ErrBusy, "the ledger registry kept changing; try again")
}

// homeMirror returns this HOME's mirror of a repository ledger, or nil for a repo-less ledger or when the
// mirror is missing. Own writers append to the mirror first and are read from it: the repository's copy of
// their refs (and its objects) travels with a copied .git, so it is never what this HOME trusts.
func (l *Ledger) homeMirror() *store.Git {
	if !l.InRepo {
		return nil
	}
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return nil
	}
	if fi, err := os.Stat(mdir); err != nil || !fi.IsDir() {
		return nil
	}
	return &store.Git{GitDir: mdir}
}

// DisplacedPrefix holds repository copies of own refs that differed from this HOME's mirror when a write
// replaced them. They are never folded; they keep such commits reachable for inspection.
const DisplacedPrefix = "refs/goodqa-displaced/v1/"

// syncRepo copies an own ref from the mirror into the repository, warning (not failing) when it cannot:
// the ops are safe in the mirror and the copy is retried on the next write. prev is the mirror tip the
// write built on. A repository copy that is only behind (an earlier commit of the mirror's chain, left by
// a crash or a failed copy) is simply brought up to date; one that is not on the mirror's chain (ops added
// there, or written while the mirror was missing) is kept under DisplacedPrefix before it is replaced.
func (l *Ledger) syncRepo(mirror *store.Git, ref, prev, tip string) {
	if cur, err := l.Git.Tip(ref); err == nil && cur != "" && cur != tip && (prev == "" || !mirror.IsAncestor(cur, prev)) {
		_, w, _ := store.ParseRefName(ref)
		keep := fmt.Sprintf("%s%s/%s/%d", DisplacedPrefix, l.Project, w, time.Now().UnixNano())
		if err := l.Git.CAS(keep, cur, ""); err != nil {
			l.warn = append(l.warn, "the repository copy of this writer's ref differs from this HOME's mirror and could not be kept; not replaced")
			return
		}
		l.warn = append(l.warn, "the repository copy of this writer's ref differed from this HOME's mirror; it was replaced and kept as "+keep)
	}
	if err := mirror.PushToRepo(l.Root, ref, tip); err != nil {
		l.warn = append(l.warn, "repository copy of the ledger ref not updated (ops are safe in this HOME's mirror): "+err.Error())
	}
}

// CurrentWriterID returns the writer this process would append as, without minting one ("" if none yet).
func (l *Ledger) CurrentWriterID() string {
	mid, err := writer.MachineID()
	if err != nil {
		return ""
	}
	ino, err := writer.Inode(l.Root)
	if err != nil {
		return ""
	}
	m, _, err := writer.Load(l.Dir)
	if err != nil {
		return ""
	}
	return m.Writers[writer.Fingerprint(mid, ino)].Writer
}
