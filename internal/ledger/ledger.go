// Package ledger is the Phase 0a local ticket ledger: an append-only op log in hidden git refs under a
// repository's common dir (or a private bare repository for repo-less ledgers), folded into a view that
// contains only self and trusted writers. All writes happen under <goodqa>/writer.lock.
package ledger

import (
	"bytes"
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
	DirName           = "goodqa"
	projectsFile      = "projects.json"
	trustFile         = "trust.json"
	cacheFile         = "view.cache.json"
	lockFile          = "writer.lock"
	metaFile          = "meta.json"
	mirrorWritersFile = "mirror-writers.json"
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

// MirrorDir is the bare backup mirror of a repository ledger.
func MirrorDir(project string) (string, error) {
	home, err := LedgersHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, project, "mirror.git"), nil
}

// ---------------------------------------------------------------------------------------- view

type trustEntry struct {
	Class string `json:"class"`
}

func (l *Ledger) classes() (map[string]string, *writer.Map, error) {
	m, _, err := writer.Load(l.Dir)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]string{}
	if b, err := l.Dir.ReadRegular(trustFile, 1<<20); err == nil {
		var t struct {
			Writers map[string]trustEntry `json:"writers"`
		}
		if json.Unmarshal(b, &t) == nil {
			for w, e := range t.Writers {
				if op.ValidID(w, op.PrefixWriter) && (e.Class == fold.ClassTrusted || e.Class == fold.ClassBlocked) {
					out[w] = e.Class
				}
			}
		} else {
			l.warn = append(l.warn, "trust.json is malformed; every foreign writer is treated as unverified")
		}
	}
	for w := range m.Self() {
		out[w] = fold.ClassSelf // self always wins over trust.json
	}
	return out, m, nil
}

type snapshot struct {
	tips    map[string]string
	bad     []string
	classes map[string]string
	key     string
}

func (l *Ledger) snapshot() (*snapshot, error) {
	refs, bad, err := l.Git.Refs()
	if err != nil {
		return nil, err
	}
	classes, _, err := l.classes()
	if err != nil {
		return nil, err
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
	k, err := pycompat.Canonical(map[string]any{"v": Version, "project": l.Project, "tips": tips, "classes": cl, "bad": badAny})
	if err != nil {
		return nil, err
	}
	return &snapshot{tips: refs, bad: bad, classes: classes, key: fold.HandleHash(string(k))}, nil
}

// readAll reads and validates every writer ref of the project. Refs of other projects and malformed names
// are reported, never read.
func (l *Ledger) readAll(s *snapshot) (fold.Input, error) {
	in := fold.Input{Project: l.Project, Classes: s.classes}
	names := make([]string, 0, len(s.tips))
	for r := range s.tips {
		names = append(names, r)
	}
	sort.Strings(names)
	seen := map[string][]byte{} // op id -> bytes, across refs
	for _, r := range names {
		proj, w, _ := store.ParseRefName(r)
		if proj != l.Project {
			continue
		}
		ref := fold.Ref{Writer: w}
		packs, err := l.Git.ReadRef(proj, w, s.tips[r])
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
	var v fold.View
	if json.Unmarshal(doc.View, &v) != nil {
		return nil
	}
	c, err := canonicalView(&v)
	if err != nil || fold.HandleHash(string(c)) != doc.ViewSHA || !bytes.Equal(c, doc.View) {
		return nil
	}
	return &v
}

// CacheBytes renders the cache document for v under key: Python-canonical JSON of
// {key, ledger_version, view, view_sha256}.
func CacheBytes(key string, v *fold.View) ([]byte, error) {
	g, err := toGeneric(v)
	if err != nil {
		return nil, err
	}
	c, err := pycompat.Canonical(g)
	if err != nil {
		return nil, err
	}
	doc, err := pycompat.Canonical(map[string]any{"key": key, "ledger_version": Version, "view": g,
		"view_sha256": fold.HandleHash(string(c))})
	if err != nil {
		return nil, err
	}
	return append(doc, '\n'), nil
}

func (l *Ledger) saveCache(key string, v *fold.View) {
	b, err := CacheBytes(key, v)
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
	lk, err := lock.Acquire(filepath.Join(l.Root, DirName, lockFile), lock.Wait(LockWait))
	if errors.Is(err, lock.ErrBusy) {
		return nil, wrap(ErrBusy, "another process holds the ledger lock (waited %s)", LockWait)
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
	w, lease, _, err := writer.Resolve(l.Dir, writer.Fingerprint(mid, ino), now)
	return w, lease, err
}

// scanDrafts refuses (or masks) secret-shaped text in every string payload member.
func scanDrafts(ds []op.Draft, redact bool) error {
	for i := range ds {
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
			if s, ok := f.V.(string); ok && len(scan.Scan([][2]string{{f.K, s}})) > 0 {
				return wrap(ErrSecret, "masking left secret-shaped text in %s", f.K)
			}
		}
	}
	return nil
}

// Append validates drafts against the current view, assigns clocks and ids under the writer lock, writes
// one pack commit, moves the writer ref with compare-and-swap, refreshes the cache and then pushes the ref
// to the local mirror. check runs under the lock against the fresh view (e.g. "ticket exists").
func (l *Ledger) Append(drafts []op.Draft, opts AppendOptions, check func(*fold.View, []op.Draft) error) (*Result, error) {
	if err := scanDrafts(drafts, opts.RedactSecrets); err != nil {
		return nil, err
	}
	lk, err := l.lock()
	if err != nil {
		return nil, err
	}
	res, err := l.appendLocked(drafts, check)
	lk.Close()
	if err != nil {
		return nil, err
	}
	l.pushMirror(res.Writer)
	return res, nil
}

func (l *Ledger) appendLocked(drafts []op.Draft, check func(*fold.View, []op.Draft) error) (*Result, error) {
	now, err := Now()
	if err != nil {
		return nil, err
	}
	w, lease, err := l.currentWriter(now)
	if err != nil {
		return nil, err
	}
	ref := store.RefName(l.Project, w)
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
		}
		tip, err := l.Git.Tip(ref)
		if err != nil {
			return nil, err
		}
		var last op.HLC
		if tip != "" {
			if last, err = l.Git.TipHLC(tip); err != nil { // authoritative last clock (N10)
				return nil, wrap(ErrRefused, "own ref tip unreadable: %v", err)
			}
		}
		ops, err := l.mint(drafts, w, last, now, v.Witness(w, now))
		if err != nil {
			return nil, err
		}
		commit, err := l.Git.WritePack(tip, ops, lease, l.Git.ConfigBool("ledger.sign"))
		if err != nil {
			return nil, err
		}
		if err := l.Git.CAS(ref, commit, tip); err != nil {
			if errors.Is(err, store.ErrCASFailed) {
				continue
			}
			return nil, err
		}
		if os.Getenv(CrashAfterCASEnv) == "1" && writer.TestHooksAllowed {
			os.Exit(9) // test hook: simulate a crash between update-ref and the cache write
		}
		l.recordMirrorWriter(w, lease)
		nv, err := l.View()
		if err != nil {
			return nil, err
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

// recordMirrorWriter notes (writer, lease hash) beside the mirror so --from-mirror can restore exactly
// this machine's writers as self.
func (l *Ledger) recordMirrorWriter(w, lease string) {
	if !l.InRepo {
		return
	}
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return
	}
	d, err := safefs.OpenDir(filepath.Dir(mdir))
	if err != nil {
		return
	}
	defer d.Close()
	cur := map[string]any{}
	prior, err := d.Snapshot(mirrorWritersFile, 1<<20)
	if err == nil {
		b, _ := d.ReadRegular(mirrorWritersFile, 1<<20)
		_ = json.Unmarshal(b, &cur)
	} else {
		prior = nil
	}
	if cur[w] == store.LeaseHash(lease) {
		return
	}
	cur[w] = store.LeaseHash(lease)
	b, err := pycompat.Canonical(cur)
	if err == nil {
		_ = d.Replace(mirrorWritersFile, append(b, '\n'), prior)
	}
}

func (l *Ledger) pushMirror(w string) {
	if !l.InRepo {
		return
	}
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return
	}
	if _, err := os.Stat(mdir); err != nil {
		l.warn = append(l.warn, "mirror missing; ops are stored only in this repository")
		return
	}
	ref := store.RefName(l.Project, w)
	tip, err := l.Git.Tip(ref)
	if err != nil || tip == "" {
		return
	}
	if err := l.Git.PushMirror(mdir, ref, tip); err != nil {
		l.warn = append(l.warn, "mirror push failed (ops are safe in this repository): "+err.Error())
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
