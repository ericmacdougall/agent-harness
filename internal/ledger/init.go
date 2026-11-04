package ledger

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/store"
	"github.com/ericmacdougall/agent-harness/internal/ledger/writer"
	"github.com/ericmacdougall/agent-harness/internal/pycompat"
	"github.com/ericmacdougall/agent-harness/internal/safefs"
)

// InitOptions configure Init.
type InitOptions struct {
	Slug       string
	Name       string
	NoRepo     bool
	FromMirror bool
	Actor      op.Actor
}

var slugJunk = regexp.MustCompile(`[^a-z0-9-]+`)

// DefaultSlug derives a slug from a directory name.
func DefaultSlug(dir string) string {
	s := strings.Trim(slugJunk.ReplaceAllString(strings.ToLower(filepath.Base(dir)), "-"), "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if !op.ValidSlug(s) {
		return "ledger"
	}
	return s
}

func writeMeta(project, slug, role string) error {
	home, err := LedgersHome()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, project)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(home, 0o700)
	d, err := safefs.OpenDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	b, _ := pycompat.Canonical(map[string]any{"project": project, "slug": slug, "role": role})
	err = d.PublishNew(metaFile, append(b, '\n'))
	if errors.Is(err, safefs.ErrExists) {
		return nil
	}
	return err
}

func slugTaken(slug string) (string, error) {
	ms, _, err := machineLedgers()
	if err != nil {
		return "", err
	}
	for _, m := range ms {
		if m.Slug == slug {
			return m.Project, nil
		}
	}
	return "", nil
}

// Init creates a ledger (in the repository at loc.Cwd, or repo-less) and returns it opened.
func Init(loc Location, o InitOptions) (*Ledger, error) {
	common, inRepo, err := store.CommonDir(loc.Cwd)
	if err != nil {
		return nil, err
	}
	if o.FromMirror {
		if !inRepo {
			return nil, wrap(ErrUsage, "--from-mirror restores into a git repository; run it inside one")
		}
		return initFromMirror(common, o)
	}
	if o.NoRepo {
		inRepo = false
		if o.Slug == "" {
			return nil, wrap(ErrUsage, "init --no-repo needs --slug")
		}
	} else if !inRepo {
		return nil, wrap(ErrNoLedger, "not in a git repository; use init --no-repo --slug S for a repo-less ledger")
	}
	if o.Slug == "" {
		top := filepath.Dir(common)
		o.Slug = DefaultSlug(top)
	}
	if !op.ValidSlug(o.Slug) {
		return nil, wrap(ErrUsage, "slug must match [a-z0-9][a-z0-9-]{0,62}")
	}
	if o.Name == "" {
		o.Name = o.Slug
	}
	if p, err := slugTaken(o.Slug); err != nil {
		return nil, err
	} else if p != "" {
		return nil, wrap(ErrRefused, "slug %q is already used on this machine by %s (slugs are unique per machine)", o.Slug, p)
	}
	if inRepo {
		if d, err := openGoodqa(common, false); err == nil {
			_, perr := readProjects(d)
			d.Close()
			if perr == nil {
				return nil, wrap(ErrRefused, "this repository already has a ledger")
			}
		}
	}
	now, err := Now()
	if err != nil {
		return nil, err
	}
	rootID, err := op.NewID(op.PrefixOp, now)
	if err != nil {
		return nil, err
	}
	project := op.PrefixProject + strings.TrimPrefix(rootID, op.PrefixOp)
	root := common
	if !inRepo {
		home, err := LedgersHome()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(home, project, "repo.git")
		if err := store.InitBare(root, "ledger"); err != nil {
			return nil, err
		}
	}
	d, err := openGoodqa(root, true)
	if err != nil {
		return nil, err
	}
	l := &Ledger{Root: root, InRepo: inRepo, Dir: d, Git: &store.Git{GitDir: root}, Project: project, Slug: o.Slug}
	lk, err := l.lock()
	if err != nil {
		l.Close()
		return nil, err
	}
	err = l.initLocked(rootID, now, o)
	lk.Close()
	if err != nil {
		l.Close()
		return nil, err
	}
	role := "ledger"
	if inRepo {
		role = "mirror"
		mdir, _ := MirrorDir(project)
		if err := store.InitBare(mdir, "mirror"); err != nil {
			l.warn = append(l.warn, "mirror could not be created: "+err.Error())
		}
	}
	if err := writeMeta(project, o.Slug, role); err != nil {
		l.warn = append(l.warn, "ledger registry entry could not be written: "+err.Error())
	}
	if inRepo {
		w, lease, _ := l.currentWriter(now)
		l.recordMirrorWriter(w, lease)
		l.pushMirror(w)
	}
	return l, nil
}

func (l *Ledger) initLocked(rootID string, now int64, o InitOptions) error {
	if _, err := l.Dir.ReadRegular(projectsFile, 64*1024); err == nil {
		return wrap(ErrRefused, "this repository already has a ledger")
	}
	w, lease, err := l.currentWriter(now)
	if err != nil {
		return err
	}
	create := &op.Op{V: 1, ID: rootID, Project: l.Project, Writer: w, HLC: op.HLC{WallMs: now},
		Actor: o.Actor, Kind: op.KindProjectCreate, Payload: op.ProjectCreate(o.Slug, o.Name, op.DefaultStatuses)}
	raw, err := create.Encode()
	if err != nil {
		return err
	}
	parsed, err := op.Parse(raw)
	if err != nil {
		return wrap(ErrUsage, "%v", err)
	}
	ref := store.RefName(l.Project, w)
	commit, err := l.Git.WritePack("", []*op.Op{parsed}, lease, l.Git.ConfigBool("ledger.sign"))
	if err != nil {
		return err
	}
	if err := l.Git.CAS(ref, commit, ""); err != nil {
		return err
	}
	if err := l.Dir.PublishNew(projectsFile, projectsBody(l.Project, o.Slug)); err != nil {
		return err
	}
	_, err = l.Rebuild()
	return err
}

func initFromMirror(common string, o InitOptions) (*Ledger, error) {
	if o.Slug == "" {
		return nil, wrap(ErrUsage, "init --from-mirror needs --slug")
	}
	ms, home, err := machineLedgers()
	if err != nil {
		return nil, err
	}
	project := ""
	for _, m := range ms {
		if m.Slug == o.Slug && m.Role == "mirror" {
			project = m.Project
		}
	}
	if project == "" {
		return nil, wrap(ErrNotFound, "no mirror for slug %q on this machine", o.Slug)
	}
	mdir := filepath.Join(home, project, "mirror.git")
	d, err := openGoodqa(common, true)
	if err != nil {
		return nil, err
	}
	l := &Ledger{Root: common, InRepo: true, Dir: d, Git: &store.Git{GitDir: common}, Project: project, Slug: o.Slug}
	lk, err := l.lock()
	if err != nil {
		l.Close()
		return nil, err
	}
	defer lk.Close()
	if _, err := l.Dir.ReadRegular(projectsFile, 64*1024); err == nil {
		l.Close()
		return nil, wrap(ErrRefused, "this repository already has a ledger")
	}
	if err := l.Git.FetchFromMirror(mdir, project); err != nil {
		l.Close()
		return nil, err
	}
	known := map[string]string{}
	if md, err := safefs.OpenDir(filepath.Join(home, project)); err == nil {
		if b, err := md.ReadRegular(mirrorWritersFile, 1<<20); err == nil {
			_ = json.Unmarshal(b, &known)
		}
		md.Close()
	}
	refs, _, err := l.Git.Refs()
	if err != nil {
		l.Close()
		return nil, err
	}
	now, err := Now()
	if err != nil {
		l.Close()
		return nil, err
	}
	for name, tip := range refs {
		proj, w, _ := store.ParseRefName(name)
		if proj != project || known[w] == "" {
			continue
		}
		packs, err := l.Git.ReadRef(proj, w, tip)
		if err != nil {
			continue
		}
		ok := true
		for _, p := range packs {
			ok = ok && p.Lease == known[w]
		}
		if ok {
			if err := writer.AddRestored(l.Dir, w, now); err != nil {
				l.Close()
				return nil, err
			}
		} else {
			l.warn = append(l.warn, "writer "+w+" in the mirror has a different lease; left unverified")
		}
	}
	if err := l.Dir.PublishNew(projectsFile, projectsBody(project, o.Slug)); err != nil {
		l.Close()
		return nil, err
	}
	if _, err := l.Rebuild(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// TrustInfo is unused in 0a beyond reading trust.json; kept for status rendering.
var _ = fold.ClassTrusted
var _ = fs.ErrNotExist
