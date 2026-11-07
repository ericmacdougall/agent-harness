package ledger

// Phase 0b: the folded frontier, the HOME-held GoodQA binding and the HOME trust registry.
//
// Everything here is keyed by this HOME (~/.agent-harness/ledgers/<proj>/), never by the git directory:
// a repository copied with its .git into another account carries none of it, so it can neither claim to be
// synced nor have a writer trusted.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/safefs"
)

const (
	syncFile  = "sync.json"
	trustFile = "trust.json"
	stateMax  = 1 << 20
)

// Frontier is where one writer's validated ops end: a count and the last op, never a commit id, so a
// restored or repacked ref with the same ops has the same frontier.
type Frontier struct {
	Writer string
	Ops    int
	WallMs int64
	Ctr    int64
	LastOp string
}

// Snapshot reads the refs once and returns the validated ops of every writer. Callers derive everything
// from this one Input, so a concurrent write cannot produce a mixed result.
func (l *Ledger) Snapshot() (fold.Input, error) {
	s, err := l.snapshot()
	if err != nil {
		return fold.Input{}, err
	}
	return l.readAll(s, readNormal)
}

// FoldedFrontier lists the frontier of every folded (self or trusted), unrejected, non-empty writer,
// ordered by writer id.
func FoldedFrontier(in fold.Input) []Frontier {
	var out []Frontier
	for _, r := range in.Refs {
		if r.Rejected != "" || len(r.Ops) == 0 || !fold.Folded(in.Class(r.Writer)) {
			continue
		}
		last := r.Ops[len(r.Ops)-1]
		out = append(out, Frontier{Writer: r.Writer, Ops: len(r.Ops), WallMs: last.HLC.WallMs, Ctr: last.HLC.Ctr, LastOp: last.ID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Writer < out[j].Writer })
	return out
}

// Relation of a recorded frontier to the current one.
const (
	RelEqual    = "equal"    // same ops
	RelBehind   = "behind"   // the recorded frontier is a proper prefix of the current one
	RelDiverged = "diverged" // the recorded frontier names ops the current refs lack or differ on
)

// Compare relates a recorded frontier rec to the current input. extra is the number of folded ops past rec.
func Compare(in fold.Input, rec []Frontier) (rel string, extra int) {
	have := map[string]fold.Ref{}
	for _, r := range in.Refs {
		if r.Rejected == "" && fold.Folded(in.Class(r.Writer)) {
			have[r.Writer] = r
		}
	}
	seen := map[string]bool{}
	for _, f := range rec {
		r, ok := have[f.Writer]
		if !ok || f.Ops <= 0 || len(r.Ops) < f.Ops || r.Ops[f.Ops-1].ID != f.LastOp {
			return RelDiverged, 0
		}
		seen[f.Writer] = true
		extra += len(r.Ops) - f.Ops
	}
	for w, r := range have {
		if !seen[w] {
			extra += len(r.Ops)
		}
	}
	if extra == 0 {
		return RelEqual, 0
	}
	return RelBehind, extra
}

// Binding records that a GoodQA import receipt was accepted for this ledger.
type Binding struct {
	GoodQAProject string
	ImportID      string
	ExportDigest  string
	BoundMs       int64
	Frontier      []Frontier
	GoodQAKey     string // hex ed25519 public key pinned by the user; empty = receipts are advisory
	// Damaged: a binding file exists but failed validation. It vouches for nothing (no frontier, no pin),
	// yet it is not "never bound": bind and --since-bound refuse it until `unbind` removes it, so damage
	// can never drop a pinned key and let an unsigned receipt through (Kimi audit F10, goodqa#14998).
	Damaged bool
}

type frontierJSON struct {
	Writer string `json:"writer"`
	Ops    int    `json:"ops"`
	WallMs int64  `json:"wall_ms"`
	Ctr    int64  `json:"ctr"`
	LastOp string `json:"last_op"`
}

type bindingJSON struct {
	V             int            `json:"v"`
	Ledger        string         `json:"ledger_project"`
	GoodQAProject string         `json:"goodqa_project"`
	ImportID      string         `json:"import_id"`
	ExportDigest  string         `json:"export_digest"`
	BoundMs       int64          `json:"bound_ms"`
	Frontier      []frontierJSON `json:"frontier"`
	GoodQAKey     string         `json:"goodqa_key"`
}

func (l *Ledger) homeDir(create bool) (*safefs.Dir, error) {
	mdir, err := MirrorDir(l.Project)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(mdir)
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, wrap(ErrRefused, "cannot create the ledger state directory: %v", err)
		}
	}
	d, err := safefs.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// maxPersistedOps bounds op counts read back from HOME state: far above any real writer, far below overflow.
const maxPersistedOps = 1 << 30

func validDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// ReadBinding returns this HOME's binding, or nil when the ledger was never bound here (no binding file).
// A file that exists but cannot be read, parsed or validated (strict JSON, version, ledger, digest, each
// frontier entry: writer and op ids, count, clock, no duplicate writer) returns a Binding with Damaged set
// and nothing else, never nil: damage must not look like "never bound". The pinned key is not validated
// here; Bind parses it at the authentication boundary and refuses there.
func (l *Ledger) ReadBinding() *Binding {
	d, err := l.homeDir(false)
	if err != nil {
		if IsNotExist(err) {
			return nil
		}
		return &Binding{Damaged: true}
	}
	defer d.Close()
	b, err := d.ReadRegular(syncFile, stateMax)
	if err != nil {
		if IsNotExist(err) {
			return nil
		}
		return &Binding{Damaged: true}
	}
	var j bindingJSON
	if _, derr := op.DecodeStrict(b); derr != nil || json.Unmarshal(b, &j) != nil || j.V != 1 ||
		j.Ledger != l.Project || !validDigest(j.ExportDigest) || len(j.Frontier) > 4096 {
		return &Binding{Damaged: true}
	}
	out := &Binding{GoodQAProject: j.GoodQAProject, ImportID: j.ImportID, ExportDigest: j.ExportDigest, BoundMs: j.BoundMs, GoodQAKey: j.GoodQAKey}
	seen := map[string]bool{}
	for _, f := range j.Frontier {
		if seen[f.Writer] || !op.ValidID(f.Writer, op.PrefixWriter) || !op.ValidID(f.LastOp, op.PrefixOp) ||
			f.Ops < 1 || f.Ops > maxPersistedOps || f.WallMs < 0 || f.Ctr < 0 ||
			op.ULIDTime(f.LastOp[len(op.PrefixOp):]) != f.WallMs {
			return &Binding{Damaged: true}
		}
		seen[f.Writer] = true
		out.Frontier = append(out.Frontier, Frontier{f.Writer, f.Ops, f.WallMs, f.Ctr, f.LastOp})
	}
	return out
}

// WriteBinding replaces this HOME's binding.
func (l *Ledger) WriteBinding(b *Binding) error {
	j := bindingJSON{V: 1, Ledger: l.Project, GoodQAProject: b.GoodQAProject, ImportID: b.ImportID,
		ExportDigest: b.ExportDigest, BoundMs: b.BoundMs, Frontier: []frontierJSON{}, GoodQAKey: b.GoodQAKey}
	for _, f := range b.Frontier {
		j.Frontier = append(j.Frontier, frontierJSON{f.Writer, f.Ops, f.WallMs, f.Ctr, f.LastOp})
	}
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return l.replaceHome(syncFile, append(body, '\n'))
}

func (l *Ledger) replaceHome(name string, body []byte) error {
	d, err := l.homeDir(true)
	if err != nil {
		return wrap(ErrRefused, "cannot open the ledger state directory: %v", err)
	}
	defer d.Close()
	for attempt := 0; attempt < 5; attempt++ {
		prior, err := d.Snapshot(name, stateMax)
		if err != nil {
			prior = nil
		}
		err = d.Replace(name, body, prior)
		if err == nil {
			return nil
		}
		if !(errors.Is(err, safefs.ErrChanged) || errors.Is(err, safefs.ErrExists)) {
			return wrap(ErrRefused, "cannot write %s: %v", name, err)
		}
	}
	return wrap(ErrBusy, "%s kept changing; try again", name)
}

// ---------------------------------------------------------------------------------------- trust

// Trust is this HOME's registry of writers other than its own.
type Trust struct {
	Trusted map[string]TrustEntry // writer -> reviewed state
	Blocked map[string]bool
}

// TrustEntry is a reviewed prefix of a writer's ops: its count and OpsDigest.
type TrustEntry struct {
	Ops    int
	Digest string
}

type trustJSON struct {
	V       int                       `json:"v"`
	Ledger  string                    `json:"ledger_project"`
	Trusted map[string]map[string]any `json:"trusted"`
	Blocked []string                  `json:"blocked"`
}

// OpsDigest is the review digest of a writer's ops: sha256 over each op's stored bytes and a newline.
func OpsDigest(ops []*op.Op) string {
	h := sha256.New()
	for _, o := range ops {
		h.Write(o.Raw)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ReadTrust loads the HOME registry; absent or malformed means nobody is trusted or blocked.
func (l *Ledger) ReadTrust() *Trust {
	t := &Trust{Trusted: map[string]TrustEntry{}, Blocked: map[string]bool{}}
	if !l.InRepo {
		return t // a repo-less ledger lives under this HOME and has only its own writers
	}
	d, err := l.homeDir(false)
	if err != nil {
		return t
	}
	defer d.Close()
	b, err := d.ReadRegular(trustFile, stateMax)
	if err != nil {
		return t
	}
	var j trustJSON
	if _, derr := op.DecodeStrict(b); derr != nil || json.Unmarshal(b, &j) != nil || j.V != 1 || j.Ledger != l.Project {
		return t
	}
	for w, e := range j.Trusted {
		// Only a whole, in-range count and a lowercase hex digest are trust; anything else trusts nobody.
		ops, isNum := e["ops"].(float64)
		dg, isStr := e["digest"].(string)
		if op.ValidID(w, op.PrefixWriter) && isNum && ops >= 1 && ops <= maxPersistedOps && ops == float64(int(ops)) &&
			isStr && validDigest(dg) {
			t.Trusted[w] = TrustEntry{Ops: int(ops), Digest: dg}
		}
	}
	for _, w := range j.Blocked {
		if op.ValidID(w, op.PrefixWriter) {
			t.Blocked[w] = true
		}
	}
	return t
}

// WriteTrust replaces the HOME registry.
func (l *Ledger) WriteTrust(t *Trust) error {
	j := trustJSON{V: 1, Ledger: l.Project, Trusted: map[string]map[string]any{}, Blocked: []string{}}
	for w, e := range t.Trusted {
		j.Trusted[w] = map[string]any{"ops": e.Ops, "digest": e.Digest}
	}
	for w := range t.Blocked {
		j.Blocked = append(j.Blocked, w)
	}
	sort.Strings(j.Blocked)
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return l.replaceHome(trustFile, append(body, '\n'))
}

// IsNotExist reports a missing-file error from the state helpers.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// applyTrust adds the HOME registry's trusted and blocked writers to a class map. Writers this HOME owns
// (self) are never changed, and the registry is the only source: nothing in the git directory counts.
func (l *Ledger) applyTrust(classes map[string]string) {
	t := l.ReadTrust()
	for w := range t.Blocked {
		if classes[w] != fold.ClassSelf {
			classes[w] = fold.ClassBlocked
		}
	}
	for w := range t.Trusted {
		if _, set := classes[w]; !set {
			classes[w] = fold.ClassTrusted
		}
	}
}

// trustPrefix returns how many of a trusted writer's ops are folded: the reviewed prefix, provided its
// digest still matches. A writer that appended since the review keeps the reviewed ops and the rest are
// held back; a writer whose reviewed prefix changed (or that has fewer ops) is not trusted at all.
func (l *Ledger) trustPrefix(w string, ops []*op.Op) (int, bool) {
	e, ok := l.ReadTrust().Trusted[w]
	if !ok || len(ops) < e.Ops || OpsDigest(ops[:e.Ops]) != e.Digest {
		return 0, false
	}
	return e.Ops, true
}

// Locked runs fn while holding this ledger's writer lock (so two bind or trust changes cannot interleave).
func (l *Ledger) Locked(fn func() error) error {
	lk, err := l.lock()
	if err != nil {
		return err
	}
	defer lk.Close()
	return fn()
}

// WriterReview returns a writer's ops as read now (full, even for a trusted writer), their review digest
// and the writer's class.
func (l *Ledger) WriterReview(w string) (ops []*op.Op, digest, class string, err error) {
	s, err := l.snapshot()
	if err != nil {
		return nil, "", "", err
	}
	// A full review read is explicit and per call: it never changes a concurrent normal read and never
	// populates the normal view cache with unreviewed ops.
	in, err := l.readAll(s, readFullReview)
	if err != nil {
		return nil, "", "", err
	}
	for _, r := range in.Refs {
		if r.Writer == w {
			if r.Rejected != "" {
				return nil, "", in.Class(w), wrap(ErrRefused, "writer %s was rejected: %s", w, r.Rejected)
			}
			return r.Ops, OpsDigest(r.Ops), in.Class(w), nil
		}
	}
	return nil, "", "", wrap(ErrNotFound, "no writer %s", w)
}
