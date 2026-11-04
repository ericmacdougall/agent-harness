package writer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/pycompat"
	"github.com/ericmacdougall/agent-harness/internal/safefs"
)

// FileName is the writer map inside <common>/goodqa.
const FileName = "writer.json"

// Entry is one fingerprint's writer.
type Entry struct {
	Writer    string `json:"writer"`
	Lease     string `json:"lease"`
	FirstSeen int64  `json:"first_seen"`
	Restored  bool   `json:"restored,omitempty"`
}

// Map is writer.json.
type Map struct {
	Writers map[string]Entry `json:"writers"`
	Current string           `json:"current"`
}

// Load reads writer.json (an absent file is an empty map). A malformed file is an error, never reset.
func Load(dir *safefs.Dir) (*Map, *safefs.Identity, error) {
	prior, err := dir.Snapshot(FileName, 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return &Map{Writers: map[string]Entry{}}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	m, err := parse(readBody(dir))
	if err != nil {
		return nil, nil, err
	}
	return m, prior, nil
}

func readBody(dir *safefs.Dir) []byte {
	b, _ := dir.ReadRegular(FileName, 1<<20)
	return b
}

func parse(b []byte) (*Map, error) {
	var m Map
	if err := json.Unmarshal(b, &m); err != nil || m.Writers == nil {
		return nil, errors.New("writer.json is malformed; refusing to mint over it")
	}
	for fp, e := range m.Writers {
		if len(fp) == 0 || len(fp) > 128 || !op.ValidID(e.Writer, op.PrefixWriter) || (len(e.Lease) != 32 && !(e.Restored && e.Lease == "")) {
			return nil, errors.New("writer.json has a malformed entry")
		}
	}
	if m.Current != "" && !op.ValidID(m.Current, op.PrefixWriter) {
		return nil, errors.New("writer.json current writer is malformed")
	}
	return &m, nil
}

// Self returns the set of writers in the map (the self class).
func (m *Map) Self() map[string]bool {
	out := map[string]bool{}
	for _, e := range m.Writers {
		out[e.Writer] = true
	}
	return out
}

// LeaseOf returns the lease of writer w.
func (m *Map) LeaseOf(w string) string {
	keys := make([]string, 0, len(m.Writers))
	for k := range m.Writers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if m.Writers[k].Writer == w {
			return m.Writers[k].Lease
		}
	}
	return ""
}

func (m *Map) encode() ([]byte, error) {
	ws := map[string]any{}
	for fp, e := range m.Writers {
		ent := map[string]any{"writer": e.Writer, "lease": e.Lease, "first_seen": e.FirstSeen}
		if e.Restored {
			ent["restored"] = true
		}
		ws[fp] = ent
	}
	return pycompat.Canonical(map[string]any{"writers": ws, "current": m.Current})
}

// Save replaces writer.json only if it is unchanged since Load (prior), so concurrent minting is detected.
func (m *Map) Save(dir *safefs.Dir, prior *safefs.Identity) error {
	b, err := m.encode()
	if err != nil {
		return err
	}
	return dir.Replace(FileName, append(b, '\n'), prior)
}

func newLease() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Resolve returns the writer for fingerprint fp, minting and saving a new one on a miss. The caller must
// hold the writer lock. minted reports a new writer.
func Resolve(dir *safefs.Dir, fp string, now int64) (w string, lease string, minted bool, err error) {
	m, prior, err := Load(dir)
	if err != nil {
		return "", "", false, err
	}
	if e, ok := m.Writers[fp]; ok {
		if m.Current != e.Writer {
			m.Current = e.Writer
			if err := m.Save(dir, prior); err != nil {
				return "", "", false, err
			}
		}
		return e.Writer, e.Lease, false, nil
	}
	id, err := op.NewID(op.PrefixWriter, now)
	if err != nil {
		return "", "", false, err
	}
	lease, err = newLease()
	if err != nil {
		return "", "", false, err
	}
	m.Writers[fp] = Entry{Writer: id, Lease: lease, FirstSeen: now}
	m.Current = id
	if err := m.Save(dir, prior); err != nil {
		return "", "", false, fmt.Errorf("writer.json changed concurrently: %w", err)
	}
	return id, lease, true, nil
}

// AddRestored records a writer restored from the mirror as self under a synthetic key. Restored writers
// never append again (their lease stays with the lost checkout); a new current writer is minted.
func AddRestored(dir *safefs.Dir, w string, now int64) error {
	m, prior, err := Load(dir)
	if err != nil {
		return err
	}
	key := "restored-" + w
	if _, ok := m.Writers[key]; ok {
		return nil
	}
	m.Writers[key] = Entry{Writer: w, FirstSeen: now, Restored: true}
	return m.Save(dir, prior)
}
