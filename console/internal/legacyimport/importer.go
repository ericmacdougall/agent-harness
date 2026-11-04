package legacyimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ericmacdougall/agent-harness/console/internal/eventlog"
	"github.com/ericmacdougall/agent-harness/console/internal/kernel"
)

const journalName = "sessions.jsonl"

// Sentinel replaces sessions.jsonl after an import. It is one newline-terminated
// line that is not JSON, so 6172744 refuses to start on it (journal.go:30) and can
// never recreate an empty journal in its place.
const Sentinel = "agent-harness console: sessions moved to the event log (facts.db); see the console docs to roll back\n"

// Outcome says what Import did.
type Outcome string

const (
	Imported            Outcome = "imported"
	AlreadyImported     Outcome = "already_imported"
	SwapFinished        Outcome = "swap_finished"
	SentinelReinstalled Outcome = "sentinel_reinstalled"
)

// Report is what a directory holds, as the importer reads it.
type Report struct {
	Journal Journal
	Queue   Queue
	// Unsupported names items with no legal fact kind yet. Any of them refuses import.
	Unsupported []string
}

// Options configure Import. Now stamps facts and names files.
type Options struct {
	Now      string
	Reimport bool
	fs       fileOps
}

// kindsMapped are the reserved kinds this importer can already write. None yet: a
// kind lifts the guard only once it leaves kernel.ReservedFactKinds and has a mapping.
var kindsMapped = map[kernel.FactKind]bool{}

func kindReady(kind kernel.FactKind) bool {
	return !slices.Contains(kernel.ReservedFactKinds, kind) && kindsMapped[kind]
}

// unsupported is the completeness guard: an item with no legal fact would be lost
// by a completed import, which INV3 forbids.
func unsupported(j Journal, q Queue) []string {
	var out []string
	if q.Files > 0 && !kindReady("LegacyInputHeld") {
		out = append(out, fmt.Sprintf("%d queue files need LegacyInputHeld (K1c)", q.Files))
	}
	reviews := len(j.Reviews)
	for _, s := range j.Sessions {
		if s.RequestState == "review_unknown" {
			reviews++
		}
	}
	if reviews > 0 && !kindReady("ReviewOutcome") {
		out = append(out, fmt.Sprintf("%d review records need ReviewOutcome (K1d)", reviews))
	}
	return out
}

type journalFile struct {
	data     []byte
	present  bool
	sentinel bool
}

func readJournal(dir string) (journalFile, error) {
	path := filepath.Join(dir, journalName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return journalFile{}, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return journalFile{}, refuse("sessions.jsonl is not a regular file")
	}
	if info.Size() > MaxJournalBytes {
		return journalFile{}, refuse("journal is larger than 0.1.0 can read")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return journalFile{}, refuse("sessions.jsonl cannot be read")
	}
	return journalFile{data: data, present: true, sentinel: string(data) == Sentinel}, nil
}

func read(dir string, j journalFile) (Report, error) {
	journal, err := DecodeJournal(j.data, j.present)
	if err != nil {
		return Report{}, err
	}
	queue, err := decodeQueue(dir, journal.Sessions)
	if err != nil {
		return Report{}, err
	}
	return Report{Journal: journal, Queue: queue, Unsupported: unsupported(journal, queue)}, nil
}

// Verify reads dir under the console lock and writes nothing but console.lock if it
// is absent. It reports what an import would carry and what would stop it.
func Verify(dir string) (Report, error) {
	lock, err := eventlog.LockDir(dir)
	if err != nil {
		return Report{}, err
	}
	defer lock.Release()
	j, err := readJournal(dir)
	if err != nil {
		return Report{}, err
	}
	if j.sentinel {
		return Report{}, refuse("sessions.jsonl is the import sentinel; this directory was already imported")
	}
	return read(dir, j)
}

var receiptFor = map[string]kernel.Receipt{
	"":         kernel.ReceiptNone,
	"final":    kernel.ReceiptFinal,
	"rejected": kernel.ReceiptRejected,
	"paused":   kernel.ReceiptRejected,
	"intent":   kernel.ReceiptUnknown,
	"accepted": kernel.ReceiptUnknown,
	"unknown":  kernel.ReceiptUnknown,
}

// batch builds the import facts against p: one LegacyImported per session, the
// completion, then a restart whose trim hides old sessions and protects unresolved
// ones. Every fact is checked before anything is written.
func batch(p kernel.Projection, r Report, generation uint64, now string) ([]kernel.Fact, error) {
	open := 0
	for _, s := range p.Sessions {
		if !s.Closed {
			open++
		}
	}
	// 0.1.0 lets a session's queue file override its checkpoint's input revision and
	// objective hash, and clear passes when the queue is newer. That mapping belongs
	// with LegacyInputHeld (K1c). Until it exists here, no queue may reach a batch,
	// whatever the completeness guard says.
	if r.Queue.Files > 0 {
		return nil, refuse("queue overrides are not mapped yet (K1c)")
	}
	if open+len(r.Journal.Sessions) > kernel.MaxOpenSessions {
		return nil, refuse("%d open sessions after import is more than %d; close sessions in 0.1.0 and import again", open+len(r.Journal.Sessions), kernel.MaxOpenSessions)
	}
	seq := p.LastSeq
	next := func(f kernel.Fact) kernel.Fact {
		seq++
		f.Seq, f.SchemaVersion, f.At = seq, kernel.SchemaVersion, now
		return f
	}
	var facts []kernel.Fact
	for i, s := range r.Journal.Sessions {
		receipt, ok := receiptFor[s.RequestState]
		if !ok {
			return nil, refuse("session %d has a receipt this importer cannot map", i+1)
		}
		id := s.ID
		if generation > 1 {
			id = fmt.Sprintf("%s:g%d", s.ID, generation)
		}
		f := kernel.Fact{Kind: kernel.FactLegacyImported, ImportGeneration: generation, SessionID: id, SessionRevision: 1,
			Provider: s.Provider, ProviderID: s.ProviderID, ProfileID: s.ProfileID, CWD: s.CWD, Receipt: receipt}
		if receipt != kernel.ReceiptNone {
			f.RequestID = s.RequestID
		}
		if cp := s.Checkpoint; cp != nil {
			f.TaskID, f.Generation, f.InputRevision, f.ObjectiveHash, f.Passes = cp.ID, cp.Generation, cp.InputRevision, cp.ObjectiveHash, cp.Passes
		}
		f = next(f)
		if _, ok := p.Sessions[id]; ok {
			return nil, refuse("session %d is already in the log", i+1)
		}
		if err := kernel.ValidateFact(f); err != nil {
			return nil, refuse("session %d has a value out of shape", i+1)
		}
		facts = append(facts, f)
	}
	facts = append(facts,
		next(kernel.Fact{Kind: kernel.FactLegacyImportCompleted, Digest: r.Journal.Digest, QueueDigest: r.Queue.Digest, ImportGeneration: generation}),
		next(kernel.Fact{Kind: kernel.FactProcessRestarted}))
	folded := p
	for _, f := range facts {
		var err error
		if folded, err = kernel.Reduce(folded, f); err != nil {
			return nil, refuse("the import does not apply to this log: %v", err)
		}
	}
	return facts, nil
}

func stamp(now string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, now)
}

// Import runs at console open. It takes the console lock before reading anything,
// imports or recovers per the plan's recovery table, and returns the open log. Every
// refusal before commit leaves the directory as it was, except console.lock and,
// when the directory already had a log, that log's own restart fact.
func Import(ctx context.Context, dir string, opts Options) (*eventlog.Log, kernel.Projection, Outcome, error) {
	ops := opts.fs
	if ops == nil {
		ops = osOps{}
	}
	empty := kernel.NewProjection()
	lock, err := eventlog.LockDir(dir)
	if err != nil {
		return nil, empty, "", err
	}
	j, err := readJournal(dir)
	if err != nil {
		lock.Release()
		return nil, empty, "", err
	}
	if !eventlog.Exists(dir) {
		if j.sentinel {
			lock.Release()
			return nil, empty, "", refuse("sessions.jsonl is the import sentinel but the event log is missing; restore facts.db")
		}
		// Nothing is written until decode, guard and preflight pass.
		r, err := read(dir, j)
		if err == nil {
			err = check(r, empty, opts.Now)
		}
		if err == nil {
			err = preflight(dir, ops)
		}
		if err != nil {
			lock.Release()
			return nil, empty, "", err
		}
	}
	log, p, _, err := eventlog.OpenLocked(ctx, lock, opts.Now)
	if err != nil {
		return nil, empty, "", err
	}
	fail := func(err error) (*eventlog.Log, kernel.Projection, Outcome, error) {
		log.Close()
		return nil, empty, "", err
	}
	if log.Latched() {
		return fail(errors.New("event log is latched; import cannot run"))
	}
	if p.LegacyGeneration == 0 {
		if j.sentinel {
			return fail(refuse("sessions.jsonl is the import sentinel but the log records no import"))
		}
		return run(ctx, dir, log, p, j, 1, opts, ops)
	}
	switch {
	case j.sentinel:
		return log, p, AlreadyImported, nil
	case !j.present:
		if err := installSentinel(dir, ops); err != nil {
			return fail(err)
		}
		return log, p, SentinelReinstalled, nil
	}
	files, _, err := readQueueDir(dir)
	if err != nil {
		return fail(err)
	}
	sameJournal := JournalDigest(j.data) == p.LegacyImported
	sameQueue := QueueDigest(files) == p.LegacyQueueDigest
	if sameJournal && sameQueue {
		if err := swap(dir, j, p.LegacyImported, opts.Now, ops); err != nil {
			return fail(err)
		}
		return log, p, SwapFinished, nil
	}
	if !opts.Reimport {
		if sameJournal {
			return fail(refuse("queue files changed since the import; run --reimport"))
		}
		return fail(refuse("sessions.jsonl changed since the import; run --reimport"))
	}
	return run(ctx, dir, log, p, j, p.LegacyGeneration+1, opts, ops)
}

func check(r Report, p kernel.Projection, now string) error {
	if len(r.Unsupported) > 0 {
		return refuse("nothing imported: %s", strings.Join(r.Unsupported, "; "))
	}
	_, err := batch(p, r, p.LegacyGeneration+1, now)
	return err
}

func run(ctx context.Context, dir string, log *eventlog.Log, p kernel.Projection, j journalFile, generation uint64, opts Options, ops fileOps) (*eventlog.Log, kernel.Projection, Outcome, error) {
	fail := func(err error) (*eventlog.Log, kernel.Projection, Outcome, error) {
		log.Close()
		return nil, kernel.NewProjection(), "", err
	}
	r, err := read(dir, j)
	if err != nil {
		return fail(err)
	}
	if len(r.Unsupported) > 0 {
		return fail(refuse("nothing imported: %s", strings.Join(r.Unsupported, "; ")))
	}
	facts, err := batch(p, r, generation, opts.Now)
	if err != nil {
		return fail(err)
	}
	if err = preflight(dir, ops); err != nil {
		return fail(err)
	}
	stored, _, err := log.Append(ctx, p, "", "", facts)
	switch {
	case errors.Is(err, eventlog.ErrConflict), errors.Is(err, eventlog.ErrQuota):
		// Definite refusals: nothing was committed.
		return fail(fmt.Errorf("%w: append: %v", ErrRefused, err))
	case err != nil:
		// The commit may or may not have landed. The next open reads the log and
		// either finishes the swap or imports again; it never imports twice.
		return fail(fmt.Errorf("import outcome unknown; the next open recovers: %w", err))
	}
	for _, f := range stored {
		if p, err = kernel.Reduce(p, f); err != nil {
			return fail(err)
		}
	}
	// Committed. A failure from here on is finished by recovery at the next open.
	if err := swap(dir, j, r.Journal.Digest, opts.Now, ops); err != nil {
		return fail(fmt.Errorf("import committed; the swap finishes at the next open: %w", err))
	}
	return log, p, Imported, nil
}

// swap is steps 3 to 5: set aside a torn tail by copy, keep the journal under an
// .imported name, then put the sentinel in its place. Each step is idempotent.
func swap(dir string, j journalFile, digest, now string, ops fileOps) error {
	path := filepath.Join(dir, journalName)
	ts := stamp(now)
	if j.present {
		if _, torn := Acknowledged(j.data); torn != nil {
			if err := keepCopy(dir, journalName+".torn-", torn, ts, ops, func(b []byte) bool { return bytes.Equal(b, torn) }); err != nil {
				return err
			}
		}
		existing, err := findImported(dir, digest)
		if err != nil {
			return err
		}
		if existing == "" {
			if _, err := freeName(path+".imported-"+ts, func(n string) error { return ops.Link(path, n) }); err != nil {
				return err
			}
			if err := ops.SyncDir(dir); err != nil {
				return err
			}
		}
	}
	return installSentinel(dir, ops)
}

func keepCopy(dir, prefix string, data []byte, ts string, ops fileOps, same func([]byte) bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && same(b) {
				return nil
			}
		}
	}
	if _, err := freeName(filepath.Join(dir, prefix+ts), func(n string) error { return ops.WriteSync(n, data, true) }); err != nil {
		return err
	}
	return ops.SyncDir(dir)
}

// freeName runs create with base, then base.2, base.3 and so on while the name is
// taken, so a retry or a reimport with the same clock reading still finishes. The
// copies it would collide with hold other content: callers look for a matching copy
// first.
func freeName(base string, create func(string) error) (string, error) {
	name := base
	for i := 2; i <= 100; i++ {
		err := create(name)
		if !errors.Is(err, os.ErrExist) {
			return name, err
		}
		name = fmt.Sprintf("%s.%d", base, i)
	}
	return "", fmt.Errorf("no free name for %s", filepath.Base(base))
}

// findImported returns the .imported-* copy whose journal digest matches, if any.
// Copies with the same digest are the same journal.
func findImported(dir, digest string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), journalName+".imported-") && e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && JournalDigest(data) == digest {
			return name, nil
		}
	}
	return "", nil
}

func installSentinel(dir string, ops fileOps) error {
	path := filepath.Join(dir, journalName)
	tmp := path + ".sentinel-tmp"
	if err := ops.WriteSync(tmp, []byte(Sentinel), false); err != nil {
		return err
	}
	if err := ops.Rename(tmp, path); err != nil {
		return err
	}
	return ops.SyncDir(dir)
}

// preflight checks that the directory supports what the swap needs: a hard link and
// a rename over an existing name. FAT and exFAT fail it. It leaves no files behind.
func preflight(dir string, ops fileOps) error {
	probe := filepath.Join(dir, ".import-probe")
	names := []string{probe, probe + ".link", probe + ".next"}
	cleanup := func() {
		for _, name := range names {
			_ = os.Remove(name)
		}
	}
	cleanup()
	defer cleanup()
	if err := ops.WriteSync(probe, []byte("probe\n"), true); err != nil {
		return refuse("the data directory cannot be written")
	}
	if err := ops.Link(probe, names[1]); err != nil {
		return refuse("the data directory does not support hard links")
	}
	if err := ops.WriteSync(names[2], []byte("next\n"), true); err != nil {
		return refuse("the data directory cannot be written")
	}
	if err := ops.Rename(names[2], names[1]); err != nil {
		return refuse("the data directory does not support rename over a file")
	}
	return nil
}

// Rollback puts the imported journal back so 0.1.0 can run. It refuses unless
// sessions.jsonl is exactly the sentinel, and selects the copy by the recorded
// journal digest. The restored journal has no torn tail, so 0.1.0 starts on it, and
// its digest is unchanged, so an upgrade with no 0.1.0 changes finishes the swap.
// Nothing recorded in the event log after the import is visible to 0.1.0.
func Rollback(ctx context.Context, dir, now string) error {
	log, p, _, err := eventlog.Open(ctx, dir, now)
	if err != nil {
		return err
	}
	defer log.Close()
	return rollback(dir, p, osOps{})
}

func rollback(dir string, p kernel.Projection, ops fileOps) error {
	if p.LegacyGeneration == 0 {
		return refuse("the log records no import to roll back")
	}
	j, err := readJournal(dir)
	if err != nil {
		return err
	}
	if !j.sentinel {
		return refuse("sessions.jsonl is not the import sentinel; it may hold 0.1.0 work")
	}
	var kept []byte
	name, err := findImported(dir, p.LegacyImported)
	if err != nil {
		return err
	}
	switch {
	case name != "":
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		kept, _ = Acknowledged(data)
	case p.LegacyImported == JournalDigest(nil):
		// The import found no journal, so the rollback restores an empty one.
	default:
		return refuse("no imported journal copy matches the log; nothing changed")
	}
	path := filepath.Join(dir, journalName)
	tmp := path + ".rollback-tmp"
	if err := ops.WriteSync(tmp, kept, false); err != nil {
		return err
	}
	if err := ops.Rename(tmp, path); err != nil {
		return err
	}
	return ops.SyncDir(dir)
}
