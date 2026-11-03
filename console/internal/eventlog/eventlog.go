// Package eventlog stores the kernel's facts in an append-only SQLite log. It holds no
// second projection: opening folds the log through kernel.Replay, so restart and live
// state are one fold over one log. It is not wired into the console yet.
package eventlog

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ericmacdougall/agent-harness/console/internal/kernel"
	_ "modernc.org/sqlite"
)

const (
	formatVersion = 1
	// MaxFacts bounds the log. Opening replays every fact, about 6 seconds per million
	// on the reference Mac, so this is the stated limit. Recovery at the limit is an
	// export and a new data directory.
	MaxFacts = 1_000_000
	// Reserve is the headroom kept for must-append facts once ordinary facts reach
	// MaxFacts - Reserve, so the console can still start, record outcomes, discard and close.
	Reserve = 50_000
	// LockName is the lock the 0.1 console also holds, so the two can never share a
	// data directory.
	LockName = "console.lock"
	fileName = "facts.db"
)

// mustAppend kinds record an outcome, a release, a close or a restart. They may use
// the reserve. A full reserve latches the log.
var mustAppend = map[kernel.FactKind]bool{
	kernel.FactProcessRestarted: true, kernel.FactProviderCompleted: true, kernel.FactOutcomeUnknown: true,
	kernel.FactProviderRefused: true, kernel.FactAbandoned: true, kernel.FactSessionClosed: true,
	kernel.FactControlOutcome: true, kernel.FactAuthBoundaryCrossed: true, kernel.FactLateFrameObserved: true,
	kernel.FactSessionQuarantined: true,
}

// isMustAppend classifies by fact: only a stop request may use the reserve, so
// repeated pauses cannot drain it.
func isMustAppend(f kernel.Fact) bool {
	return mustAppend[f.Kind] || f.Kind == kernel.FactControlRequested && f.Control == "stop"
}

// revoking kinds take authority away. If one cannot commit, authority must not
// outlive the failure, so the log latches.
var revoking = map[kernel.FactKind]bool{kernel.FactAuthBoundaryCrossed: true, kernel.FactSessionQuarantined: true}

var (
	// ErrLatched means the log's state is unknown. Every append refuses until the
	// console restarts and replays the truth. Stop-work effects stay with the adapter.
	ErrLatched = errors.New("event log is latched: its state is unknown; restart the console")
	// ErrConflict means the log moved since the caller decided. Nothing was written.
	ErrConflict = errors.New("event log moved since this decision; decide again")
	// ErrQuota means the log is full. Nothing was written.
	ErrQuota = errors.New("event log is full; export it and continue in a new data directory")
	// ErrCommandConflict means a command identity was reused for a different command.
	ErrCommandConflict = errors.New("command identity already used for a different command")
	ErrLocked          = errors.New("data directory is in use by another console")
	ErrFormat          = errors.New("event log was written by an incompatible version")
)

// barrier lets tests stop or fail an append at a named step. Nil in production.
var barrier func(step string) error

// Log is one open fact log. A single connection serializes every append.
type Log struct {
	mu      sync.Mutex
	db      *sql.DB
	unlock  func()
	key     []byte
	latched bool
	count   uint64
}

func dsn(path string) string {
	// Pragmas go in the DSN so a replaced pool connection keeps them. fullfsync only
	// takes effect on Darwin, where plain fsync does not reach stable storage.
	return "file:" + filepath.ToSlash(path) + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=fullfsync(1)&_pragma=checkpoint_fullfsync(1)&_pragma=busy_timeout(5000)"
}

// Open locks dir, opens or creates its log, replays it and records the restart. A
// restart that cannot commit leaves the log latched with the replayed projection.
func Open(ctx context.Context, dir string, now string) (*Log, kernel.Projection, []kernel.Quarantined, error) {
	empty := kernel.NewProjection()
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, empty, nil, errors.New("data directory must be an existing real directory")
	}
	unlock, err := lockDir(filepath.Join(dir, LockName))
	if err != nil {
		return nil, empty, nil, err
	}
	path := filepath.Join(dir, fileName)
	// The DSN is a URI, so these would make SQLite open a different file than the one
	// the lock guards.
	if strings.ContainsAny(path, "?#%") {
		unlock()
		return nil, empty, nil, errors.New("data directory path may not contain ?, # or %")
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		unlock()
		return nil, empty, nil, errors.New("event log must be a regular file")
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		unlock()
		return nil, empty, nil, err
	}
	db.SetMaxOpenConns(1)
	l := &Log{db: db, unlock: unlock}
	fail := func(err error) (*Log, kernel.Projection, []kernel.Quarantined, error) {
		l.Close()
		return nil, empty, nil, err
	}
	if err = l.initialize(ctx); err != nil {
		return fail(err)
	}
	facts, err := l.load(ctx)
	if err != nil {
		return fail(err)
	}
	p, quarantined, err := kernel.Replay(facts)
	if err != nil {
		return fail(err)
	}
	decision, err := kernel.Decide(p, kernel.In{Kind: kernel.ObRestart, Principal: kernel.Principal{Class: kernel.PrincipalSystem}, At: now})
	if err != nil {
		return fail(err)
	}
	if len(decision.Facts) > 0 {
		stored, _, err := l.Append(ctx, p.LastSeq, "", "", decision.Facts)
		if err != nil {
			// The restart rule could not be recorded, so nothing may be admitted.
			l.latch()
			return l, p, quarantined, nil
		}
		for _, f := range stored {
			if p, err = kernel.Reduce(p, f); err != nil {
				return fail(err)
			}
		}
	}
	return l, p, quarantined, nil
}

func (l *Log) initialize(ctx context.Context) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS metadata (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), format INTEGER NOT NULL, digest_key BLOB NOT NULL, fact_count INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS facts (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, body BLOB NOT NULL, checksum TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS receipts (command_id TEXT PRIMARY KEY, digest TEXT NOT NULL, first_seq INTEGER NOT NULL, last_seq INTEGER NOT NULL)`,
	} {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var format int
	err = tx.QueryRowContext(ctx, `SELECT format, digest_key, fact_count FROM metadata`).Scan(&format, &l.key, &l.count)
	if errors.Is(err, sql.ErrNoRows) {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO metadata VALUES (1, ?, ?, 0)`, formatVersion, key); err != nil {
			return err
		}
		l.key, format = key, formatVersion
	} else if err != nil {
		return err
	}
	if format != formatVersion {
		return fmt.Errorf("%w: format %d", ErrFormat, format)
	}
	checks := []struct{ name, want string }{{"journal_mode", "wal"}, {"synchronous", "2"}}
	if runtime.GOOS == "darwin" {
		checks = append(checks, struct{ name, want string }{"fullfsync", "1"}, struct{ name, want string }{"checkpoint_fullfsync", "1"})
	}
	for _, check := range checks {
		var got string
		if err = tx.QueryRowContext(ctx, "PRAGMA "+check.name).Scan(&got); err != nil || got != check.want {
			return fmt.Errorf("pragma %s is %q, want %q", check.name, got, check.want)
		}
	}
	return tx.Commit()
}

func checksum(seq uint64, body []byte) string {
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("%d\x00", seq)), body...))
	return hex.EncodeToString(sum[:])
}

func (l *Log) load(ctx context.Context) ([]kernel.Fact, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq, kind, body, checksum FROM facts ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := []kernel.Fact{}
	var want uint64 = 1
	for rows.Next() {
		var seq uint64
		var kind, sum string
		var body []byte
		if err = rows.Scan(&seq, &kind, &body, &sum); err != nil {
			return nil, err
		}
		if seq != want || sum != checksum(seq, body) {
			return nil, fmt.Errorf("%w: fact %d is missing or damaged", kernel.ErrUnreadableLog, want)
		}
		f, err := kernel.DecodeFact(body)
		if err != nil || f.Seq != seq || string(f.Kind) != kind {
			return nil, fmt.Errorf("%w: fact %d does not decode", kernel.ErrUnreadableLog, seq)
		}
		facts = append(facts, f)
		want++
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if uint64(len(facts)) != l.count {
		return nil, fmt.Errorf("%w: %d facts, counter says %d", kernel.ErrUnreadableLog, len(facts), l.count)
	}
	return facts, nil
}

// CommandDigest binds a command's canonical bytes with the log's own key, so the log
// can recognise a retry without holding the command, and a low-entropy body cannot be
// guessed from the stored digest.
func (l *Log) CommandDigest(canonical []byte) string {
	mac := hmac.New(sha256.New, l.key)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// Latched reports whether every append now refuses.
func (l *Log) Latched() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.latched
}

func (l *Log) latch() {
	l.mu.Lock()
	l.latched = true
	l.mu.Unlock()
}

// Append commits facts decided against a projection whose last sequence was
// expectedSeq. commandID and digest are optional; with them a retry of the same
// command returns the facts it already committed, and a different command under the
// same identity is refused. It returns the facts as stored, which the caller reduces,
// and whether they were already committed by an earlier call, in which case they
// are already in any projection that saw that call.
//
// Outcomes follow the plan's log health table: a definite failure writes nothing
// and returns its error; any commit error not known to precede commit, or a revoking
// fact that cannot commit, latches the log.
func (l *Log) Append(ctx context.Context, expectedSeq uint64, commandID, digest string, facts []kernel.Fact) ([]kernel.Fact, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.latched {
		return nil, false, ErrLatched
	}
	stored, replayed, err := l.append(ctx, expectedSeq, commandID, digest, facts)
	switch {
	case err == nil:
		return stored, replayed, nil
	case errors.Is(err, errAmbiguous), errors.Is(err, errReserveSpent):
		l.latched = true
		return nil, false, fmt.Errorf("%w: %v", ErrLatched, err)
	case hasRevoking(facts):
		// Authority must not outlive a revocation that did not commit, even definitely.
		l.latched = true
		return nil, false, fmt.Errorf("%w: a revoking fact could not commit: %v", ErrLatched, err)
	}
	return nil, false, err
}

var errAmbiguous = errors.New("commit outcome unknown")

var errReserveSpent = errors.New("the must-append reserve is spent")

func hasRevoking(facts []kernel.Fact) bool {
	for _, f := range facts {
		if revoking[f.Kind] {
			return true
		}
	}
	return false
}

func (l *Log) append(ctx context.Context, expectedSeq uint64, commandID, digest string, facts []kernel.Fact) ([]kernel.Fact, bool, error) {
	if len(facts) == 0 {
		return nil, false, errors.New("nothing to append")
	}
	if (commandID == "") != (digest == "") {
		return nil, false, errors.New("a command identity needs its digest")
	}
	if err := step("begin"); err != nil {
		return nil, false, err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if commandID != "" {
		var storedDigest string
		var first, last uint64
		err = tx.QueryRowContext(ctx, `SELECT digest, first_seq, last_seq FROM receipts WHERE command_id = ?`, commandID).Scan(&storedDigest, &first, &last)
		if err == nil {
			if !hmac.Equal([]byte(storedDigest), []byte(digest)) {
				return nil, false, ErrCommandConflict
			}
			stored, err := readRange(ctx, tx, first, last)
			return stored, true, err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, false, err
		}
	}
	var count uint64
	if err = tx.QueryRowContext(ctx, `SELECT fact_count FROM metadata`).Scan(&count); err != nil {
		return nil, false, err
	}
	if count != expectedSeq {
		return nil, false, ErrConflict
	}
	limit := uint64(MaxFacts - Reserve)
	for _, f := range facts {
		if !isMustAppend(f) {
			if count+uint64(len(facts)) > limit {
				return nil, false, ErrQuota
			}
		}
	}
	if count+uint64(len(facts)) > MaxFacts {
		return nil, false, errReserveSpent
	}
	stored := make([]kernel.Fact, 0, len(facts))
	for i, f := range facts {
		if f.Seq != expectedSeq+uint64(i)+1 {
			return nil, false, ErrConflict
		}
		// The storage boundary validates too, so no path can store a fact out of shape.
		if err := kernel.ValidateFact(f); err != nil {
			return nil, false, err
		}
		body, err := kernel.EncodeFact(f)
		if err != nil {
			return nil, false, err
		}
		// What is stored is what a replay will decode, so the caller reduces that.
		decoded, err := kernel.DecodeFact(body)
		if err != nil {
			return nil, false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO facts (seq, kind, body, checksum) VALUES (?, ?, ?, ?)`, f.Seq, string(f.Kind), body, checksum(f.Seq, body)); err != nil {
			return nil, false, err
		}
		stored = append(stored, decoded)
	}
	if err := step("written"); err != nil {
		return nil, false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE metadata SET fact_count = ?`, count+uint64(len(facts))); err != nil {
		return nil, false, err
	}
	if commandID != "" {
		if _, err = tx.ExecContext(ctx, `INSERT INTO receipts VALUES (?, ?, ?, ?)`, commandID, digest, facts[0].Seq, facts[len(facts)-1].Seq); err != nil {
			return nil, false, err
		}
	}
	if err := step("before-commit"); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("%w: %v", errAmbiguous, err)
	}
	if err := step("after-commit"); err != nil {
		return nil, false, fmt.Errorf("%w: %v", errAmbiguous, err)
	}
	l.count = count + uint64(len(facts))
	return stored, false, nil
}

func step(name string) error {
	if barrier == nil {
		return nil
	}
	return barrier(name)
}

func readRange(ctx context.Context, tx *sql.Tx, first, last uint64) ([]kernel.Fact, error) {
	rows, err := tx.QueryContext(ctx, `SELECT seq, body, checksum FROM facts WHERE seq BETWEEN ? AND ? ORDER BY seq`, first, last)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := []kernel.Fact{}
	want := first
	for rows.Next() {
		var seq uint64
		var body []byte
		var sum string
		if err = rows.Scan(&seq, &body, &sum); err != nil {
			return nil, err
		}
		if seq != want || sum != checksum(seq, body) {
			return nil, fmt.Errorf("%w: receipt range is damaged", kernel.ErrUnreadableLog)
		}
		f, err := kernel.DecodeFact(body)
		if err != nil {
			return nil, err
		}
		facts = append(facts, f)
		want++
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if want != last+1 {
		return nil, fmt.Errorf("%w: receipt range is incomplete", kernel.ErrUnreadableLog)
	}
	return facts, nil
}

// Count is the number of committed facts.
func (l *Log) Count() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// Close releases the database and the directory lock.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	if l.db != nil {
		err = l.db.Close()
		l.db = nil
	}
	if l.unlock != nil {
		l.unlock()
		l.unlock = nil
	}
	return err
}
