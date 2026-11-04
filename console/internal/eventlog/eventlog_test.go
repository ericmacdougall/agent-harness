package eventlog

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericmacdougall/agent-harness/console/internal/kernel"
)

var ctx = context.Background()

func stamp(n int) string {
	return fmt.Sprintf("2026-11-03T%02d:%02d:%02d.%09dZ", (n/3600000)%24, (n/60000)%60, (n/1000)%60, n%1000)
}

// driver decides inputs against the projection and commits through the log, the way
// the wired console will.
type driver struct {
	t   testing.TB
	log *Log
	p   kernel.Projection
	n   int
}

func open(t testing.TB, dir string) *driver {
	t.Helper()
	l, p, q, err := Open(ctx, dir, stamp(0))
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 0 {
		t.Fatalf("quarantined on open: %+v", q)
	}
	return &driver{t: t, log: l, p: p}
}

func (d *driver) do(in kernel.In) (kernel.Decision, error) {
	d.n++
	in.At = stamp(d.n + 1000)
	if in.Principal.Class == kernel.PrincipalProvider {
		in.Principal.SessionID = in.SessionID
	}
	decision, err := kernel.Decide(d.p, in)
	if err != nil || len(decision.Facts) == 0 {
		return decision, err
	}
	stored, _, err := d.log.Append(ctx, d.p, "", "", decision.Facts)
	if err != nil {
		return decision, err
	}
	for _, f := range stored {
		if d.p, err = kernel.Reduce(d.p, f); err != nil {
			d.t.Fatal(err)
		}
	}
	return decision, nil
}

func (d *driver) must(in kernel.In) {
	d.t.Helper()
	if _, err := d.do(in); err != nil {
		d.t.Fatalf("%s: %v", in.Kind, err)
	}
}

var user = kernel.Principal{Class: kernel.PrincipalUser}
var provider = kernel.Principal{Class: kernel.PrincipalProvider}
var system = kernel.Principal{Class: kernel.PrincipalSystem}

func (d *driver) session(id string) {
	d.must(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: id, Provider: kernel.ProviderCodex})
	d.must(kernel.In{Kind: kernel.ObConnected, Principal: provider, SessionID: id})
}

func (d *driver) turn(id, request string, finish bool) {
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: id, RequestID: request, RuntimeIdentity: "owner"})
	d.must(kernel.In{Kind: kernel.ObAccepted, Principal: provider, SessionID: id, RequestID: request})
	d.must(kernel.In{Kind: kernel.ObTurnBound, Principal: provider, SessionID: id, RequestID: request, TurnID: "t-" + request})
	if finish {
		d.must(kernel.In{Kind: kernel.ObCompleted, Principal: provider, SessionID: id, RequestID: request, TurnID: "t-" + request, Status: "completed"})
	}
}

// Restart equals live: the projection after reopening is the live projection with
// the restart rule applied, because both are one fold over one log.
func TestReopenEqualsLiveWithRestart(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	d.turn("a", "r1", true)
	d.turn("a", "r2", false)
	d.session("b")
	d.turn("b", "r1", true)
	live := d.p
	d.log.Close()
	again := open(t, dir)
	defer again.log.Close()
	want, err := kernel.Reduce(live, kernel.Fact{Seq: live.LastSeq + 1, SchemaVersion: kernel.SchemaVersion, At: stamp(0), Kind: kernel.FactProcessRestarted})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", deref(want)) != fmt.Sprintf("%+v", deref(again.p)) {
		t.Fatalf("reopened projection differs from live plus restart")
	}
	if got := again.p.Sessions["a"].Requests["r2"]; got != kernel.ReceiptUnknown {
		t.Fatalf("open receipt after restart: %q", got)
	}
	// A crash loop does not spend the log: a second open with no new facts appends nothing.
	count := again.log.Count()
	again.log.Close()
	third := open(t, dir)
	defer third.log.Close()
	if third.log.Count() != count {
		t.Fatalf("repeated restart appended: %d -> %d", count, third.log.Count())
	}
}

func deref(p kernel.Projection) map[string]kernel.Session {
	out := map[string]kernel.Session{}
	for id, s := range p.Sessions {
		out[id] = *s
	}
	return out
}

func TestSequenceCompareAndSwap(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.log.Close()
	stale := d.p
	d.session("a")
	decision, err := kernel.Decide(stale, kernel.In{Kind: kernel.InCreate, Principal: user, At: stamp(5), SessionID: "b", Provider: kernel.ProviderClaude})
	if err != nil {
		t.Fatal(err)
	}
	before := d.log.Count()
	if _, _, err = d.log.Append(ctx, stale, "", "", decision.Facts); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale decision committed: %v", err)
	}
	if d.log.Count() != before || d.log.Latched() {
		t.Fatal("a conflict wrote or latched")
	}
	// A sequence that skips ahead is a conflict too.
	decision.Facts[0].Seq = d.p.LastSeq + 5
	if _, _, err = d.log.Append(ctx, d.p, "", "", decision.Facts); !errors.Is(err, ErrConflict) {
		t.Fatalf("gap committed: %v", err)
	}
}

func TestConcurrentAppendsOneWinsNoGap(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	base := d.p
	var wins, conflicts int
	var mu sync.Mutex
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			decision, err := kernel.Decide(base, kernel.In{Kind: kernel.InCreate, Principal: user, At: stamp(50 + i), SessionID: fmt.Sprintf("c%d", i), Provider: kernel.ProviderClaude})
			if err != nil {
				t.Error(err)
				return
			}
			_, _, err = d.log.Append(ctx, base, "", "", decision.Facts)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	if wins != 1 || conflicts != 15 {
		t.Fatalf("wins %d conflicts %d", wins, conflicts)
	}
	d.log.Close()
	again := open(t, dir)
	defer again.log.Close()
}

func TestCommandReceiptsAreIdempotentAndBound(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.log.Close()
	decision, err := kernel.Decide(d.p, kernel.In{Kind: kernel.InCreate, Principal: user, At: stamp(9), SessionID: "a", Provider: kernel.ProviderClaude})
	if err != nil {
		t.Fatal(err)
	}
	digest := d.log.CommandDigest([]byte(`{"kind":"create","sessionId":"a"}`))
	first, replayed, err := d.log.Append(ctx, d.p, "cmd-1", digest, decision.Facts)
	if replayed {
		t.Fatal("first append reported as replayed")
	}
	if err != nil {
		t.Fatal(err)
	}
	count := d.log.Count()
	// A lost response retries with the old expected sequence: same facts, nothing new.
	again, replayed, err := d.log.Append(ctx, d.p, "cmd-1", digest, decision.Facts)
	if err != nil || !replayed || len(again) != len(first) || again[0].Seq != first[0].Seq || d.log.Count() != count {
		t.Fatalf("retry: %v %+v", err, again)
	}
	other := d.log.CommandDigest([]byte(`{"kind":"create","sessionId":"b"}`))
	if _, _, err = d.log.Append(ctx, d.p, "cmd-1", other, decision.Facts); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("reused identity: %v", err)
	}
	if strings.Contains(digest, "sessionId") || len(digest) != 64 {
		t.Fatal("digest exposes the command")
	}
}

func TestSecondConsoleIsLockedOut(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	if _, _, _, err := Open(ctx, dir, stamp(0)); !errors.Is(err, ErrLocked) {
		t.Fatalf("second open in-process: %v", err)
	}
	// A separate process, as a running 0.1 console would be.
	cmd := exec.Command(self(t), "-test.run=^TestHelperChild$")
	cmd.Env = append(os.Environ(), "EVENTLOG_CHILD=open", "EVENTLOG_DIR="+dir)
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "LOCKED") {
		t.Fatalf("child was not locked out: %s", out)
	}
	d.log.Close()
	again := open(t, dir)
	again.log.Close()
}

func TestBusyIsADefiniteFailure(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	defer d.log.Close()
	// Another writer holds the database write lock past the busy timeout.
	other, err := sql.Open("sqlite", "file:"+filepath.Join(dir, fileName)+"?_pragma=busy_timeout(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := other.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE metadata SET fact_count = fact_count`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.log.db.Exec(`PRAGMA busy_timeout=50`); err != nil {
		t.Fatal(err)
	}
	before := d.log.Count()
	_, err = d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "a", Provider: kernel.ProviderClaude})
	tx.Rollback()
	if err == nil || d.log.Latched() || d.log.Count() != before {
		t.Fatalf("busy: err=%v latched=%v", err, d.log.Latched())
	}
	d.must(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "a", Provider: kernel.ProviderClaude})
}

func TestDiskFullIsDefiniteAndRevokingLatches(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	defer d.log.Close()
	d.session("a")
	d.turn("a", "r1", false)
	var pages int
	if err := d.log.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	// SQLite's own full-database error, the same path as a full disk.
	if _, err := d.log.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
		t.Fatal(err)
	}
	before := d.log.Count()
	_, err := d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "big" + strings.Repeat("x", 100), Provider: kernel.ProviderClaude, CWD: "/" + strings.Repeat("d", 4000)})
	for i := 0; err == nil && i < 200; i++ {
		_, err = d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: fmt.Sprintf("f%03d", i), Provider: kernel.ProviderClaude, CWD: "/" + strings.Repeat("d", 4000)})
	}
	if err == nil || errors.Is(err, ErrLatched) || d.log.Latched() {
		t.Fatalf("full database: err=%v latched=%v", err, d.log.Latched())
	}
	if d.log.Count() < before {
		t.Fatal("count went backwards")
	}
	// A revoking fact that cannot commit latches: authority must not outlive the failure.
	barrier = func(step string) error {
		if step == "written" {
			return errors.New("injected definite failure")
		}
		return nil
	}
	_, err = d.do(kernel.In{Kind: kernel.ObAuthBoundary, Principal: system, Provider: kernel.ProviderCodex})
	barrier = nil
	if !errors.Is(err, ErrLatched) || !d.log.Latched() {
		t.Fatalf("revoking fact failure did not latch: %v", err)
	}
	if _, err = d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "z", Provider: kernel.ProviderClaude}); !errors.Is(err, ErrLatched) {
		t.Fatalf("latched log admitted: %v", err)
	}
}

func TestAmbiguousCommitLatches(t *testing.T) {
	for _, at := range []string{"after-commit"} {
		t.Run(at, func(t *testing.T) {
			d := open(t, t.TempDir())
			defer d.log.Close()
			barrier = func(step string) error {
				if step == at {
					return errors.New("injected: commit returned an unclear error")
				}
				return nil
			}
			_, err := d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "a", Provider: kernel.ProviderClaude})
			barrier = nil
			if !errors.Is(err, ErrLatched) || !d.log.Latched() {
				t.Fatalf("ambiguous commit: %v", err)
			}
		})
	}
	for _, at := range []string{"begin", "written", "before-commit"} {
		t.Run(at, func(t *testing.T) {
			d := open(t, t.TempDir())
			defer d.log.Close()
			before := d.log.Count()
			barrier = func(step string) error {
				if step == at {
					return errors.New("injected definite failure")
				}
				return nil
			}
			_, err := d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "a", Provider: kernel.ProviderClaude})
			barrier = nil
			if err == nil || d.log.Latched() || d.log.Count() != before {
				t.Fatalf("definite failure at %s: err=%v latched=%v", at, err, d.log.Latched())
			}
		})
	}
}

func TestQuotaKeepsReserveForMustAppend(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.log.Close()
	d.session("a")
	d.session("idle")
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "a", RequestID: "r1", RuntimeIdentity: "owner"})
	// Move the counter to the edge of the ordinary limit, as a long-lived log would be.
	set := func(count uint64) {
		t.Helper()
		d.log.mu.Lock()
		defer d.log.mu.Unlock()
		gap := count - d.log.count
		if _, err := d.log.db.Exec(`UPDATE metadata SET fact_count = ?`, count); err != nil {
			t.Fatal(err)
		}
		d.log.count = count
		d.p.LastSeq += gap
	}
	set(MaxFacts - Reserve)
	_, err := d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "b", Provider: kernel.ProviderClaude})
	if !errors.Is(err, ErrQuota) || d.log.Latched() {
		t.Fatalf("ordinary fact past the limit: %v", err)
	}
	// An outcome still records, from the reserve.
	if _, err = d.do(kernel.In{Kind: kernel.ObUnknown, Principal: provider, SessionID: "a", RequestID: "r1", ReasonCode: "deadline"}); err != nil {
		t.Fatalf("must-append refused at quota: %v", err)
	}
	// Repeated pauses are ordinary facts, so they cannot drain the reserve.
	if _, err = d.do(kernel.In{Kind: kernel.InPause, Principal: user, SessionID: "idle"}); !errors.Is(err, ErrQuota) {
		t.Fatalf("pause used the reserve: %v", err)
	}
	// A stop still records, from the reserve: here it owes the unbound turn's interrupt.
	stop, err := d.do(kernel.In{Kind: kernel.InStop, Principal: user, SessionID: "a"})
	if err != nil {
		t.Fatalf("stop refused at quota: %v", err)
	}
	// The log judges eligibility itself: the same stop again changes nothing, so a
	// caller that skips Decide cannot spend the reserve with it.
	again := stop.Facts[0]
	again.Seq, again.At, again.SessionRevision = d.p.LastSeq+1, stamp(9000), d.p.Sessions["a"].Revision+1
	if _, _, err = d.log.Append(ctx, d.p, "", "", []kernel.Fact{again}); !errors.Is(err, ErrQuota) {
		t.Fatalf("a stop that changes nothing used the reserve: %v", err)
	}
	// Likewise a restart after a restart: the first is eligible, a second changes nothing.
	restart := func(n int) error {
		f := kernel.Fact{Kind: kernel.FactProcessRestarted, SchemaVersion: kernel.SchemaVersion, Seq: d.p.LastSeq + 1, At: stamp(9100 + n)}
		stored, _, err := d.log.Append(ctx, d.p, "", "", []kernel.Fact{f})
		for _, f := range stored {
			if d.p, err = kernel.Reduce(d.p, f); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	if err = restart(0); err != nil {
		t.Fatalf("first restart refused at quota: %v", err)
	}
	if err = restart(1); !errors.Is(err, ErrQuota) || d.log.Latched() {
		t.Fatalf("a restart after a restart used the reserve: %v latched=%v", err, d.log.Latched())
	}
	set(MaxFacts)
	if _, err = d.do(kernel.In{Kind: kernel.InAbandon, Principal: user, SessionID: "a", ExpectedRequest: "r1", Reason: kernel.Redact("done", func(s string) string { return s })}); !errors.Is(err, ErrLatched) || !d.log.Latched() {
		t.Fatalf("spent reserve did not latch: %v latched=%v", err, d.log.Latched())
	}
}

const canary = "CANARY-sk-live-7f3a9c2e"

// INV6: nothing secret-shaped reaches the files, including WAL and free pages.
func TestSecretsNeverReachTheFiles(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	redactor := func(s string) string { return strings.ReplaceAll(s, canary, "[redacted]") }
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "a", RequestID: "r1", RuntimeIdentity: "owner"})
	for _, in := range []kernel.In{
		{Kind: kernel.ObAccepted, Principal: provider, SessionID: "a", RequestID: "r1", Status: canary, Digest: canary, ReasonCode: canary},
		{Kind: kernel.ObTurnBound, Principal: provider, SessionID: "a", RequestID: canary, TurnID: canary},
		{Kind: kernel.ObCompleted, Principal: provider, SessionID: "a", RequestID: "r1", TurnID: "x", Status: canary, Digest: canary},
		{Kind: kernel.ObRefused, Principal: provider, SessionID: "a", RequestID: "r9", ReasonCode: canary},
		{Kind: kernel.ObControlOutcome, Principal: provider, SessionID: "a", Control: canary, Outcome: canary},
		{Kind: kernel.ObUnknown, Principal: provider, SessionID: "a", RequestID: "r1", ReasonCode: canary},
		{Kind: kernel.InAbandon, Principal: user, SessionID: "a", ExpectedRequest: "r1", Reason: kernel.Redact("reason "+canary, redactor)},
		{Kind: kernel.ObConversationBound, Principal: provider, SessionID: "a", ProviderID: canary, RuntimeIdentity: canary},
	} {
		_, _ = d.do(in)
	}
	// A receipt holds only its keyed digest, never the command.
	decision, err := kernel.Decide(d.p, kernel.In{Kind: kernel.InCreate, Principal: user, At: stamp(77), SessionID: "receipt", Provider: kernel.ProviderClaude})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.log.Append(ctx, d.p, "cmd-canary", d.log.CommandDigest([]byte(canary)), decision.Facts); err != nil {
		t.Fatal(err)
	}
	var receipts int
	if err = d.log.db.QueryRow(`SELECT count(*) FROM receipts`).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("receipt not written, so the check is vacuous: %d %v", receipts, err)
	}
	d.log.Close()
	needle := []byte(strings.TrimPrefix(canary, "CANARY-"))
	for _, name := range []string{fileName, fileName + "-wal", fileName + "-shm"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if bytes.Contains(data, needle) {
			t.Fatalf("secret reached %s", name)
		}
	}
}

// Crash safety: the child appends one fact per transaction and prints each
// acknowledgement. It dies at a named step, or the parent kills it at a random time.
func TestHelperChild(t *testing.T) {
	mode := os.Getenv("EVENTLOG_CHILD")
	if mode == "" {
		t.Skip("helper process only")
	}
	dir := os.Getenv("EVENTLOG_DIR")
	if mode == "open" {
		if _, _, _, err := Open(ctx, dir, stamp(0)); errors.Is(err, ErrLocked) {
			fmt.Println("LOCKED")
		}
		os.Exit(0)
	}
	die := os.Getenv("EVENTLOG_DIE")
	after, _ := strconv.Atoi(os.Getenv("EVENTLOG_DIE_AFTER"))
	appends := 0
	barrier = func(step string) error {
		if step == die && appends >= after {
			os.Stdout.Sync()
			os.Exit(3)
		}
		return nil
	}
	d := open(t, dir)
	for i := 0; ; i++ {
		id := fmt.Sprintf("s%06d", i)
		if _, err := d.do(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: id, Provider: kernel.ProviderClaude}); err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		appends++
		fmt.Printf("ACK %d\n", d.log.Count())
	}
}

// self is the test binary by absolute path, since Windows refuses to run an
// executable found relative to the current directory.
func self(t *testing.T) string {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func child(t *testing.T, dir string, env ...string) *exec.Cmd {
	cmd := exec.Command(self(t), "-test.run=^TestHelperChild$")
	cmd.Env = append(append(os.Environ(), "EVENTLOG_CHILD=append", "EVENTLOG_DIR="+dir), env...)
	return cmd
}

func lastAck(out []byte) uint64 {
	var last uint64
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ACK ") {
			last, _ = strconv.ParseUint(strings.TrimPrefix(line, "ACK "), 10, 64)
		}
	}
	return last
}

func verify(t *testing.T, dir string, acked uint64) uint64 {
	t.Helper()
	l, p, q, err := Open(ctx, dir, stamp(0))
	if err != nil {
		t.Fatalf("reopen after crash: %v", err)
	}
	defer l.Close()
	if len(q) != 0 {
		t.Fatalf("quarantined after crash: %+v", q)
	}
	committed := l.Count()
	if p.LastKind == kernel.FactProcessRestarted {
		committed--
	}
	if committed < acked {
		t.Fatalf("acknowledged %d facts, %d survived", acked, committed)
	}
	return committed
}

// Death at each step of the transaction: before commit nothing new survives; after
// commit the fact survives even though its acknowledgement was never printed.
func TestCrashAtEachTransactionStep(t *testing.T) {
	for _, step := range []string{"begin", "written", "before-commit", "after-commit"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			out, _ := child(t, dir, "EVENTLOG_DIE="+step, "EVENTLOG_DIE_AFTER=5").Output()
			acked := lastAck(out)
			if acked == 0 {
				t.Fatalf("child acknowledged nothing: %s", out)
			}
			// The open itself appended a restart, counted in acknowledgements.
			got := verify(t, dir, acked)
			want := acked
			if step == "after-commit" {
				want = acked + 1
			}
			if got != want {
				t.Fatalf("after death at %s: %d facts, want %d", step, got, want)
			}
		})
	}
}

// Random kills, half with the WAL torn past the last acknowledged commit's frames.
func TestRandomKillsLoseNoAcknowledgedFact(t *testing.T) {
	trials := 40
	if v, err := strconv.Atoi(os.Getenv("EVENTLOG_KILL_TRIALS")); err == nil {
		trials = v
	}
	seed := time.Now().UnixNano()
	if v, err := strconv.ParseInt(os.Getenv("EVENTLOG_SEED"), 10, 64); err == nil {
		seed = v
	}
	rng := rand.New(rand.NewSource(seed))
	torn, acks := 0, []uint64{}
	for trial := 0; trial < trials; trial++ {
		dir := t.TempDir()
		cmd := child(t, dir)
		stdout, _ := cmd.StdoutPipe()
		var buf bytes.Buffer
		var walAtAck int64
		done := make(chan struct{})
		var mu sync.Mutex
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() {
			defer close(done)
			chunk := make([]byte, 4096)
			for {
				n, err := stdout.Read(chunk)
				if n > 0 {
					mu.Lock()
					buf.Write(chunk[:n])
					if info, statErr := os.Stat(filepath.Join(dir, fileName+"-wal")); statErr == nil && bytes.Contains(chunk[:n], []byte("ACK")) {
						walAtAck = info.Size()
					}
					mu.Unlock()
				}
				if err != nil {
					return
				}
			}
		}()
		time.Sleep(time.Duration(20+rng.Intn(500)) * time.Millisecond)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		<-done
		mu.Lock()
		acked := lastAck(buf.Bytes())
		limit := walAtAck
		mu.Unlock()
		wal := filepath.Join(dir, fileName+"-wal")
		if info, err := os.Stat(wal); err == nil && trial%2 == 1 && info.Size() > limit && limit > 0 {
			if err = os.Truncate(wal, limit+rng.Int63n(info.Size()-limit+1)); err != nil {
				t.Fatal(err)
			}
			torn++
		}
		verify(t, dir, acked)
		acks = append(acks, acked)
	}
	sort.Slice(acks, func(i, j int) bool { return acks[i] < acks[j] })
	t.Logf("seed=%d trials=%d torn=%d acked min=%d median=%d max=%d", seed, trials, torn, acks[0], acks[len(acks)/2], acks[len(acks)-1])
	if acks[len(acks)/2] == 0 {
		t.Fatalf("seed=%d: kills landed before any acknowledgement, so the check is vacuous", seed)
	}
}

// Falsifier timing, kept as a measurement: EVENTLOG_FACTS sets the size.
func TestOpenTime(t *testing.T) {
	total, err := strconv.Atoi(os.Getenv("EVENTLOG_FACTS"))
	if err != nil {
		t.Skip("set EVENTLOG_FACTS to measure open time")
	}
	dir := t.TempDir()
	d := open(t, dir)
	if _, err = d.log.db.Exec(`PRAGMA synchronous=OFF`); err != nil {
		t.Fatal(err)
	}
	batch := []kernel.Fact{}
	expected := d.p
	for i := 0; d.p.LastSeq < uint64(total); i++ {
		id := fmt.Sprintf("s%07d", i)
		for _, in := range []kernel.In{
			{Kind: kernel.InCreate, Principal: user, SessionID: id, Provider: kernel.ProviderCodex},
			{Kind: kernel.ObConnected, Principal: provider, SessionID: id},
		} {
			in.At = stamp(i*1000 + 1)
			if in.Principal.Class == kernel.PrincipalProvider {
				in.Principal.SessionID = id
			}
			decision, _ := kernel.Decide(d.p, in)
			for _, f := range decision.Facts {
				d.p, _ = kernel.Reduce(d.p, f)
			}
			batch = append(batch, decision.Facts...)
		}
		for r := 0; r < 50; r++ {
			request := fmt.Sprintf("r%d", r)
			for _, in := range []kernel.In{
				{Kind: kernel.InSend, Principal: user, SessionID: id, RequestID: request, RuntimeIdentity: "owner"},
				{Kind: kernel.ObAccepted, Principal: provider, SessionID: id, RequestID: request},
				{Kind: kernel.ObTurnBound, Principal: provider, SessionID: id, RequestID: request, TurnID: "t"},
				{Kind: kernel.ObCompleted, Principal: provider, SessionID: id, RequestID: request, TurnID: "t", Status: "completed"},
			} {
				in.At = stamp(i*1000 + r + 2)
				if in.Principal.Class == kernel.PrincipalProvider {
					in.Principal.SessionID = id
				}
				decision, _ := kernel.Decide(d.p, in)
				for _, f := range decision.Facts {
					d.p, _ = kernel.Reduce(d.p, f)
				}
				batch = append(batch, decision.Facts...)
			}
		}
		// Close each session after its requests, as users do, so the open-session limit holds.
		closing, _ := kernel.Decide(d.p, kernel.In{Kind: kernel.InClose, Principal: user, At: stamp(i*1000 + 999), SessionID: id})
		for _, f := range closing.Facts {
			d.p, _ = kernel.Reduce(d.p, f)
		}
		batch = append(batch, closing.Facts...)
		if len(batch) >= 5000 {
			if _, _, err = d.log.Append(ctx, expected, "", "", batch); err != nil {
				t.Fatal(err)
			}
			expected = d.p
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if _, _, err = d.log.Append(ctx, expected, "", "", batch); err != nil {
			t.Fatal(err)
		}
	}
	d.log.Close()
	// The first open after a bulk write also checkpoints a large WAL, so both opens
	// are reported.
	for _, label := range []string{"first", "warm"} {
		start := time.Now()
		l, p, _, err := Open(ctx, dir, stamp(0))
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("OPEN %s facts=%d sessions=%d ms=%d\n", label, p.LastSeq, len(p.Sessions), elapsed.Milliseconds())
		l.Close()
	}
}

// A restart that cannot be recorded leaves nothing admissible.
func TestRestartThatCannotCommitLatches(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	d.log.Close()
	barrier = func(step string) error {
		if step == "written" {
			return errors.New("injected definite failure")
		}
		return nil
	}
	l, p, _, err := Open(ctx, dir, stamp(0))
	barrier = nil
	if err != nil || l == nil || !l.Latched() {
		t.Fatalf("open with a failed restart: err=%v latched=%v", err, l != nil && l.Latched())
	}
	defer l.Close()
	if p.Sessions["a"] == nil || !p.Sessions["a"].ReadOnly || p.Sessions["a"].Connected {
		t.Fatal("a latched open must show every session read-only")
	}
	if _, _, err = l.Append(ctx, p, "", "", []kernel.Fact{{Seq: p.LastSeq + 1, SchemaVersion: kernel.SchemaVersion, At: stamp(1), Kind: kernel.FactProcessRestarted}}); !errors.Is(err, ErrLatched) {
		t.Fatalf("latched log admitted: %v", err)
	}
}

// A damaged fact refuses the log even when the damage still decodes.
func TestDamagedFactRefusesOpen(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "a", RequestID: "r1", RuntimeIdentity: "owner"})
	var body []byte
	if err := d.log.db.QueryRow(`SELECT body FROM facts WHERE seq = ?`, d.p.LastSeq).Scan(&body); err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(body, []byte(`"r1"`), []byte(`"r2"`), 1)
	if bytes.Equal(altered, body) {
		t.Fatal("fixture did not change")
	}
	if _, err := d.log.db.Exec(`UPDATE facts SET body = ? WHERE seq = ?`, altered, d.p.LastSeq); err != nil {
		t.Fatal(err)
	}
	d.log.Close()
	if l, _, _, err := Open(ctx, dir, stamp(0)); !errors.Is(err, kernel.ErrUnreadableLog) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("damaged log opened: %v", err)
	}
}

// Append returns what a replay will decode, not the caller's struct.
func TestAppendReturnsTheDecodedFacts(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.log.Close()
	f := kernel.Fact{Seq: d.p.LastSeq + 1, SchemaVersion: kernel.SchemaVersion, At: stamp(3), Kind: kernel.FactSessionCreated, SessionID: "a", SessionRevision: 1, Provider: kernel.ProviderClaude, Passes: map[string]string{}}
	stored, _, err := d.log.Append(ctx, d.p, "", "", []kernel.Fact{f})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := kernel.EncodeFact(f)
	want, _ := kernel.DecodeFact(data)
	if stored[0].Passes != nil || fmt.Sprintf("%#v", stored[0]) != fmt.Sprintf("%#v", want) {
		t.Fatalf("returned %#v, replay decodes %#v", stored[0], want)
	}
}

// The storage boundary validates facts itself, so no caller can store one out of shape.
func TestAppendRefusesAFactOutOfShape(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	s := d.p.Sessions["a"]
	bad := kernel.Fact{Seq: d.p.LastSeq + 1, SchemaVersion: kernel.SchemaVersion, At: stamp(9), Kind: kernel.FactLateFrameObserved, SessionID: "a", SessionRevision: s.Revision + 1, LateKind: "final", Digest: canary}
	before := d.log.Count()
	if _, _, err := d.log.Append(ctx, d.p, "", "", []kernel.Fact{bad}); err == nil || d.log.Count() != before || d.log.Latched() {
		t.Fatalf("out-of-shape fact stored: %v", err)
	}
	d.log.Close()
	data, _ := os.ReadFile(filepath.Join(dir, fileName))
	if bytes.Contains(data, []byte(canary)) {
		t.Fatal("canary stored")
	}
}

// A revoking fact that loses the sequence race latches too: authority must not
// outlive a revocation that did not commit.
func TestRevokingConflictLatches(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.log.Close()
	d.session("a")
	stale := d.p
	d.session("b")
	decision, err := kernel.Decide(stale, kernel.In{Kind: kernel.ObAuthBoundary, Principal: system, At: stamp(99), Provider: kernel.ProviderCodex})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.log.Append(ctx, stale, "", "", decision.Facts); !errors.Is(err, ErrLatched) || !d.log.Latched() {
		t.Fatalf("revoking conflict: %v", err)
	}
}

// The canary check also reads the WAL while the log is open, before a checkpoint.
func TestSecretsNeverReachTheOpenWAL(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	defer d.log.Close()
	d.session("a")
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "a", RequestID: "r1", RuntimeIdentity: "owner"})
	d.must(kernel.In{Kind: kernel.ObAccepted, Principal: provider, SessionID: "a", RequestID: "r1", Status: canary, Digest: canary})
	d.must(kernel.In{Kind: kernel.ObCompleted, Principal: provider, SessionID: "a", RequestID: "r1", TurnID: "x", Status: canary, Digest: canary})
	if _, err := d.do(kernel.In{Kind: kernel.ObUnknown, Principal: provider, SessionID: "a", RequestID: "r1", ReasonCode: canary}); err != nil {
		t.Fatal(err)
	}
	if len(d.p.Sessions["a"].Evidence) == 0 {
		t.Fatal("no late evidence was recorded, so the check is vacuous")
	}
	needle := []byte(strings.TrimPrefix(canary, "CANARY-"))
	wal, err := os.ReadFile(filepath.Join(dir, fileName+"-wal"))
	if err != nil || len(wal) == 0 {
		t.Fatalf("no open WAL to inspect: %v", err)
	}
	if bytes.Contains(wal, needle) {
		t.Fatal("secret reached the WAL")
	}
}

func TestLockRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, LockName)); err != nil {
		t.Skip("symlinks unavailable")
	}
	if l, _, _, err := Open(ctx, dir, stamp(0)); err == nil {
		l.Close()
		t.Fatal("opened through a symlinked lock")
	}
}

func TestPathWithURIMetacharactersIsRefused(t *testing.T) {
	root := t.TempDir()
	// "a%62" percent-decodes to "ab": without the guard SQLite would open ab's log
	// while the lock guards a%62.
	dir, decoy := filepath.Join(root, "a%62"), filepath.Join(root, "ab")
	if os.Mkdir(dir, 0o700) != nil || os.Mkdir(decoy, 0o700) != nil {
		t.Skip("cannot create those names here")
	}
	if l, _, _, err := Open(ctx, dir, stamp(0)); err == nil {
		l.Close()
		t.Fatal("opened a path SQLite reads differently")
	}
	if _, err := os.Stat(filepath.Join(decoy, fileName)); err == nil {
		t.Fatal("a log was created in the decoy directory")
	}
}

// Repeated presses neither grow the log nor reach the reserve.
func TestRepeatedControlsRecordOnce(t *testing.T) {
	d := open(t, t.TempDir())
	defer d.log.Close()
	d.session("idle")
	d.session("busy")
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "busy", RequestID: "r1", RuntimeIdentity: "owner"})
	before := d.log.Count()
	for i := 0; i < 200; i++ {
		for _, id := range []string{"idle", "busy"} {
			for _, kind := range []kernel.InputKind{kernel.InStop, kernel.InPause} {
				if _, err := d.do(kernel.In{Kind: kind, Principal: user, SessionID: id}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if got := d.log.Count() - before; got > 2 {
		t.Fatalf("800 presses appended %d facts", got)
	}
}

func TestAppendAfterCloseRefuses(t *testing.T) {
	d := open(t, t.TempDir())
	d.log.Close()
	if _, _, err := d.log.Append(ctx, d.p, "", "", []kernel.Fact{{Seq: d.p.LastSeq + 1, SchemaVersion: kernel.SchemaVersion, At: stamp(1), Kind: kernel.FactProcessRestarted}}); err == nil {
		t.Fatal("append after close")
	}
}

func TestMissingLogIsNotAFreshStart(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("a")
	d.log.Close()
	for _, name := range []string{fileName, fileName + "-wal", fileName + "-shm"} {
		_ = os.Remove(filepath.Join(dir, name))
	}
	if l, _, _, err := Open(ctx, dir, stamp(0)); err == nil {
		l.Close()
		t.Fatal("a deleted log opened as a new one")
	}
}

// At the limit, floods of every provider frame and every user control spend only a
// bounded part of the reserve, and an outcome, a discard, a close and a restart still
// record afterwards.
func TestFloodsAtTheLimitCannotSpendTheReserve(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	d.session("codex")
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "codex", RequestID: "r1", RuntimeIdentity: "owner"})
	d.must(kernel.In{Kind: kernel.InCreate, Principal: user, SessionID: "claude", Provider: kernel.ProviderClaude})
	d.must(kernel.In{Kind: kernel.InSend, Principal: user, SessionID: "claude", RequestID: "r1", RuntimeIdentity: "owner"})
	d.log.mu.Lock()
	gap := uint64(MaxFacts-Reserve) - d.log.count
	if _, err := d.log.db.Exec(`UPDATE metadata SET fact_count = ?`, MaxFacts-Reserve); err != nil {
		t.Fatal(err)
	}
	d.log.count = MaxFacts - Reserve
	d.p.LastSeq += gap
	d.log.mu.Unlock()
	start := d.log.Count()
	for i := 0; i < 2000; i++ {
		for _, id := range []string{"codex", "claude"} {
			for _, in := range []kernel.In{
				{Kind: kernel.ObDisconnected, Principal: provider, SessionID: id},
				{Kind: kernel.ObConnected, Principal: provider, SessionID: id},
				{Kind: kernel.ObControlOutcome, Principal: provider, SessionID: id, Control: "pause", Outcome: []string{"confirmed", "unconfirmed", "rejected"}[i%3]},
				{Kind: kernel.InStop, Principal: user, SessionID: id},
				{Kind: kernel.InPause, Principal: user, SessionID: id},
				{Kind: kernel.ObCompleted, Principal: provider, SessionID: id, RequestID: fmt.Sprintf("old%d", i), TurnID: "x", Status: "completed"},
				{Kind: kernel.ObTurnBound, Principal: provider, SessionID: id, RequestID: "r1", TurnID: fmt.Sprintf("t%d", i)},
				{Kind: kernel.ObQuarantine, Principal: system, SessionID: id, ReasonCode: "flood"},
			} {
				if _, err := d.do(in); err != nil && !errors.Is(err, ErrQuota) {
					var refusal *kernel.Refusal
					if !errors.As(err, &refusal) {
						t.Fatalf("%s on %s: %v", in.Kind, id, err)
					}
				}
			}
		}
	}
	spent := d.log.Count() - start
	if spent > 2*11 || d.log.Latched() {
		t.Fatalf("floods spent %d reserve facts, latched=%v", spent, d.log.Latched())
	}
	reason := kernel.Redact("done", func(s string) string { return s })
	for _, id := range []string{"codex", "claude"} {
		if s := d.p.Sessions[id]; s.Abandoned == nil && kernel.Status(s) != "closed" {
			if _, err := d.do(kernel.In{Kind: kernel.InAbandon, Principal: user, SessionID: id, ExpectedRequest: s.LastRequest, Reason: reason}); err != nil {
				t.Fatalf("discard after floods on %s: %v", id, err)
			}
		}
		if _, err := d.do(kernel.In{Kind: kernel.InClose, Principal: user, SessionID: id}); err != nil {
			t.Fatalf("close after floods on %s: %v", id, err)
		}
	}
	// The counter was moved past rows that do not exist, so a reopen would rightly
	// refuse the gap. The restart is checked as the open path would append it.
	if _, err := d.do(kernel.In{Kind: kernel.ObRestart, Principal: system}); err != nil || d.p.LastKind != kernel.FactProcessRestarted {
		t.Fatalf("restart after floods: %v", err)
	}
	// Windows cannot remove the temp dir while the lock is held.
	if err := d.log.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTooManyOpenSessionsRefusesOpen(t *testing.T) {
	dir := t.TempDir()
	d := open(t, dir)
	facts := []kernel.Fact{}
	p := d.p
	// Raw creations past the limit, as only a foreign writer could produce.
	for i := 0; i <= maxOpenAtOpen; i++ {
		f := kernel.Fact{Seq: p.LastSeq + 1, SchemaVersion: kernel.SchemaVersion, At: stamp(i + 10), Kind: kernel.FactSessionCreated, SessionID: fmt.Sprintf("s%05d", i), SessionRevision: 1, Provider: kernel.ProviderClaude}
		var err error
		if p, err = kernel.Reduce(p, f); err != nil {
			t.Fatal(err)
		}
		facts = append(facts, f)
	}
	if _, _, err := d.log.Append(ctx, d.p, "", "", facts); err != nil {
		t.Fatal(err)
	}
	d.log.Close()
	if l, _, _, err := Open(ctx, dir, stamp(0)); !errors.Is(err, kernel.ErrUnreadableLog) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("opened a log with more open sessions than the reserve covers: %v", err)
	}
}
