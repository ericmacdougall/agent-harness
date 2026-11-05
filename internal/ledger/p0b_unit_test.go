package ledger_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/store"
)

// buildOps makes a small valid single-writer ledger in memory: project root, n tickets, one comment each.
func buildOps(t *testing.T, tickets int) (project, writer string, ops []*op.Op) {
	t.Helper()
	wall := int64(1_800_000_000_000)
	rootID, _ := op.NewID(op.PrefixOp, wall)
	project = op.PrefixProject + strings.TrimPrefix(rootID, op.PrefixOp)
	writer, _ = op.NewID(op.PrefixWriter, wall)
	act := op.Actor{Kind: "human", Label: "cli"}
	add := func(o *op.Op) {
		raw, err := o.Encode()
		if err != nil {
			t.Fatal(err)
		}
		p, err := op.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, p)
	}
	add(&op.Op{V: 1, ID: rootID, Project: project, Writer: writer, HLC: op.HLC{WallMs: wall}, Actor: act,
		Kind: op.KindProjectCreate, Payload: op.ProjectCreate("unit", "Unit", op.DefaultStatuses)})
	for i := 0; i < tickets; i++ {
		wall += 10
		tid, _ := op.NewID(op.PrefixOp, wall)
		add(&op.Op{V: 1, ID: tid, Project: project, Writer: writer, HLC: op.HLC{WallMs: wall}, Actor: act,
			Ticket: op.PrefixTicket + strings.TrimPrefix(tid, op.PrefixOp), Kind: op.KindTicketCreate,
			Payload: op.TicketCreate(fmt.Sprintf("ticket %d", i), "", "task", "none", nil, "todo", "unstarted")})
		wall += 10
		cid, _ := op.NewID(op.PrefixOp, wall)
		cmid, _ := op.NewID(op.PrefixComment, wall)
		add(&op.Op{V: 1, ID: cid, Project: project, Writer: writer, HLC: op.HLC{WallMs: wall}, Actor: act,
			Ticket: op.PrefixTicket + strings.TrimPrefix(tid, op.PrefixOp), Kind: op.KindComment, Payload: op.Comment(cmid, "note")})
	}
	return
}

func inputOf(project, writer string, ops []*op.Op) fold.Input {
	return fold.Input{Project: project, Refs: []fold.Ref{{Writer: writer, Ops: ops}}, Classes: map[string]string{writer: fold.ClassSelf}}
}

// NEG-4: the document is a pure function of one snapshot. A write after the snapshot cannot leak into a
// document built from it, and rebuilding at an older frontier reproduces the older digest exactly (this is
// what `bind` relies on).
func TestImportDocumentIsPureOfItsSnapshot(t *testing.T) {
	project, writer, ops := buildOps(t, 3)
	early := inputOf(project, writer, ops[:5])
	later := inputOf(project, writer, ops)
	f1 := ledger.FoldedFrontier(early)
	d1, err := ledger.BuildImport(early, nil, f1, "", false)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ledger.BuildImport(early, nil, f1, "", false)
	if string(d1.Body) != string(again.Body) {
		t.Fatalf("same snapshot, different bytes")
	}
	full, err := ledger.BuildImport(later, nil, ledger.FoldedFrontier(later), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if full.Digest == d1.Digest {
		t.Fatalf("a later snapshot has the same digest")
	}
	atPrefix, err := ledger.BuildImport(later, nil, f1, "", false)
	if err != nil || atPrefix.Digest != d1.Digest || string(atPrefix.Body) != string(d1.Body) {
		t.Fatalf("rebuilding at the older frontier did not reproduce the older document (%v)", err)
	}
	// The delta between the two names exactly the new ops.
	delta, err := ledger.BuildImport(later, f1, ledger.FoldedFrontier(later), d1.Digest, false)
	if err != nil || delta.Ops != len(ops)-5 {
		t.Fatalf("delta: %v ops %d want %d", err, delta.Ops, len(ops)-5)
	}
	// Not a prefix: a frontier that names an op the ledger lacks is refused.
	bad := append([]ledger.Frontier(nil), f1...)
	bad[0].LastOp = "op_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := ledger.BuildImport(later, nil, bad, "", false); err == nil {
		t.Fatalf("a frontier with the wrong last op was accepted")
	}
	// An unverified writer's ops change neither the digest nor the frontier.
	_, w2, ops2 := buildOps(t, 2)
	mixed := later
	mixed.Refs = append(append([]fold.Ref(nil), later.Refs...), fold.Ref{Writer: w2, Ops: ops2})
	mixed.Classes = map[string]string{writer: fold.ClassSelf, w2: fold.ClassUnverified}
	withStranger, err := ledger.BuildImport(mixed, nil, ledger.FoldedFrontier(mixed), "", false)
	if err != nil || withStranger.Digest != full.Digest {
		t.Fatalf("an unverified writer changed the digest (%v)", err)
	}
	if !strings.Contains(string(withStranger.Body), `"unverified_ops":`+fmt.Sprint(len(ops2))) {
		t.Fatalf("the unverified ops are not counted in excluded")
	}
}

func TestCompareClassifiesFrontiers(t *testing.T) {
	project, writer, ops := buildOps(t, 3)
	cur := inputOf(project, writer, ops)
	rec := ledger.FoldedFrontier(inputOf(project, writer, ops[:4]))
	if rel, n := ledger.Compare(cur, rec); rel != ledger.RelBehind || n != len(ops)-4 {
		t.Fatalf("behind: %s %d", rel, n)
	}
	if rel, _ := ledger.Compare(cur, ledger.FoldedFrontier(cur)); rel != ledger.RelEqual {
		t.Fatalf("equal: %s", rel)
	}
	longer := append([]ledger.Frontier(nil), rec...)
	longer[0].Ops = len(ops) + 5
	if rel, _ := ledger.Compare(cur, longer); rel != ledger.RelDiverged {
		t.Fatalf("a frontier ahead of the ledger must be diverged: %s", rel)
	}
	wrongLast := append([]ledger.Frontier(nil), rec...)
	wrongLast[0].LastOp = "op_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if rel, _ := ledger.Compare(cur, wrongLast); rel != ledger.RelDiverged {
		t.Fatalf("a frontier whose last op differs must be diverged: %s", rel)
	}
	other := append([]ledger.Frontier(nil), rec...)
	other[0].Writer = "w_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if rel, _ := ledger.Compare(cur, other); rel != ledger.RelDiverged {
		t.Fatalf("a frontier naming another writer must be diverged: %s", rel)
	}
	// A writer that loses folded status (unverified) drops out: diverged for what was bound.
	gone := cur
	gone.Classes = map[string]string{writer: fold.ClassUnverified}
	if rel, _ := ledger.Compare(gone, ledger.FoldedFrontier(cur)); rel != ledger.RelDiverged {
		t.Fatalf("a writer that lost trust must read as diverged: %s", rel)
	}
}

func TestURLValidation(t *testing.T) {
	good := []string{"https://example.org/x.git", "ssh://git@example.org/x.git", "git@example.org:x/y.git", "/abs/path/x.git", "file:///abs/x.git"}
	bad := []string{"", "-oProxyCommand=x", "ext::sh -c id", "fd::3", "transport::x", "ssh://-oProxy@host/x", "ssh://-host/x", "-o@host:x",
		"https://user:pw@host/x", "http://host/x", "git://host/x", "rel/path", "https://host/a b", "file://rel/path", "host:path\nx", "git@example.invalid:--upload-pack=x"}
	for _, u := range good {
		if err := store.ValidateURL(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := store.ValidateURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

// With 5000 ops, sync-state-sized work (snapshot + frontier + compare) stays far under the 3 s bound. It is a
// wall-clock check, so it only runs where asked for (dev2: HARNESS_LEDGER_PERF=1).
func TestSyncStatePerformance5000Ops(t *testing.T) {
	if os.Getenv("HARNESS_LEDGER_PERF") != "1" {
		t.Skip("wall-clock bound; set HARNESS_LEDGER_PERF=1")
	}
	project, writer, ops := buildOps(t, 2500) // 1 + 2*2500 = 5001 ops
	in := inputOf(project, writer, ops)
	started := time.Now()
	f := ledger.FoldedFrontier(in)
	rel, _ := ledger.Compare(in, f)
	doc, err := ledger.BuildImport(in, nil, f, "", false)
	if err != nil || rel != ledger.RelEqual || doc.Ops != len(ops) {
		t.Fatalf("%v %s %d", err, rel, doc.Ops)
	}
	if el := time.Since(started); el > 3*time.Second {
		t.Fatalf("5000-op export took %s (limit 3s)", el)
	}
}

func TestBindConcurrentExactlyOneWins(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "cc")
	w.newTicket(w.repo, nil, "alpha")
	_, doc := w.exportDoc(w.repo, nil)
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		i := i
		p := receiptFor(t, deepCopy(doc), func(r map[string]any) { r["import_id"] = fmt.Sprintf("import-%d", i) })
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = w.bind(w.repo, p).code }()
	}
	wg.Wait()
	wins := 0
	for _, c := range codes {
		if c == 0 {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("want exactly one winning bind, got %v", codes)
	}
	if st := w.syncState(w.repo, nil); st["state"] != "synced" {
		t.Fatalf("%v", st)
	}
}

func TestTrustRegistryIgnoresGitDirMarkers(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "tr")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", b.adoptToken(b.repo))
	ws := b.jsonOK(b.repo, nil, "writers")["writers"].([]any)
	wid := ws[0].(map[string]any)["id"].(string)
	show := b.jsonOK(b.repo, nil, "writers", "--show", wid)
	proj := b.jsonOK(b.repo, nil, "writers")["project"].(string)
	// Plant a registry inside the git dir (it travels with a copied .git): it must change nothing.
	marker, _ := json.Marshal(map[string]any{"v": 1, "ledger_project": proj,
		"trusted": map[string]any{wid: map[string]any{"ops": int(show["ops"].(float64)), "digest": show["review_digest"]}}, "blocked": []string{}})
	for _, dir := range []string{filepath.Join(b.commonDir(), "goodqa"), b.commonDir()} {
		os.WriteFile(filepath.Join(dir, "trust.json"), marker, 0o600)
	}
	if r := b.run(b.repo, nil, "tickets", "list"); r.code == 0 {
		t.Fatalf("a trust marker in the git dir folded a writer: %s", r.stdout)
	}
	if got := b.jsonOK(b.repo, nil, "writers")["writers"].([]any)[0].(map[string]any)["class"]; got != "unverified" {
		t.Fatalf("class %v", got)
	}
	// The same registry in HOME state is honoured (and a symlinked one is not).
	home := filepath.Join(b.home, ".agent-harness", "ledgers", proj, "trust.json")
	target := filepath.Join(b.home, "elsewhere.json")
	os.WriteFile(target, marker, 0o600)
	os.Symlink(target, home)
	if r := b.run(b.repo, nil, "tickets", "list"); r.code == 0 {
		t.Fatalf("a symlinked HOME registry was followed")
	}
	os.Remove(home)
	os.WriteFile(home, marker, 0o600)
	if r := b.run(b.repo, nil, "tickets", "list"); r.code != 0 {
		t.Fatalf("a valid HOME registry was not honoured: %s", r.stderr)
	}
}

func TestPhase0aCommandsStillRefused(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "refuse")
	for _, c := range []string{"fetch", "push", "sync", "import"} {
		r := w.run(w.repo, nil, "tickets", c)
		if r.code != 2 || !strings.Contains(r.stderr, "not part of Phase 0a") {
			t.Errorf("%s: %d %s", c, r.code, r.stderr)
		}
	}
}

// sync-state reads remotes from a hostile repository without running anything its config names.
func TestSyncStateDoesNotRunRepositoryConfig(t *testing.T) {
	w := newWorld(t)
	marker := filepath.Join(w.home, "ran")
	hook := filepath.Join(w.home, "evil.sh")
	os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	w.git(w.repo, "config", "core.fsmonitor", hook)
	w.git(w.repo, "config", "core.sshCommand", hook)
	w.git(w.repo, "config", "core.hooksPath", w.home)
	w.git(w.repo, "remote", "add", "origin", "git@github.com:x/y.git")
	w.ok(w.repo, nil, "init", "--slug", "hostile")
	w.newTicket(w.repo, nil, "alpha")
	w.syncState(w.repo, nil)
	w.ok(w.repo, nil, "export", "--format", "goodqa-import")
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("repository config was executed")
	}
}
