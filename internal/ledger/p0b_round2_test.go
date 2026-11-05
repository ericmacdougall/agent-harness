package ledger_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/store"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// writerID makes the i-th syntactically valid writer id; low i sorts first.
func writerID(i int) string {
	id := []byte("00000000000000000000000000")
	id[24], id[25] = crockford[(i/32)%32], crockford[i%32]
	return "w_" + string(id)
}

// remoteOps appends one pack of ops to a writer ref in a bare remote.
func remoteOps(t *testing.T, remote, project, writer string, ops []*op.Op) {
	t.Helper()
	g := &store.Git{GitDir: remote}
	commit, err := g.WritePack("", ops, "lease-"+writer)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(store.RefName(project, writer), commit, ""); err != nil {
		t.Fatal(err)
	}
}

// junkWriter makes a valid writer ref holding one noop op.
func junkWriter(t *testing.T, remote, project, writer string, wall int64) {
	t.Helper()
	id, _ := op.NewID(op.PrefixOp, wall)
	o := &op.Op{V: 1, ID: id, Project: project, Writer: writer, HLC: op.HLC{WallMs: wall}, Actor: op.Actor{Kind: "human", Label: "x"}, Kind: op.KindNoop, Payload: op.Obj{}}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := op.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	remoteOps(t, remote, project, writer, []*op.Op{p})
}

func (p *pair) projectOf(t *testing.T) string {
	t.Helper()
	ref := strings.Fields(remoteRefs(p.a, p.remote))[0]
	return strings.Split(ref, "/")[3]
}

// F3: a collaborator who plants many writers cannot make the real one unreviewable or fill the unverified budget.
func TestFetchCapsUnverifiedWritersAndKeepsTheRootHolder(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "cap2")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	proj := p.projectOf(t)
	for i := 1; i <= 70; i++ {
		junkWriter(t, p.remote, proj, writerID(i), 1_800_000_000_000+int64(i))
	}
	out := b.jsonOK(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", b.adoptToken(b.repo))
	acc := len(out["accepted"].([]any))
	if acc > 64 || acc < 2 {
		t.Fatalf("accepted %d writers (cap 64, the root holder must be among them)", acc)
	}
	if len(out["rejected"].([]any)) < 7 {
		t.Fatalf("the surplus was not reported as rejected: %v", out["rejected"])
	}
	realW := ""
	for _, w := range a.jsonOK(a.repo, nil, "writers")["writers"].([]any) {
		if w.(map[string]any)["class"] == "self" {
			realW = w.(map[string]any)["id"].(string)
		}
	}
	found := false
	for _, w := range out["accepted"].([]any) {
		found = found || w == realW
	}
	if !found {
		t.Fatalf("the writer holding the project root was not landed")
	}
	// The real writer stays reviewable, and blocking junk keeps the budget free.
	if r := b.run(b.repo, nil, "tickets", "writers", "--show", realW); r.code != 0 || !strings.Contains(r.stdout, "review digest") {
		t.Fatalf("real writer not reviewable: %d %s", r.code, r.stderr)
	}
}

// F11: the slug is never taken from a lone, unverified root op.
func TestAdoptRefusesDisagreeingRootsAndSlugMismatch(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "real")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	proj := p.projectOf(t)
	// A forged root: same id as the real root, another slug, another writer.
	_, doc := a.exportDoc(a.repo, nil)
	var realRoot *op.Op
	for _, line := range doc["ops"].([]any) {
		if o, _ := op.Parse([]byte(line.(string))); o != nil && o.Kind == op.KindProjectCreate {
			realRoot = o
		}
	}
	forgedRoot := *realRoot
	forgedRoot.Writer = writerID(1)
	forgedRoot.Payload = op.ProjectCreate("evil", "Evil", op.DefaultStatuses)
	forged := &forgedRoot
	raw, err := forged.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := op.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	remoteOps(t, p.remote, proj, writerID(1), []*op.Op{fp})
	tok := b.adoptToken(b.repo)
	r := b.run(b.repo, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok)
	if r.code == 0 || !strings.Contains(r.stderr, "disagree") {
		t.Fatalf("adopt accepted disagreeing roots: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(b.commonDir(), "goodqa", "projects.json")); err == nil {
		t.Fatalf("a ledger was created from disagreeing roots")
	}
}

func TestAdoptSlugAssertionAndSlugTaken(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "joint2")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	tok := b.adoptToken(b.repo)
	if r := b.run(b.repo, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok, "--slug", "other"); r.code == 0 {
		t.Fatalf("a --slug that differs from the remote's root slug was accepted")
	}
	// A slug already used on this machine is refused.
	other := filepath.Join(filepath.Dir(b.home), "other-repo")
	os.MkdirAll(other, 0o755)
	b.git(other, "init", "-q", "-b", "main")
	b.ok(other, nil, "init", "--slug", "joint2")
	if r := b.run(b.repo, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok); r.code == 0 || !strings.Contains(r.stderr, "already used") {
		t.Fatalf("slug already used on the machine: %d %s", r.code, r.stderr)
	}
	// With the matching assertion and a free slug it works.
	c := newWorld(t)
	c.git(c.repo, "remote", "add", "origin", p.remote)
	c.ok(c.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", c.adoptToken(c.repo), "--slug", "joint2")
}

// F12a: a remote that streams a huge ref list is stopped by an output cap, not read whole.
func TestLsRemoteOutputIsCapped(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "lsr")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	proj := p.projectOf(t)
	empty := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "commit-tree", "-m", "x", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"))
	var batch strings.Builder
	for i := 0; i < 6000; i++ {
		batch.WriteString(fmt.Sprintf("create refs/goodqa/v1/%s/log/w_%026d %s\n", proj, i, empty))
	}
	cmd := execCommand("git", "--git-dir="+p.remote, "update-ref", "--stdin")
	cmd.Env = a.env
	cmd.Stdin = strings.NewReader(batch.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("update-ref: %v %s", err, out)
	}
	started := time.Now()
	r := a.run(a.repo, nil, "tickets", "travel", "fetch")
	if r.code == 0 || !strings.Contains(r.stderr, "output cap") {
		t.Fatalf("a 6000-ref remote was not refused: %d %s", r.code, r.stderr)
	}
	if time.Since(started) > 60*time.Second {
		t.Fatalf("too slow: %s", time.Since(started))
	}
}

// F12c: a fetch or push that was already running cannot revert a newer consent.
func TestUpdateTravelKeepsNewerConsent(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "upd")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	other := filepath.Join(filepath.Dir(a.home), "second.git")
	a.git(a.home, "init", "--bare", "-q", other)
	a.git(a.repo, "remote", "add", "second", other)
	t.Setenv("HOME", a.home)
	t.Setenv("HARNESS_LEDGER_FAKE_MACHINE_ID", "machine-0")
	l, err := ledger.Open(ledger.Location{Cwd: a.repo})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stale := l.ReadTravel() // what a long-running push read at its start
	if stale == nil || stale.Remote != "origin" {
		t.Fatalf("setup: %+v", stale)
	}
	a.ok(a.repo, nil, "travel", "enable", "--remote", "second", "--yes-share", tokenFor(t, a, "second"))
	if err := l.UpdateTravel(func(c *ledger.TravelConfig) { c.PushedMs = 42 }); err == nil {
		// the update applies to whatever consent is current, not to the stale struct
	}
	now := l.ReadTravel()
	if now.Remote != "second" || now.PushedMs != 42 {
		t.Fatalf("a stale write reverted the consent: %+v", now)
	}
}

func tokenFor(t *testing.T, w *world, remote string) string {
	t.Helper()
	r := w.run(w.repo, nil, "tickets", "travel", "enable", "--remote", remote)
	m := tokenRe.FindStringSubmatch(r.stderr + r.stdout)
	if m == nil {
		t.Fatalf("no token: %s", r.stderr)
	}
	return m[1]
}

// F12e: a FIFO (or other non-regular file) as a receipt is refused instead of blocking.
func TestBindRefusesNonRegularReceipt(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "fifo")
	w.newTicket(w.repo, nil, "alpha")
	fifo := filepath.Join(w.home, "receipt.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no mkfifo")
	}
	done := make(chan result, 1)
	go func() { done <- w.bind(w.repo, fifo) }()
	select {
	case r := <-done:
		if r.code == 0 {
			t.Fatalf("a FIFO receipt was accepted")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("bind blocked on a FIFO")
	}
}

// A trusted writer whose reviewed prefix no longer matches (registry tampered or history replaced) is not trusted.
func TestTamperedTrustDigestDropsTrust(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "tamp")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", b.adoptToken(b.repo))
	ws := b.jsonOK(b.repo, nil, "writers")
	wid := ws["writers"].([]any)[0].(map[string]any)["id"].(string)
	dg := b.jsonOK(b.repo, nil, "writers", "--show", wid)["review_digest"].(string)
	b.ok(b.repo, nil, "trust-writer", wid, "--reviewed", dg)
	if r := b.run(b.repo, nil, "tickets", "list"); r.code != 0 {
		t.Fatalf("trusted writer not folded: %s", r.stderr)
	}
	proj := ws["project"].(string)
	path := filepath.Join(b.home, ".agent-harness", "ledgers", proj, "trust.json")
	raw, _ := os.ReadFile(path)
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["trusted"].(map[string]any)[wid].(map[string]any)["digest"] = strings.Repeat("a", 64)
	bad, _ := json.Marshal(doc)
	os.WriteFile(path, bad, 0o600)
	if r := b.run(b.repo, nil, "tickets", "list"); r.code == 0 {
		t.Fatalf("a writer whose reviewed digest no longer matches was still folded")
	}
}

func TestStaleFetchDirectoriesAreRemoved(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "stale")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	proj := p.projectOf(t)
	dir := filepath.Join(a.home, ".agent-harness", "ledgers", proj)
	old, fresh := filepath.Join(dir, ".fetch-old"), filepath.Join(dir, ".fetch-fresh")
	os.MkdirAll(old, 0o700)
	os.MkdirAll(fresh, 0o700)
	os.Chtimes(old, time.Now().Add(-3*time.Hour), time.Now().Add(-3*time.Hour))
	a.ok(a.repo, nil, "travel", "fetch")
	if _, err := os.Stat(old); err == nil {
		t.Fatalf("a stale disposable directory survived a fetch")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("a fresh directory (maybe another fetch's) was removed")
	}
}

// Hostile fetches: a colliding op id, this machine's own writer id, and a far-future clock.
func TestHostileFetchCases(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "host")
	h := a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	proj := p.projectOf(t)
	_, doc := a.exportDoc(a.repo, nil)
	ownWriter := doc["frontier"].([]any)[0].(map[string]any)["writer"].(string)
	before := a.jsonOK(a.repo, nil, "list")
	_, docBefore := a.exportDoc(a.repo, nil)

	// 1. same op id as an own op, different bytes, from another writer
	var victim *op.Op
	for _, line := range doc["ops"].([]any) {
		o, _ := op.Parse([]byte(line.(string)))
		if o.Kind == op.KindTicketCreate {
			victim = o
		}
	}
	evil := *victim
	evil.Writer = writerID(5)
	evil.Payload = op.TicketCreate("HIJACKED", "", "task", "none", nil, "todo", "unstarted")
	raw, _ := evil.Encode()
	ep, err := op.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	remoteOps(t, p.remote, proj, writerID(5), []*op.Op{ep})
	// 2. an op dated a year ahead from another writer
	junkWriter(t, p.remote, proj, writerID(6), time.Now().Add(365*24*time.Hour).UnixMilli())
	// 3. own writer id on the remote with other content
	empty := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "commit-tree", "-m", "x", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"))
	a.git(a.home, "--git-dir="+p.remote, "update-ref", store.RefName(proj, ownWriter), empty)
	ownTip := strings.TrimSpace(a.git(a.repo, "rev-parse", store.RefName(proj, ownWriter)))

	out := a.jsonOK(a.repo, nil, "travel", "fetch")
	if !strings.Contains(fmt.Sprint(out["skipped"]), ownWriter) {
		t.Fatalf("the own writer id on the remote was not skipped: %v", out)
	}
	if got := strings.TrimSpace(a.git(a.repo, "rev-parse", store.RefName(proj, ownWriter))); got != ownTip {
		t.Fatalf("an own ref was overwritten by the remote")
	}
	if got := a.jsonOK(a.repo, nil, "list"); fmt.Sprint(got["tickets"]) != fmt.Sprint(before["tickets"]) {
		t.Fatalf("hostile writers changed the view: %v", got["tickets"])
	}
	_, docAfter := a.exportDoc(a.repo, nil)
	if docAfter["digest"] != docBefore["digest"] {
		t.Fatalf("hostile writers changed the digest")
	}
	// the colliding writer is rejected, never folded
	for _, w := range a.jsonOK(a.repo, nil, "writers")["writers"].([]any) {
		m := w.(map[string]any)
		if m["id"] == writerID(5) && m["rejected"] == "" {
			t.Errorf("the writer that reused an op id is not rejected")
		}
	}
	// A later own write is not dragged forward by the far-future clock.
	a.ok(a.repo, nil, "comment", h, "--body", "after the hostile fetch")
	_, d2 := a.exportDoc(a.repo, nil)
	last := d2["tickets"].([]any)[0].(map[string]any)["history"].([]any)
	wall := last[len(last)-1].(map[string]any)["wall_ms"].(float64)
	if int64(wall) > time.Now().Add(10*time.Minute).UnixMilli() {
		t.Fatalf("an own op was stamped %v, dragged forward by a far-future writer", int64(wall))
	}
}

// F11 (main's rule): the slug comes from the user or local config; with neither, adopt refuses even
// though the remote's root names one, and a given slug must match that root.
func TestAdoptNeedsTheSlugFromTheUser(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "userslug")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	tok := (&world{t: t, env: b.env, home: b.home, repo: b.repo}).adoptTokenNoSlug(b.repo)
	r := b.run(b.repo, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok)
	if r.code == 0 || !strings.Contains(r.stderr, "--slug") {
		t.Fatalf("adopt without a user-given slug: %d %s", r.code, r.stderr)
	}
	if r := b.run(b.repo, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok, "--slug", "wrong"); r.code == 0 {
		t.Fatalf("a mismatching slug adopted")
	}
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok, "--slug", "userslug")
}

func (w *world) adoptTokenNoSlug(dir string) string {
	r := w.run(dir, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin")
	m := tokenRe.FindStringSubmatch(r.stderr + r.stdout)
	if m == nil {
		w.t.Fatalf("no token: %s %s", r.stdout, r.stderr)
	}
	return m[1]
}

// Signed receipts: once the user pins GoodQA's ed25519 key, only a receipt it signed binds, and sync-state says so.
func TestSignedReceiptsAndPinnedKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1) // a fixed, public, test-only key
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(append([]byte{9}, seed[1:]...))
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "sig")
	a := w.newTicket(w.repo, nil, "alpha")
	keyFile := filepath.Join(w.home, "goodqa.pub")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(pub)+"\n"), 0o600)

	// sign builds the receipt GoodQA would return: signed envelope when key != nil, bare receipt otherwise.
	sign := func(doc map[string]any, key ed25519.PrivateKey, mutate func(*ledger.ReceiptDoc)) string {
		p := receiptFor(t, doc, nil)
		raw, _ := os.ReadFile(p)
		var rd ledger.ReceiptDoc
		json.Unmarshal(raw, &rd)
		if mutate != nil {
			mutate(&rd)
		}
		out := any(rd)
		if key != nil {
			env, err := rd.Sign(key)
			if err != nil {
				t.Fatal(err)
			}
			out = env
		}
		b, _ := json.Marshal(out)
		os.WriteFile(p, b, 0o600)
		return p
	}
	bindKey := func(path string, extra ...string) result {
		return w.run(w.repo, nil, append([]string{"tickets", "bind", "--project", goodqaUUID, "--receipt", path, "--json"}, extra...)...)
	}
	_, doc := w.exportDoc(w.repo, nil)

	// Unpinned and unsigned: advisory, and sync-state says it is not authenticated.
	// First check refusals with the key given: unsigned, wrong key, tampered content.
	if r := bindKey(sign(doc, nil, nil), "--goodqa-key", keyFile); r.code == 0 {
		t.Fatalf("an unsigned receipt bound with a key given")
	}
	// A wrong key id (right signature, different pinned key) is refused too.
	if r := bindKey(sign(doc, other, nil), "--goodqa-key", keyFile); r.code == 0 {
		t.Fatalf("a receipt signed by another key bound")
	}
	// A PEM SPKI key file works as well as hex.
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	pemFile := filepath.Join(w.home, "goodqa.pem")
	os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o600)
	if _, err := ledger.ParseKey(mustRead(t, pemFile)); err != nil {
		t.Fatalf("PEM key: %v", err)
	}
	if r := bindKey(sign(doc, other, nil), "--goodqa-key", keyFile); r.code == 0 {
		t.Fatalf("a receipt signed by another key bound")
	}
	if r := bindKey(sign(doc, priv, func(rd *ledger.ReceiptDoc) { rd.ImportID = "tampered" }), "--goodqa-key", keyFile); r.code != 0 {
		t.Fatalf("a receipt re-signed after edits must verify: %s", r.stderr) // sign() signs the final content
	}
	if st := w.syncState(w.repo, nil); st["state"] != "synced" || st["authenticated"] != true {
		t.Fatalf("after a signed bind: %v", st)
	}
	// Tampering after signing is caught.
	w.ok(w.repo, nil, "comment", a, "--body", "later")
	_, d2 := w.exportDoc(w.repo, nil, "--since-bound")
	p := sign(d2, priv, nil)
	raw, _ := os.ReadFile(p)
	var env ledger.SignedReceipt
	json.Unmarshal(raw, &env)
	env.Receipt.ImportedMs = 99999
	b, _ := json.Marshal(env)
	os.WriteFile(p, b, 0o600)
	if r := bindKey(p); r.code == 0 {
		t.Fatalf("a receipt edited after signing bound")
	}
	// The pin sticks: an unsigned delta is refused even without --goodqa-key, and a different key is refused.
	if r := bindKey(sign(d2, nil, nil)); r.code == 0 {
		t.Fatalf("an unsigned receipt bound after a key was pinned")
	}
	otherPub := filepath.Join(w.home, "other.pub")
	os.WriteFile(otherPub, []byte(hex.EncodeToString(other.Public().(ed25519.PublicKey))), 0o600)
	if r := bindKey(sign(d2, other, nil), "--goodqa-key", otherPub); r.code == 0 {
		t.Fatalf("the pinned key was replaced")
	}
	if r := bindKey(sign(d2, priv, nil)); r.code != 0 {
		t.Fatalf("a signed delta with the pinned key: %s", r.stderr)
	}
	// An unpinned ledger stays advisory.
	w2 := newWorld(t)
	w2.ok(w2.repo, nil, "init", "--slug", "adv")
	w2.newTicket(w2.repo, nil, "x")
	_, dd := w2.exportDoc(w2.repo, nil)
	if r := w2.bind(w2.repo, receiptFor(t, dd, nil)); r.code != 0 {
		t.Fatalf("%s", r.stderr)
	}
	if st := w2.syncState(w2.repo, nil); st["authenticated"] != false {
		t.Fatalf("an advisory binding claims to be authenticated: %v", st)
	}
	if _, err := ledger.ParseKey([]byte("nothex")); err == nil {
		t.Fatalf("a malformed key parsed")
	}
}

// Private remotes: the user's own credential helpers are used only on opt-in, only whole-name or absolute-path
// helpers, and nothing else from the global git config is read. No Keychain is touched here: the helpers are
// only listed, never run.
func TestUserCredentialHelpersAreVettedAndOptIn(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[credential]\n\thelper = osxkeychain\n\thelper = !sh -c 'echo pwned'\n\thelper = store --file /tmp/x\n\thelper = /usr/local/bin/git-credential-foo\n[url \"https://evil/\"]\n\tinsteadOf = https://github.com/\n"), 0o600)
	t.Setenv("HOME", home)
	got := ledger.UserCredentialHelpers()
	if strings.Join(got, "|") != "osxkeychain|/usr/local/bin/git-credential-foo" {
		t.Fatalf("helpers: %v", got)
	}
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "cred")
	a.newTicket(a.repo, nil, "alpha")
	a.ok(a.repo, nil, "travel", "enable", "--remote", "origin", "--yes-share", a.token(a.repo))
	if st := a.jsonOK(a.repo, nil, "travel", "status"); st["credentials"] != false {
		t.Fatalf("credentials are on by default: %v", st)
	}
	a.ok(a.repo, nil, "travel", "enable", "--remote", "origin", "--yes-share", a.token(a.repo), "--use-git-credentials")
	if st := a.jsonOK(a.repo, nil, "travel", "status"); st["credentials"] != true {
		t.Fatalf("opt-in not recorded: %v", st)
	}
	// A push over a file remote still works with helpers enabled (they are only consulted for https auth).
	a.ok(a.repo, nil, "travel", "push")
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The canonical signed bytes are what a Python implementation produces with sort_keys, compact separators and
// ensure_ascii; this pins them so GoodQA's signer and the harness cannot drift.
func TestReceiptCanonicalBytesArePinned(t *testing.T) {
	red := false
	r := ledger.ReceiptDoc{Format: "goodqa-ledger-receipt/v1", GoodQAProject: goodqaUUID, ImportID: "imp-1", LedgerProject: "proj_X", ExportDigest: strings.Repeat("a", 64),
		BaseDigest: "", Redacted: &red, Frontier: []ledger.ReceiptFrontier{{Writer: "w_1", Ops: 2, WallMs: 3, Ctr: 0, LastOp: "op_9"}},
		Tickets: []ledger.ReceiptTicket{{Handle: "d974ebba", Number: 1}}, ImportedMs: 5}
	got, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"base_digest":"","export_digest":"` + strings.Repeat("a", 64) + `","format":"goodqa-ledger-receipt/v1","frontier":[{"ctr":0,"last_op":"op_9","ops":2,"wall_ms":3,"writer":"w_1"}],"goodqa_project":"` + goodqaUUID + `","import_id":"imp-1","imported_at_ms":5,"ledger_project":"proj_X","redacted":false,"tickets":[{"handle":"d974ebba","number":1}]}`
	if string(got) != want {
		t.Fatalf("canonical bytes changed:\n%s\n%s", got, want)
	}
}

// A repository's own config cannot supply the adopt slug (a copied .git could plant a matching one).
func TestAdoptIgnoresRepositoryLocalSlugConfig(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "localcfg")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	tok := b.adoptTokenNoSlug(b.repo)
	b.git(b.repo, "config", "--local", "harness.ledgerslug", "localcfg")
	if r := b.run(b.repo, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok); r.code == 0 {
		t.Fatalf("a repository-local slug config was honoured")
	}
	b.git(b.repo, "config", "--global", "harness.ledgerslug", "localcfg")
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok)
}

// A lost or rotated key is not a dead end: unbind (typed slug) forgets the binding and the pinned key.
func TestUnbindReleasesAPinnedKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "rot")
	w.newTicket(w.repo, nil, "alpha")
	key := filepath.Join(w.home, "k.pub")
	os.WriteFile(key, []byte(hex.EncodeToString(priv.Public().(ed25519.PublicKey))), 0o600)
	_, doc := w.exportDoc(w.repo, nil)
	bindSigned := func(d map[string]any, k ed25519.PrivateKey, keyFile string) result {
		p := receiptFor(t, d, nil)
		raw, _ := os.ReadFile(p)
		var rd ledger.ReceiptDoc
		json.Unmarshal(raw, &rd)
		env, _ := rd.Sign(k)
		b, _ := json.Marshal(env)
		os.WriteFile(p, b, 0o600)
		return w.run(w.repo, nil, "tickets", "bind", "--project", goodqaUUID, "--receipt", p, "--goodqa-key", keyFile, "--json")
	}
	if r := bindSigned(doc, priv, key); r.code != 0 {
		t.Fatalf("%s", r.stderr)
	}
	if r := w.run(w.repo, nil, "tickets", "unbind"); r.code == 0 {
		t.Fatalf("unbind ran without the typed slug")
	}
	if r := w.run(w.repo, nil, "tickets", "unbind", "--confirm", "wrong"); r.code == 0 {
		t.Fatalf("unbind accepted the wrong slug")
	}
	w.ok(w.repo, nil, "unbind", "--confirm", "rot")
	if st := w.syncState(w.repo, nil); st["state"] != "local-only" || st["authenticated"] != false {
		t.Fatalf("after unbind: %v", st)
	}
	// A new key can now be pinned with a fresh full import.
	rot := ed25519.NewKeyFromSeed(append([]byte{1}, seed[1:]...))
	key2 := filepath.Join(w.home, "k2.pub")
	os.WriteFile(key2, []byte(hex.EncodeToString(rot.Public().(ed25519.PublicKey))), 0o600)
	if r := bindSigned(doc, rot, key2); r.code != 0 {
		t.Fatalf("a rotated key could not be pinned after unbind: %s", r.stderr)
	}
}
