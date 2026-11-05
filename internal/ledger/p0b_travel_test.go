package ledger_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Phase 0b: travel (push, fetch, adopt), the trust registry and the git behaviours around them.

var tokenRe = regexp.MustCompile(`--yes-share ([0-9a-f]{8})`)

// pair is two machines (two HOMEs, two repositories) sharing one bare remote.
type pair struct {
	a, b   *world
	remote string
}

func newPair(t *testing.T) *pair {
	t.Helper()
	a := newWorld(t)
	b := newWorld(t)
	for i, w := range []*world{a, b} {
		for j := range w.env {
			if strings.HasPrefix(w.env[j], "HARNESS_LEDGER_FAKE_MACHINE_ID=") {
				w.env[j] = fmt.Sprintf("HARNESS_LEDGER_FAKE_MACHINE_ID=machine-%d", i)
			}
		}
	}
	remote := filepath.Join(filepath.Dir(a.home), "remote.git")
	a.git(a.home, "init", "--bare", "-q", remote)
	a.git(a.repo, "remote", "add", "origin", remote)
	b.git(b.repo, "remote", "add", "origin", remote)
	return &pair{a: a, b: b, remote: remote}
}

func (w *world) token(dir string) string {
	w.t.Helper()
	r := w.run(dir, nil, "tickets", "travel", "enable", "--remote", "origin")
	if r.code == 0 {
		w.t.Fatalf("bare enable must refuse")
	}
	m := tokenRe.FindStringSubmatch(r.stderr + r.stdout)
	if m == nil {
		w.t.Fatalf("no token in refusal: %s %s", r.stdout, r.stderr)
	}
	for _, want := range []string{"everyone who can read", "cannot be undone"} {
		if !strings.Contains(r.stderr+r.stdout, want) {
			w.t.Errorf("refusal lacks %q: %s", want, r.stderr)
		}
	}
	return m[1]
}

// adoptToken reads the consent token from a bare adopt attempt (no ledger exists yet to enable travel on).
func (w *world) adoptToken(dir string) string {
	w.t.Helper()
	r := w.run(dir, nil, "tickets", "travel", "fetch", "--adopt", "--remote", "origin")
	m := tokenRe.FindStringSubmatch(r.stderr + r.stdout)
	if r.code == 0 || m == nil {
		w.t.Fatalf("bare adopt must refuse with a token: %d %s %s", r.code, r.stdout, r.stderr)
	}
	return m[1]
}

func (w *world) enable(dir string) {
	w.t.Helper()
	w.ok(dir, nil, "travel", "enable", "--remote", "origin", "--yes-share", w.token(dir))
}

func remoteRefs(w *world, remote string) string {
	return strings.TrimSpace(w.git(w.home, "--git-dir="+remote, "for-each-ref", "--format=%(refname)", "refs/goodqa/"))
}

func TestTravelEnableNeedsExactToken(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "tv")
	a.newTicket(a.repo, nil, "alpha")
	tok := a.token(a.repo)
	if r := a.run(a.repo, nil, "tickets", "travel", "enable", "--remote", "origin", "--yes-share", "00000000"); r.code == 0 {
		t.Fatalf("a wrong token enabled travel")
	}
	if r := a.run(a.repo, nil, "tickets", "travel", "push"); r.code == 0 {
		t.Fatalf("push worked before consent")
	}
	a.ok(a.repo, nil, "travel", "enable", "--remote", "origin", "--yes-share", tok)
	// Ordinary git never carries the ledger.
	a.git(a.repo, "commit", "--allow-empty", "-q", "-m", "x")
	a.git(a.repo, "push", "-q", "origin", "main")
	if got := remoteRefs(a, p.remote); got != "" {
		t.Fatalf("ordinary push moved ledger refs: %q", got)
	}
	a.ok(a.repo, nil, "travel", "push")
	if got := remoteRefs(a, p.remote); !strings.Contains(got, "refs/goodqa/v1/proj_") {
		t.Fatalf("travel push left no ref: %q", got)
	}
	// The consent is bound to the URL: re-pointing the remote refuses.
	other := filepath.Join(filepath.Dir(a.home), "other.git")
	a.git(a.home, "init", "--bare", "-q", other)
	a.git(a.repo, "remote", "set-url", "origin", other)
	for _, sub := range []string{"push", "fetch"} {
		if r := a.run(a.repo, nil, "tickets", "travel", sub); r.code == 0 {
			t.Errorf("%s ran against a changed URL", sub)
		}
	}
	if got := remoteRefs(a, other); got != "" {
		t.Fatalf("data reached the re-pointed remote: %q", got)
	}
	// ordinary fetch never pulls ledger refs either
	a.git(a.repo, "remote", "set-url", "origin", p.remote)
	a.git(a.repo, "fetch", "-q", "origin")
	if out := a.git(a.repo, "config", "--get-all", "remote.origin.fetch"); strings.Contains(out, "goodqa") {
		t.Fatalf("remote.origin.fetch was edited: %s", out)
	}
	if out, _ := execCommand("git", "-C", a.repo, "config", "--get-all", "remote.origin.push").Output(); strings.Contains(string(out), "goodqa") {
		t.Fatalf("remote.origin.push was edited")
	}
}

func TestTravelRefusesHostileURLs(t *testing.T) {
	a := newWorld(t)
	a.ok(a.repo, nil, "init", "--slug", "hu")
	marker := filepath.Join(a.home, "pwned")
	urls := []string{
		"ext::sh -c touch " + marker,
		"fd::3",
		"-oProxyCommand=touch " + marker,
		"ssh://-oProxyCommand=touch/x",
		"-oProxy@host:path",
		"ssh://user:pw@host/x",
		"http://host/x",
		"git://host/x",
		"relative/path",
		"https://host/x y",
		"transport::thing",
	}
	for _, u := range urls {
		a.git(a.repo, "config", "remote.origin.url", u)
		// Present the exact token for this URL, so only URL validation can refuse it.
		sum := sha256.Sum256([]byte(u + "\n" + u))
		tok := hex.EncodeToString(sum[:])[:8]
		if r := a.run(a.repo, nil, "tickets", "travel", "enable", "--remote", "origin", "--yes-share", tok); r.code == 0 {
			t.Errorf("accepted hostile URL %q", u)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("a hostile URL executed a command")
	}
}

func TestTravelPushRefusesNonFastForwardAndLeavesRemote(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "nf")
	h := a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	ref := strings.Fields(remoteRefs(a, p.remote))[0]
	// Another history lands on the remote ref (a different commit not descending from ours).
	empty := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "commit-tree", "-m", "rewritten", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"))
	a.git(a.home, "--git-dir="+p.remote, "update-ref", ref, empty)
	a.ok(a.repo, nil, "comment", h, "--body", "more")
	if r := a.run(a.repo, nil, "tickets", "travel", "push"); r.code == 0 {
		t.Fatalf("push forced over a diverged remote ref")
	}
	if got := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "rev-parse", ref)); got != empty {
		t.Fatalf("remote ref was overwritten")
	}
}

func TestTravelFetchAdoptTrustAndHeldOps(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "joint")
	h := a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")

	// Machine B adopts the remote ledger; its writers are unverified, so nothing is visible yet.
	tokB := b.adoptToken(b.repo)
	out := b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tokB)
	if !strings.Contains(out, "unverified") {
		t.Fatalf("adopt output: %s", out)
	}
	if r := b.run(b.repo, nil, "tickets", "list"); r.code == 0 {
		t.Fatalf("list worked before any writer was trusted: %s", r.stdout)
	}
	ws := b.jsonOK(b.repo, nil, "writers")["writers"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["class"] != "unverified" {
		t.Fatalf("writers: %v", ws)
	}
	wid := ws[0].(map[string]any)["id"].(string)
	show := b.jsonOK(b.repo, nil, "writers", "--show", wid)
	digest := show["review_digest"].(string)
	if len(digest) != 64 {
		t.Fatalf("no review digest: %v", show)
	}
	// A guessed or stale digest is refused; the right one trusts the reviewed ops.
	if r := b.run(b.repo, nil, "tickets", "trust-writer", wid, "--reviewed", strings.Repeat("0", 64)); r.code == 0 {
		t.Fatalf("trusted with a wrong digest")
	}
	b.ok(b.repo, nil, "trust-writer", wid, "--reviewed", digest)
	if got := titles(b.jsonOK(b.repo, nil, "list")); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("after trust: %v", got)
	}

	// The trusted writer appends; B fetches. The new ops are held back until reviewed again.
	a.ok(a.repo, nil, "comment", h, "--body", "later news")
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch")
	show2 := b.jsonOK(b.repo, nil, "show", h)["ticket"].(map[string]any)
	if n := len(show2["comments"].([]any)); n != 0 {
		t.Fatalf("a held-back op was folded: %d comments", n)
	}
	_, doc := b.exportDoc(b.repo, nil)
	if doc["excluded"].(map[string]any)["held_ops"].(float64) != 1 {
		t.Fatalf("excluded: %v", doc["excluded"])
	}
	d2 := b.jsonOK(b.repo, nil, "writers", "--show", wid)["review_digest"].(string)
	if d2 == digest {
		t.Fatalf("the digest did not change with the new op")
	}
	b.ok(b.repo, nil, "trust-writer", wid, "--reviewed", d2)
	if n := len(b.jsonOK(b.repo, nil, "show", h)["ticket"].(map[string]any)["comments"].([]any)); n != 1 {
		t.Fatalf("re-reviewed op not folded: %d", n)
	}

	// B writes its own ticket and pushes; A fetches B as unverified and its list is unchanged.
	b.newTicket(b.repo, nil, "from b")
	b.ok(b.repo, nil, "travel", "push")
	a.ok(a.repo, nil, "travel", "fetch")
	if got := titles(a.jsonOK(a.repo, nil, "list")); len(got) != 1 {
		t.Fatalf("an unverified writer changed A's list: %v", got)
	}
	_, ad := a.exportDoc(a.repo, nil)
	if ad["excluded"].(map[string]any)["unverified_ops"].(float64) < 1 {
		t.Fatalf("A does not count B's unverified ops: %v", ad["excluded"])
	}
	// Planting an unverified writer does not change the digest of A's folded state.
	if st := a.syncState(a.repo, nil); st["state"] != "local-only" {
		t.Fatalf("a: %v", st)
	}
	// block-writer on A's own writer is refused.
	own := ""
	for _, w := range a.jsonOK(a.repo, nil, "writers")["writers"].([]any) {
		if w.(map[string]any)["class"] == "self" {
			own = w.(map[string]any)["id"].(string)
		}
	}
	if r := a.run(a.repo, nil, "tickets", "block-writer", own); r.code == 0 {
		t.Fatalf("blocked own writer")
	}
}

func TestTravelFetchRejectsRewrittenHistoryAndLeavesNoStaging(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "rw")
	h := a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	first := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "for-each-ref", "--format=%(refname) %(objectname)", "refs/goodqa/"))
	f := strings.Fields(first)
	ref, tip1 := f[0], f[1]
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", b.adoptToken(b.repo))
	a.ok(a.repo, nil, "comment", h, "--body", "second")
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch")
	// Rewind the remote ref to the first tip: B already holds the second, so this is a rewrite.
	a.git(a.home, "--git-dir="+p.remote, "update-ref", ref, tip1)
	out := b.jsonOK(b.repo, nil, "travel", "fetch")
	if len(out["rejected"].([]any)) != 1 {
		t.Fatalf("a rewound ref was not rejected: %v", out)
	}
	// B's ref still holds the later history.
	if got := strings.Fields(b.git(b.repo, "for-each-ref", "--format=%(objectname)", ref)); len(got) != 1 || got[0] == tip1 {
		t.Fatalf("B's ref moved back: %v", got)
	}
	ents, _ := os.ReadDir(filepath.Join(b.home, ".agent-harness", "ledgers"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".fetch-") {
			t.Errorf("disposable directory left behind: %s", e.Name())
		}
		sub, _ := os.ReadDir(filepath.Join(b.home, ".agent-harness", "ledgers", e.Name()))
		for _, s := range sub {
			if strings.HasPrefix(s.Name(), ".fetch-") {
				t.Errorf("disposable directory left behind: %s/%s", e.Name(), s.Name())
			}
		}
	}
}

func TestTravelFetchRefusesTooManyRefsAndOversizedFetch(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "cap")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	ref := strings.Fields(remoteRefs(a, p.remote))[0]
	proj := strings.Split(ref, "/")[3]
	empty := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "commit-tree", "-m", "x", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"))
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < 129; i++ {
		id := []byte("01ARZ3NDEKTSV4RRFFQ69G5FA0")
		id[24], id[25] = alphabet[i/32], alphabet[i%32]
		a.git(a.home, "--git-dir="+p.remote, "update-ref", "refs/goodqa/v1/"+proj+"/log/w_"+string(id), empty)
	}
	r := a.run(a.repo, nil, "tickets", "travel", "fetch")
	if r.code == 0 || !strings.Contains(r.stderr+r.stdout, "more than 128") {
		t.Fatalf("129 refs not refused: %d %s %s", r.code, r.stdout, r.stderr)
	}
	for _, e := range listFetchDirs(a.home) {
		t.Errorf("disposable directory left behind: %s", e)
	}
}

func listFetchDirs(home string) []string {
	var out []string
	filepath.Walk(filepath.Join(home, ".agent-harness", "ledgers"), func(p string, i os.FileInfo, err error) error {
		if err == nil && i.IsDir() && strings.HasPrefix(i.Name(), ".fetch-") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func TestTravelFetchAbortsPastSizeCap(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 70 MiB object")
	}
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "big")
	a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	ref := strings.Fields(remoteRefs(a, p.remote))[0]
	proj := strings.Split(ref, "/")[3]
	blob := filepath.Join(a.home, "big.bin")
	buf := make([]byte, 70<<20)
	rand.Read(buf)
	os.WriteFile(blob, buf, 0o600)
	oid := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "hash-object", "-w", blob))
	tree := strings.TrimSpace(a.treeWith(p.remote, oid))
	commit := strings.TrimSpace(a.git(a.home, "--git-dir="+p.remote, "commit-tree", "-m", "huge", tree))
	a.git(a.home, "--git-dir="+p.remote, "update-ref", "refs/goodqa/v1/"+proj+"/log/w_01ARZ3NDEKTSV4RRFFQ69G5FAV", commit)
	r := a.run(a.repo, nil, "tickets", "travel", "fetch")
	if r.code == 0 || !strings.Contains(r.stderr+r.stdout, "size cap") {
		t.Fatalf("a 70 MiB fetch was not aborted: %d %s %s", r.code, r.stdout, r.stderr)
	}
	for _, e := range listFetchDirs(a.home) {
		t.Errorf("disposable directory left behind: %s", e)
	}
}

// treeWith builds a tree holding one blob, inside the bare repository at remote.
func (w *world) treeWith(remote, oid string) string {
	w.t.Helper()
	cmd := execCommand("git", "--git-dir="+remote, "mktree")
	cmd.Env = w.env
	cmd.Stdin = strings.NewReader("100644 blob " + oid + "\tbig.bin\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.t.Fatalf("mktree: %v %s", err, out)
	}
	return string(out)
}

func TestTravelGitBehaviours(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "gb")
	a.newTicket(a.repo, nil, "alpha")
	a.git(a.repo, "commit", "--allow-empty", "-q", "-m", "one")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	a.git(a.repo, "push", "-q", "origin", "main")
	// A plain clone does not carry the ledger.
	clone := filepath.Join(filepath.Dir(a.home), "clone")
	a.git(a.home, "clone", "-q", p.remote, clone)
	if got := strings.TrimSpace(a.git(clone, "for-each-ref", "refs/goodqa/")); got != "" {
		t.Fatalf("a plain clone fetched the ledger: %q", got)
	}
	// Squash-style rewrites, branch deletion, gc and --mirror keep the refs.
	a.git(a.repo, "checkout", "-q", "-b", "feature")
	a.git(a.repo, "commit", "--allow-empty", "-q", "-m", "two")
	a.git(a.repo, "checkout", "-q", "main")
	a.git(a.repo, "merge", "--squash", "-q", "feature")
	a.git(a.repo, "branch", "-D", "-q", "feature")
	before := strings.TrimSpace(a.git(a.repo, "for-each-ref", "refs/goodqa/"))
	a.git(a.repo, "reflog", "expire", "--expire=now", "--all")
	a.git(a.repo, "gc", "-q", "--prune=now")
	if after := strings.TrimSpace(a.git(a.repo, "for-each-ref", "refs/goodqa/")); after != before || after == "" {
		t.Fatalf("refs changed or vanished: %q vs %q", before, after)
	}
	a.git(a.repo, "fsck", "--strict", "--no-dangling")
	mirror := filepath.Join(filepath.Dir(a.home), "mirror-copy.git")
	a.git(a.home, "init", "--bare", "-q", mirror)
	a.git(a.repo, "push", "-q", "--mirror", mirror)
	if got := strings.TrimSpace(a.git(a.home, "--git-dir="+mirror, "for-each-ref", "refs/goodqa/")); got == "" {
		t.Fatalf("--mirror lost the ledger refs")
	}
	// A remote that refuses the push gives a clear error and records nothing.
	lock := func(mode os.FileMode) {
		filepath.Walk(p.remote, func(path string, i os.FileInfo, err error) error {
			if err == nil && i.IsDir() {
				os.Chmod(path, mode)
			}
			return nil
		})
	}
	lock(0o500)
	t.Cleanup(func() { lock(0o700) })
	a.ok(a.repo, nil, "comment", a.newTicket(a.repo, nil, "beta"), "--body", "x")
	r := a.run(a.repo, nil, "tickets", "travel", "push")
	if r.code == 0 || !strings.Contains(r.stderr, "refused or could not") {
		t.Fatalf("unwritable remote: %d %s", r.code, r.stderr)
	}
	st := a.jsonOK(a.repo, nil, "travel", "status")
	if st["pushed_ms"].(float64) == 0 {
		t.Fatalf("the earlier successful push was forgotten")
	}
}

var execCommand = exec.Command

// The review digest covers exactly what `writers --show` prints: a long op is shown whole.
func TestWritersShowPrintsWholeOpsSoTheDigestIsReviewable(t *testing.T) {
	p := newPair(t)
	a, b := p.a, p.b
	a.ok(a.repo, nil, "init", "--slug", "rv")
	a.newTicket(a.repo, nil, "hello", "--body", strings.Repeat("A", 3000)+" HIDDEN-TAIL")
	a.enable(a.repo)
	a.ok(a.repo, nil, "travel", "push")
	b.ok(b.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", b.adoptToken(b.repo))
	wid := b.jsonOK(b.repo, nil, "writers")["writers"].([]any)[0].(map[string]any)["id"].(string)
	if out := b.ok(b.repo, nil, "writers", "--show", wid); !strings.Contains(out, "HIDDEN-TAIL") {
		t.Fatalf("the tail of a long op is not shown, yet the digest would cover it")
	}
}

func TestTrackedWinsEvenWhenTheLedgerIsUnusable(t *testing.T) {
	w := newWorld(t)
	policy := filepath.Join(w.home, "policy.json")
	os.WriteFile(policy, []byte(`{"ticket_systems":{"goodqa":{"adapter":"goodqa","repos":["github\\.com[:/]acme-corp/"]}}}`), 0o600)
	w.git(w.repo, "remote", "add", "origin", "git@github.com:acme-corp/x.git")
	w.ok(w.repo, nil, "init", "--slug", "tu")
	w.newTicket(w.repo, nil, "a")
	home2 := filepath.Join(filepath.Dir(w.home), "home2")
	os.MkdirAll(home2, 0o700)
	repo2 := filepath.Join(filepath.Dir(w.home), "repo2")
	execCopy(w.repo, repo2)
	w.env = gitEnv(home2)
	st := w.syncState(repo2, []string{"HARNESS_COMMIT_POLICY_FILE=" + policy})
	if st["state"] != "tracked" || st["ledger"] != "unusable" {
		t.Fatalf("%v", st)
	}
}
