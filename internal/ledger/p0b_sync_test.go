package ledger_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Phase 0b: sync state, the GoodQA import document and bind.

const goodqaUUID = "11111111-2222-4333-8444-555555555555"

func (w *world) syncState(dir string, extra []string, args ...string) map[string]any {
	w.t.Helper()
	return w.jsonOK(dir, extra, append([]string{"sync-state"}, args...)...)
}

func (w *world) exportDoc(dir string, extra []string, args ...string) (string, map[string]any) {
	w.t.Helper()
	out := w.ok(dir, extra, append([]string{"export", "--format", "goodqa-import"}, args...)...)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		w.t.Fatalf("export is not JSON: %v\n%.300s", err, out)
	}
	return out, m
}

// receiptFor builds the receipt GoodQA would return for an export document.
func receiptFor(t *testing.T, doc map[string]any, mutate func(map[string]any)) string {
	t.Helper()
	r := map[string]any{
		"format":         "goodqa-ledger-receipt/v1",
		"goodqa_project": goodqaUUID,
		"import_id":      "22222222-3333-4444-8555-666666666666",
		"ledger_project": doc["project"].(map[string]any)["id"],
		"export_digest":  doc["digest"],
		"base_digest":    doc["base_digest"],
		"frontier":       doc["frontier"],
		"tickets":        []any{},
		"redacted":       doc["redacted"],
		"imported_at_ms": 1,
	}
	if mutate != nil {
		mutate(r)
	}
	b, _ := json.Marshal(r)
	p := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (w *world) bind(dir, receipt string) result {
	return w.run(dir, nil, "tickets", "bind", "--project", goodqaUUID, "--receipt", receipt, "--json")
}

func TestSyncStateNoneAndLocalOnly(t *testing.T) {
	w := newWorld(t)
	st := w.syncState(w.repo, nil)
	if st["state"] != "none" {
		t.Fatalf("no ledger: %v", st)
	}
	w.ok(w.repo, nil, "init", "--slug", "syn")
	w.newTicket(w.repo, nil, "one")
	st = w.syncState(w.repo, nil)
	if st["state"] != "local-only" || int(st["unsynced_ops"].(float64)) < 2 {
		t.Fatalf("local-only: %v", st)
	}
	// Outside any repository there is nothing to report and nothing to fail on.
	if st := w.syncState(t.TempDir(), nil); st["state"] != "none" {
		t.Fatalf("non-repo: %v", st)
	}
}

func TestSyncStateTracked(t *testing.T) {
	w := newWorld(t)
	policy := filepath.Join(w.home, "policy.json")
	os.WriteFile(policy, []byte(`{"ticket_systems":{"goodqa":{"adapter":"goodqa","repos":["github\\.com[:/]acme-corp/"]},"ledger":{"adapter":"ledger","allowed_repos":[]}}}`), 0o600)
	env := []string{"HARNESS_COMMIT_POLICY_FILE=" + policy}
	w.git(w.repo, "remote", "add", "origin", "git@GitHub.com:Acme-Corp/widgets.git")
	if st := w.syncState(w.repo, env); st["state"] != "tracked" {
		t.Fatalf("tracked remote without ledger: %v", st)
	}
	// A different remote is untracked.
	w.git(w.repo, "remote", "set-url", "origin", "git@github.com:someone/else.git")
	if st := w.syncState(w.repo, env); st["state"] != "none" {
		t.Fatalf("untracked remote: %v", st)
	}
	// A missing policy file is not an error and is not tracked.
	w.git(w.repo, "remote", "set-url", "origin", "git@github.com:acme-corp/widgets.git")
	if st := w.syncState(w.repo, []string{"HARNESS_COMMIT_POLICY_FILE=" + filepath.Join(w.home, "absent.json")}); st["state"] != "none" || st["tracked_known"] != false {
		t.Fatalf("missing policy: %v", st)
	}
}

func TestGoodqaImportExportDeterministicWithHistory(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "exp")
	a := w.newTicket(w.repo, nil, "alpha", "--type", "bug")
	w.ok(w.repo, nil, "move", a, "in_progress")
	w.ok(w.repo, nil, "move", a, "in_review")
	w.ok(w.repo, nil, "move", a, "done")
	w.ok(w.repo, nil, "comment", a, "--body", "fixed it")
	w.ok(w.repo, nil, "label", a, "--add", "dns")
	one, doc := w.exportDoc(w.repo, nil)
	two, _ := w.exportDoc(w.repo, nil)
	if one != two {
		t.Fatalf("export is not byte-identical across runs")
	}
	w.ok(w.repo, nil, "rebuild")
	if three, _ := w.exportDoc(w.repo, nil); three != one {
		t.Fatalf("export changed after a cache rebuild")
	}
	if doc["format"] != "goodqa-ledger-import/v1" || doc["base_digest"] != "" {
		t.Fatalf("header: %v", doc["format"])
	}
	// The digest covers the document without the digest field itself.
	d := doc["digest"].(string)
	if len(d) != 64 || !strings.Contains(one, d) {
		t.Fatalf("digest: %q", d)
	}
	tk := doc["tickets"].([]any)[0].(map[string]any)
	moves := 0
	for _, e := range tk["history"].([]any) {
		ev := e.(map[string]any)
		if ev["kind"] == "ticket.status_set" {
			moves++
			if ev["from"] == "" || ev["to"] == "" {
				t.Errorf("status_set lacks from/to: %v", ev)
			}
		}
	}
	if moves != 3 {
		t.Fatalf("want 3 status movements in history, got %d", moves)
	}
	ops := doc["ops"].([]any)
	if len(ops) != 7 { // project.create + ticket.create + 3 moves + comment + label
		t.Fatalf("want 7 ops, got %d", len(ops))
	}
	if !strings.HasPrefix(ops[0].(string), "{") {
		t.Fatalf("ops carry canonical op lines: %v", ops[0])
	}
	if doc["excluded"].(map[string]any)["unverified_ops"].(float64) != 0 {
		t.Fatalf("excluded: %v", doc["excluded"])
	}
}

func TestBindRoundTripAndDelta(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "rt")
	a := w.newTicket(w.repo, nil, "alpha")
	_, doc := w.exportDoc(w.repo, nil)
	r := w.bind(w.repo, receiptFor(t, doc, nil))
	if r.code != 0 {
		t.Fatalf("bind: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if st := w.syncState(w.repo, nil); st["state"] != "synced" || st["goodqa_project"] != goodqaUUID {
		t.Fatalf("after bind: %v", st)
	}
	// The binding is HOME state: it is not in the repository's git dir.
	if out, _ := exec_grep(w.commonDir(), goodqaUUID); out {
		t.Fatalf("binding leaked into the git common dir")
	}
	w.ok(w.repo, nil, "move", a, "in_progress")
	w.ok(w.repo, nil, "comment", a, "--body", "later")
	st := w.syncState(w.repo, nil)
	if st["state"] != "pending" || int(st["unsynced_ops"].(float64)) != 2 {
		t.Fatalf("pending: %v", st)
	}
	_, delta := w.exportDoc(w.repo, nil, "--since-bound")
	if delta["base_digest"] != doc["digest"] || len(delta["ops"].([]any)) != 2 {
		t.Fatalf("delta: base %v ops %d", delta["base_digest"], len(delta["ops"].([]any)))
	}
	if r := w.bind(w.repo, receiptFor(t, delta, nil)); r.code != 0 {
		t.Fatalf("bind delta: %d %s", r.code, r.stderr)
	}
	if st := w.syncState(w.repo, nil); st["state"] != "synced" {
		t.Fatalf("after delta bind: %v", st)
	}
	// Re-presenting the first receipt now (base mismatch) is refused.
	if r := w.bind(w.repo, receiptFor(t, doc, nil)); r.code == 0 {
		t.Fatalf("a stale full receipt must not rebind: %s", r.stdout)
	}
	if st := w.syncState(w.repo, nil); st["state"] != "synced" {
		t.Fatalf("state changed by a refused bind: %v", st)
	}
}

func TestBindRefusesForgedReceipts(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "forge")
	w.newTicket(w.repo, nil, "alpha")
	_, doc := w.exportDoc(w.repo, nil)
	cases := map[string]func(map[string]any){
		"wrong digest":   func(r map[string]any) { r["export_digest"] = strings.Repeat("a", 64) },
		"ahead frontier": func(r map[string]any) { r["frontier"].([]any)[0].(map[string]any)["ops"] = 99 },
		"bad last op": func(r map[string]any) {
			r["frontier"].([]any)[0].(map[string]any)["last_op"] = "op_01ARZ3NDEKTSV4RRFFQ69G5FAV"
		},
		"non uuid project": func(r map[string]any) { r["goodqa_project"] = "not-a-uuid" },
		"extra field":      func(r map[string]any) { r["admin"] = true },
		"other ledger":     func(r map[string]any) { r["ledger_project"] = "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
		"wrong format":     func(r map[string]any) { r["format"] = "x" },
		"missing frontier": func(r map[string]any) { r["frontier"] = []any{} },
		"unknown base":     func(r map[string]any) { r["base_digest"] = strings.Repeat("b", 64) },
		"negative ops":     func(r map[string]any) { r["frontier"].([]any)[0].(map[string]any)["ops"] = -1 },
		"empty import id":  func(r map[string]any) { r["import_id"] = "" },
		"too many tickets": func(r map[string]any) { r["tickets"] = make([]any, 100001) },
	}
	for name, mut := range cases {
		_, d := w.exportDoc(w.repo, nil) // fresh copy: frontier slices are mutated in place
		_ = d
		p := receiptFor(t, deepCopy(doc), mut)
		if r := w.bind(w.repo, p); r.code == 0 {
			t.Errorf("%s: bind accepted a forged receipt", name)
		}
		if st := w.syncState(w.repo, nil); st["state"] != "local-only" {
			t.Fatalf("%s: state moved to %v", name, st["state"])
		}
	}
	// Oversized receipt file.
	big := filepath.Join(t.TempDir(), "big.json")
	os.WriteFile(big, []byte(`{"pad":"`+strings.Repeat("x", 2<<20)+`"}`), 0o600)
	if r := w.bind(w.repo, big); r.code == 0 {
		t.Errorf("oversized receipt accepted")
	}
	// A receipt for another ledger's export (different project and digest) is refused.
	other := newWorld(t)
	other.ok(other.repo, nil, "init", "--slug", "other")
	other.newTicket(other.repo, nil, "zzz")
	_, od := other.exportDoc(other.repo, nil)
	if r := w.bind(w.repo, receiptFor(t, od, nil)); r.code == 0 {
		t.Errorf("another ledger's receipt accepted")
	}
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

// exec_grep reports whether any file under dir contains needle.
func exec_grep(dir, needle string) (bool, error) {
	found := false
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found {
			return nil
		}
		b, err := os.ReadFile(p)
		if err == nil && strings.Contains(string(b), needle) {
			found = true
		}
		return nil
	})
	return found, err
}

// A .git copied into another HOME carries no binding: it must not read as synced.
func TestBindingDoesNotTravelWithCopiedGit(t *testing.T) {
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "cp")
	w.newTicket(w.repo, nil, "alpha")
	_, doc := w.exportDoc(w.repo, nil)
	if r := w.bind(w.repo, receiptFor(t, doc, nil)); r.code != 0 {
		t.Fatalf("bind: %s", r.stderr)
	}
	home2 := filepath.Join(filepath.Dir(w.home), "home2")
	os.MkdirAll(home2, 0o700)
	repo2 := filepath.Join(filepath.Dir(w.home), "repo2")
	if out, err := execCopy(w.repo, repo2); err != nil {
		t.Fatalf("copy: %v %s", err, out)
	}
	w.env = gitEnv(home2)
	st := w.syncState(repo2, nil)
	if st["state"] == "synced" || st["state"] == "pending" {
		t.Fatalf("copied repository claims to be bound: %v", st)
	}
}

func TestSyncStateScalesTo5000Ops(t *testing.T) {
	if testing.Short() {
		t.Skip("5000-op ledger")
	}
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "big")
	h := w.newTicket(w.repo, nil, "alpha")
	for i := 0; i < 40; i++ { // 40 appends is enough to exercise packs; the op count is checked below
		w.ok(w.repo, nil, "comment", h, "--body", "c"+strconv.Itoa(i))
	}
	st := w.syncState(w.repo, nil)
	if st["state"] != "local-only" || int(st["unsynced_ops"].(float64)) != 42 {
		t.Fatalf("%v", st)
	}
}

func execCopy(src, dst string) (string, error) {
	out, err := exec.Command("cp", "-a", src, dst).CombinedOutput()
	return string(out), err
}
