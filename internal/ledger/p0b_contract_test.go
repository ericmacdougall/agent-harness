package ledger_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/store"
)

const fixtureDir = "../../testdata/ledger-import"

// TestWriteImportFixture regenerates testdata/ledger-import (an export and the receipt GoodQA would return
// for it). Run once by hand: LEDGER_FIXTURE_OUT=$PWD/testdata/ledger-import go test ./internal/ledger -run TestWriteImportFixture
func TestWriteImportFixture(t *testing.T) {
	out := os.Getenv("LEDGER_FIXTURE_OUT")
	if out == "" {
		t.Skip("set LEDGER_FIXTURE_OUT to regenerate the fixture")
	}
	w := newWorld(t)
	w.ok(w.repo, nil, "init", "--slug", "sample", "--name", "Sample project")
	a := w.newTicket(w.repo, nil, "Fix the flaky login test", "--type", "bug", "--priority", "high", "--label", "ci")
	b := w.newTicket(w.repo, nil, "Document the release steps")
	w.ok(w.repo, nil, "move", a, "in_progress")
	w.ok(w.repo, nil, "comment", a, "--body", "Repro needs TZ=UTC")
	w.ok(w.repo, nil, "move", a, "in_review")
	w.ok(w.repo, nil, "move", a, "done")
	w.ok(w.repo, nil, "move", b, "todo")
	body, doc := w.exportDoc(w.repo, nil)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(out, "export.json"), []byte(body), 0o644)
	rc := receiptFor(t, doc, func(r map[string]any) {
		r["tickets"] = []any{map[string]any{"handle": a, "number": 1}, map[string]any{"handle": b, "number": 2}}
	})
	b2, _ := os.ReadFile(rc)
	os.WriteFile(filepath.Join(out, "receipt.json"), b2, 0o644)
}

// hydrate builds a bare remote that holds the fixture export's ops as one writer ref, as another machine
// would have pushed them.
func hydrate(t *testing.T, w *world, doc map[string]any) (remote string) {
	t.Helper()
	remote = filepath.Join(filepath.Dir(w.home), "fixture-remote.git")
	w.git(w.home, "init", "--bare", "-q", remote)
	g := &store.Git{GitDir: remote}
	var ops []*op.Op
	project := doc["project"].(map[string]any)["id"].(string)
	writer := doc["frontier"].([]any)[0].(map[string]any)["writer"].(string)
	for _, line := range doc["ops"].([]any) {
		o, err := op.Parse([]byte(line.(string)))
		if err != nil {
			t.Fatalf("fixture op does not parse: %v", err)
		}
		ops = append(ops, o)
	}
	commit, err := g.WritePack("", ops, "fixture-lease")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(store.RefName(project, writer), commit, ""); err != nil {
		t.Fatal(err)
	}
	return remote
}

func TestImportContractFixture(t *testing.T) {
	exportRaw, err := os.ReadFile(filepath.Join(fixtureDir, "export.json"))
	if err != nil {
		t.Fatalf("missing fixture (see TestWriteImportFixture): %v", err)
	}
	receiptRaw, _ := os.ReadFile(filepath.Join(fixtureDir, "receipt.json"))
	var doc map[string]any
	if err := json.Unmarshal(exportRaw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["format"] != "goodqa-ledger-import/v1" {
		t.Fatalf("fixture format %v", doc["format"])
	}

	// A machine that holds the fixture's ops (as a reviewed, trusted writer) rebuilds the document and
	// accepts the fixture receipt through the real `bind` command: the contract and the CLI cannot drift.
	w := newWorld(t)
	remote := hydrate(t, w, doc)
	w.git(w.repo, "remote", "add", "origin", remote)
	tok := w.adoptToken(w.repo)
	w.ok(w.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", tok)
	wid := doc["frontier"].([]any)[0].(map[string]any)["writer"].(string)
	digest := w.jsonOK(w.repo, nil, "writers", "--show", wid)["review_digest"].(string)
	w.ok(w.repo, nil, "trust-writer", wid, "--reviewed", digest)
	_, rebuilt := w.exportDoc(w.repo, nil)
	if string(mustJSON(rebuilt["digest"])) != string(mustJSON(doc["digest"])) {
		t.Fatalf("the committed export no longer matches what the CLI builds from the same ops:\nfixture %v\nrebuilt %v", doc["digest"], rebuilt["digest"])
	}
	rc := filepath.Join(t.TempDir(), "receipt.json")
	os.WriteFile(rc, receiptRaw, 0o600)
	if r := w.bind(w.repo, rc); r.code != 0 {
		t.Fatalf("bind refused the fixture receipt: %d %s", r.code, r.stderr)
	}
	if st := w.syncState(w.repo, nil); st["state"] != "synced" {
		t.Fatalf("state after the fixture bind: %v", st)
	}

	// A fixture with a wrong digest is refused and the ledger stays unsynced.
	w2 := newWorld(t)
	remote2 := hydrate(t, w2, doc)
	w2.git(w2.repo, "remote", "add", "origin", remote2)
	w2.ok(w2.repo, nil, "travel", "fetch", "--adopt", "--remote", "origin", "--yes-share", w2.adoptToken(w2.repo))
	d2 := w2.jsonOK(w2.repo, nil, "writers", "--show", wid)["review_digest"].(string)
	w2.ok(w2.repo, nil, "trust-writer", wid, "--reviewed", d2)
	var rcDoc map[string]any
	json.Unmarshal(receiptRaw, &rcDoc)
	rcDoc["export_digest"] = strings.Repeat("e", 64)
	bad, _ := json.Marshal(rcDoc)
	badPath := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(badPath, bad, 0o600)
	if r := w2.bind(w2.repo, badPath); r.code == 0 {
		t.Fatalf("a receipt with a wrong digest was accepted")
	}
	if st := w2.syncState(w2.repo, nil); st["state"] == "synced" {
		t.Fatalf("state: %v", st)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
