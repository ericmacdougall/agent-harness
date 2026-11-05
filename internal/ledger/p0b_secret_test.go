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

// An invented, sequential token shape built at run time, so no token-shaped literal sits in the source
// (the repository is public and scanned for them). It is not a credential.
var plantedSecret = "gh" + "p_" + strings.Repeat("ABCDEFGHIJ", 2) + "abcdef0123456789"

// plantSecretComment appends a comment holding a secret-shaped token to this machine's own writer ref in the
// HOME mirror, bypassing the write-time scan (as a restored ref or an older version could have).
func plantSecretComment(t *testing.T, w *world, handle string) {
	t.Helper()
	list := w.jsonOK(w.repo, nil, "list")
	var ticketID string
	for _, x := range list["tickets"].([]any) {
		m := x.(map[string]any)
		if m["handle"] == handle {
			ticketID = m["id"].(string)
		}
	}
	if ticketID == "" {
		t.Fatalf("no ticket %s in %v", handle, list)
	}
	var writerID string
	for _, x := range w.jsonOK(w.repo, nil, "writers")["writers"].([]any) {
		if x.(map[string]any)["class"] == "self" {
			writerID = x.(map[string]any)["id"].(string)
		}
	}
	project := w.jsonOK(w.repo, nil, "status")["project"].(string)
	mirror := filepath.Join(w.home, ".agent-harness", "ledgers", project, "mirror.git")
	g := &store.Git{GitDir: mirror}
	ref := store.RefName(project, writerID)
	tip, err := g.Tip(ref)
	if err != nil || tip == "" {
		t.Fatalf("mirror tip: %q %v", tip, err)
	}
	last, err := g.TipHLC(tip)
	if err != nil {
		t.Fatal(err)
	}
	wall := last.WallMs + 1
	id, _ := op.NewID(op.PrefixOp, wall)
	cid, _ := op.NewID(op.PrefixComment, wall)
	o := &op.Op{V: 1, ID: id, Project: project, Writer: writerID, HLC: op.HLC{WallMs: wall}, Actor: op.Actor{Kind: "human", Label: "cli"},
		Ticket: ticketID, Kind: op.KindComment, Payload: op.Comment(cid, "the token is "+plantedSecret)}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := op.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	wj, _ := os.ReadFile(filepath.Join(w.commonDir(), "goodqa", "writer.json"))
	var wm struct {
		Writers map[string]struct{ Writer, Lease string }
	}
	json.Unmarshal(wj, &wm)
	lease := ""
	for _, e := range wm.Writers {
		if e.Writer == writerID {
			lease = e.Lease
		}
	}
	commit, err := g.WritePack(tip, []*op.Op{parsed}, lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.CAS(ref, commit, tip); err != nil {
		t.Fatal(err)
	}
}

func TestSecretInOldOpIsRefusedOnExportPlainAndPush(t *testing.T) {
	p := newPair(t)
	a := p.a
	a.ok(a.repo, nil, "init", "--slug", "sec")
	h := a.newTicket(a.repo, nil, "alpha")
	a.enable(a.repo)
	plantSecretComment(t, a, h)

	// Plain export refuses, names the field only, and says how to proceed.
	r := a.run(a.repo, nil, "tickets", "export", "--format", "goodqa-import")
	if r.code != 2 || strings.Contains(r.stdout+r.stderr, plantedSecret) || !strings.Contains(r.stderr, "redact-secrets") || !strings.Contains(r.stderr, "comment") {
		t.Fatalf("plain export: %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	// travel push refuses before anything is transferred.
	r = a.run(a.repo, nil, "tickets", "travel", "push")
	if r.code == 0 || strings.Contains(r.stdout+r.stderr, plantedSecret) {
		t.Fatalf("push with a secret: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if got := remoteRefs(a, p.remote); got != "" {
		t.Fatalf("a ref reached the remote: %q", got)
	}

	// The redacted export masks the token, drops the raw ops, and is bindable only through a redacted receipt.
	out := a.ok(a.repo, nil, "export", "--format", "goodqa-import", "--redact-secrets")
	if strings.Contains(out, plantedSecret) || !strings.Contains(out, "[REDACTED:") {
		t.Fatalf("redacted export leaked or did not mask:\n%.400s", out)
	}
	var doc map[string]any
	json.Unmarshal([]byte(out), &doc)
	if doc["redacted"] != true || doc["ops_omitted"] != "redacted" || doc["ops"] != nil {
		t.Fatalf("redacted header: %v %v", doc["redacted"], doc["ops_omitted"])
	}
	plain := receiptFor(t, deepCopy(doc), func(m map[string]any) { m["redacted"] = false })
	if r := a.bind(a.repo, plain); r.code == 0 {
		t.Fatalf("a plain-mode receipt bound a ledger that cannot be exported plain")
	}
	if r := a.bind(a.repo, receiptFor(t, doc, nil)); r.code != 0 {
		t.Fatalf("redacted receipt: %d %s", r.code, r.stderr)
	}
	if st := a.syncState(a.repo, nil); st["state"] != "synced" {
		t.Fatalf("%v", st)
	}
}
