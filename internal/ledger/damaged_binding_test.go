package ledger_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
)

// Damage to sync.json must never read as "never bound": that would drop the pinned key and let an unsigned
// receipt with base_digest "" bind (Kimi audit F10 review, goodqa#14998). Main returned nil for an unparsable
// file; a stricter reader that returns nil for a bad frontier would widen the same hole.
func TestDamagedBindingRefusesUnsignedReceiptAndSinceBound(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	for _, damage := range []string{"truncated", "negative-ops"} {
		t.Run(damage, func(t *testing.T) {
			w := newWorld(t)
			w.ok(w.repo, nil, "init", "--slug", "dmg-"+damage)
			w.newTicket(w.repo, nil, "alpha")
			key := filepath.Join(w.home, "k.pub")
			os.WriteFile(key, []byte(hex.EncodeToString(priv.Public().(ed25519.PublicKey))), 0o600)
			_, doc := w.exportDoc(w.repo, nil)
			p := receiptFor(t, doc, nil)
			raw, _ := os.ReadFile(p)
			var rd ledger.ReceiptDoc
			json.Unmarshal(raw, &rd)
			env, _ := rd.Sign(priv)
			b, _ := json.Marshal(env)
			os.WriteFile(p, b, 0o600)
			if r := w.run(w.repo, nil, "tickets", "bind", "--project", goodqaUUID, "--receipt", p, "--goodqa-key", key); r.code != 0 {
				t.Fatalf("%s", r.stderr)
			}
			proj := w.jsonOK(w.repo, nil, "status")["project"].(string)
			sync := filepath.Join(w.home, ".agent-harness", "ledgers", proj, "sync.json")
			sb, _ := os.ReadFile(sync)
			switch damage {
			case "truncated":
				sb = sb[:len(sb)/2]
			case "negative-ops":
				var sd map[string]any
				json.Unmarshal(sb, &sd)
				sd["frontier"].([]any)[0].(map[string]any)["ops"] = -1
				sb, _ = json.Marshal(sd)
			}
			os.WriteFile(sync, sb, 0o600)
			// A bare (unsigned) full-export receipt has base_digest "": it must not bind over damaged state.
			_, full := w.exportDoc(w.repo, nil)
			if r := w.run(w.repo, nil, "tickets", "bind", "--project", goodqaUUID, "--receipt", receiptFor(t, full, nil)); r.code == 0 {
				t.Fatalf("an unsigned receipt bound over a damaged binding")
			} else if !strings.Contains(r.stderr, "damaged") {
				t.Fatalf("refusal does not name the damage: %s", r.stderr)
			}
			if r := w.run(w.repo, nil, "tickets", "export", "--format", "goodqa-import", "--since-bound"); r.code == 0 {
				t.Fatalf("--since-bound exported against a damaged binding")
			}
			if st := w.jsonOK(w.repo, nil, "sync-state")["state"]; st != "diverged" {
				t.Fatalf("damaged binding reported as %v, want diverged", st)
			}
			// Recovery: unbind removes the damaged file, then a signed bind works again.
			w.ok(w.repo, nil, "unbind", "--confirm", "dmg-"+damage)
			if r := w.run(w.repo, nil, "tickets", "bind", "--project", goodqaUUID, "--receipt", p, "--goodqa-key", key); r.code != 0 {
				t.Fatalf("bind after unbind failed: %s", r.stderr)
			}
		})
	}
}
