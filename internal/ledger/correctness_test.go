package ledger

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

const (
	testProjectID = "prj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testWriterID  = "w_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testOpID      = "op_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testTicketID  = "tk_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

func testStateLedger(t *testing.T) (*Ledger, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".agent-harness", "ledgers", testProjectID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &Ledger{Project: testProjectID, InRepo: true}, dir
}

func validBindingJSON() map[string]any {
	return map[string]any{
		"v": 1, "ledger_project": testProjectID, "goodqa_project": "goodqa", "import_id": "import",
		"export_digest": strings.Repeat("a", 64), "bound_ms": 1, "goodqa_key": "",
		"frontier": []any{map[string]any{"writer": testWriterID, "ops": 1,
			"wall_ms": op.ULIDTime(strings.TrimPrefix(testOpID, op.PrefixOp)), "ctr": 0, "last_op": testOpID}},
	}
}

func writeStateJSON(t *testing.T, dir, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadBindingRejectsMalformedFrontier(t *testing.T) {
	l, dir := testStateLedger(t)
	writeStateJSON(t, dir, syncFile, validBindingJSON())
	if got := l.ReadBinding(); got == nil || len(got.Frontier) != 1 || got.Frontier[0].Ops != 1 {
		t.Fatalf("valid binding rejected: %#v", got)
	}

	cases := map[string]func(map[string]any){
		"negative count": func(doc map[string]any) {
			doc["frontier"].([]any)[0].(map[string]any)["ops"] = -1
		},
		"fractional count": func(doc map[string]any) {
			doc["frontier"].([]any)[0].(map[string]any)["ops"] = 1.5
		},
		"duplicate writer": func(doc map[string]any) {
			f := doc["frontier"].([]any)[0]
			doc["frontier"] = []any{f, f}
		},
		"bad writer": func(doc map[string]any) {
			doc["frontier"].([]any)[0].(map[string]any)["writer"] = "writer"
		},
		"bad last op": func(doc map[string]any) {
			doc["frontier"].([]any)[0].(map[string]any)["last_op"] = "op_bad"
		},
		"bad digest": func(doc map[string]any) {
			doc["export_digest"] = strings.Repeat("x", 64)
		},
		"foreign ledger": func(doc map[string]any) {
			doc["ledger_project"] = "prj_01BRZ3NDEKTSV4RRFFQ69G5FAV"
		},
		"future version": func(doc map[string]any) {
			doc["v"] = 2
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := validBindingJSON()
			mutate(doc)
			writeStateJSON(t, dir, syncFile, doc)
			if got := l.ReadBinding(); got == nil || !got.Damaged || got.Frontier != nil || got.GoodQAKey != "" ||
				got.ExportDigest != "" {
				t.Fatalf("malformed binding was not reported as damaged-only: %#v", got)
			}
		})
	}
}

func validTrustJSON() map[string]any {
	return map[string]any{"v": 1, "ledger_project": testProjectID, "blocked": []any{},
		"trusted": map[string]any{testWriterID: map[string]any{"ops": 1, "digest": strings.Repeat("b", 64)}}}
}

func TestReadTrustRejectsMalformedEntries(t *testing.T) {
	l, dir := testStateLedger(t)
	writeStateJSON(t, dir, trustFile, validTrustJSON())
	if got := l.ReadTrust().Trusted[testWriterID]; got.Ops != 1 {
		t.Fatalf("valid trust rejected: %#v", got)
	}

	cases := map[string]func(map[string]any){
		"negative count": func(doc map[string]any) {
			doc["trusted"].(map[string]any)[testWriterID].(map[string]any)["ops"] = -1
		},
		"fractional count": func(doc map[string]any) {
			doc["trusted"].(map[string]any)[testWriterID].(map[string]any)["ops"] = 1.5
		},
		"bad digest": func(doc map[string]any) {
			doc["trusted"].(map[string]any)[testWriterID].(map[string]any)["digest"] = strings.Repeat("z", 64)
		},
		"bad writer": func(doc map[string]any) {
			entry := doc["trusted"].(map[string]any)[testWriterID]
			delete(doc["trusted"].(map[string]any), testWriterID)
			doc["trusted"].(map[string]any)["writer"] = entry
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := validTrustJSON()
			mutate(doc)
			writeStateJSON(t, dir, trustFile, doc)
			if got := l.ReadTrust().Trusted; len(got) != 0 {
				t.Fatalf("malformed trust accepted: %#v", got)
			}
		})
	}

	t.Run("duplicate writer key", func(t *testing.T) {
		raw := `{"v":1,"ledger_project":"` + testProjectID + `","trusted":{"` + testWriterID + `":{"ops":1,"digest":"` + strings.Repeat("b", 64) + `"},"` + testWriterID + `":{"ops":1,"digest":"` + strings.Repeat("b", 64) + `"}},"blocked":[]}`
		if err := os.WriteFile(filepath.Join(dir, trustFile), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := l.ReadTrust().Trusted; len(got) != 0 {
			t.Fatalf("duplicate writer accepted: %#v", got)
		}
	})
}

func TestMintRejectsMalformedCommentDraft(t *testing.T) {
	l := &Ledger{Project: testProjectID}
	cases := map[string]op.Obj{
		"missing body":    {},
		"short payload":   {{K: "comment_id", V: ""}},
		"non-string body": {{K: "comment_id", V: ""}, {K: "body", V: 1}},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			draft := op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Ticket: testTicketID, Kind: op.KindComment, Payload: payload}
			if _, err := l.mint([]op.Draft{draft}, testWriterID, op.HLC{}, 1_800_000_000_000, op.HLC{}); !errors.Is(err, ErrUsage) {
				t.Fatalf("malformed comment did not return a usage error: %v", err)
			}
		})
	}
}

func TestReadBindingAbsentAndUnparsable(t *testing.T) {
	l, dir := testStateLedger(t)
	if got := l.ReadBinding(); got != nil {
		t.Fatalf("absent binding file must read as never bound: %#v", got)
	}
	for name, raw := range map[string]string{"truncated": `{"v":1,"ledger_project":`, "duplicate key": `{"v":1,"v":1}`} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, syncFile), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := l.ReadBinding(); got == nil || !got.Damaged {
				t.Fatalf("unparsable binding must read as damaged, not unbound: %#v", got)
			}
		})
	}
}
