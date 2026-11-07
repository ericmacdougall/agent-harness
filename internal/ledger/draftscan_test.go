package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

// Kimi audit F11 (goodqa#14998): secret scanning of drafts recurses into nested values, raw JSON and both
// actor name fields, and fails closed on malformed raw JSON or unbounded nesting.

func TestScanDraftsRecursesAndScansActorHuman(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("ABCDEFGHIJ", 2) + "abcdef0123456789"
	newDraft := func() op.Draft {
		return op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Payload: op.Obj{{K: "nested", V: []any{
			op.Obj{{K: "deep", V: []any{"safe", secret}}}, []string{secret}, map[string]any{"deeper": secret},
		}}}}
	}

	draft := newDraft()
	if err := scanDrafts([]op.Draft{draft}, false); !errors.Is(err, ErrSecret) {
		t.Fatalf("nested secrets were not refused: %v", err)
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the secret: %v", err)
	}

	draft = newDraft()
	if err := scanDrafts([]op.Draft{draft}, true); err != nil {
		t.Fatalf("nested redaction failed: %v", err)
	}
	encoded := string(op.MustEncode(draft.Payload))
	if strings.Contains(encoded, secret) || strings.Count(encoded, "[REDACTED:") != 3 {
		t.Fatalf("nested values were not all masked: %s", encoded)
	}

	draft = newDraft()
	draft.Actor.Human = secret
	if err := scanDrafts([]op.Draft{draft}, true); !errors.Is(err, ErrSecret) {
		t.Fatalf("actor human secret was not refused: %v", err)
	}
	if draft.Actor.Human != secret {
		t.Fatalf("actor attribution was masked instead of refused")
	}
}

func TestScanDraftsRawMessageSecrets(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("ABCDEFGHIJ", 2) + "abcdef0123456789"
	newDraft := func(nested bool) op.Draft {
		raw := json.RawMessage(`{"safe":"ok","token":"` + secret + `","array":[{"token":"` + secret + `"}]}`)
		value := any(raw)
		if nested {
			value = []any{map[string]any{"raw": raw}}
		}
		return op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Payload: op.Obj{{K: "labels", V: value}}}
	}

	for _, nested := range []bool{false, true} {
		name := "direct"
		if nested {
			name = "nested"
		}
		t.Run(name, func(t *testing.T) {
			draft := newDraft(nested)
			if err := scanDrafts([]op.Draft{draft}, false); !errors.Is(err, ErrSecret) {
				t.Fatalf("RawMessage secret was not refused: %v", err)
			} else if strings.Contains(err.Error(), secret) {
				t.Fatal("refusal error leaked the RawMessage secret")
			}

			draft = newDraft(nested)
			if err := scanDrafts([]op.Draft{draft}, true); err != nil {
				t.Fatalf("RawMessage redaction failed: %v", err)
			}
			encoded := string(op.MustEncode(draft.Payload))
			if strings.Contains(encoded, secret) || strings.Count(encoded, "[REDACTED:") != 2 {
				t.Fatal("RawMessage values were not recursively redacted")
			}
		})
	}
}

func TestScanDraftsRawMessageCanonicalEncoding(t *testing.T) {
	raw := json.RawMessage(" \n { \"message\" : \"caf\\u00e9\", \"items\" : [ 1, true, null ] } \t")
	canonical, err := op.Encode(raw)
	if err != nil {
		t.Fatal(err)
	}
	draft := op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Payload: op.Obj{
		{K: "direct", V: raw},
		{K: "nested", V: []any{map[string]any{"raw": raw}}},
	}}
	want := op.MustEncode(draft.Payload)
	if err := scanDrafts([]op.Draft{draft}, false); err != nil {
		t.Fatalf("valid RawMessage rejected: %v", err)
	}
	if got := op.MustEncode(draft.Payload); !bytes.Equal(got, want) {
		t.Fatalf("canonical encoding changed:\n%s\n%s", got, want)
	}
	direct, ok := draft.Payload[0].V.(json.RawMessage)
	if !ok || !bytes.Equal(direct, canonical) {
		t.Fatalf("direct RawMessage was not canonically re-encoded: %T %q", draft.Payload[0].V, direct)
	}
	nested, ok := draft.Payload[1].V.([]any)[0].(map[string]any)["raw"].(json.RawMessage)
	if !ok || !bytes.Equal(nested, canonical) {
		t.Fatalf("nested RawMessage was not canonically re-encoded: %T %q", nested, nested)
	}
}

func TestScanDraftsRejectsMalformedRawMessage(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("ABCDEFGHIJ", 2) + "abcdef0123456789"
	cases := map[string]json.RawMessage{
		"duplicate key": json.RawMessage(`{"` + secret + `":1,"` + secret + `":2}`),
		"trailing data": json.RawMessage(`{"token":"` + secret + `"} true`),
		"bad syntax":    json.RawMessage(`["` + secret + `",]`),
		"invalid UTF-8": json.RawMessage{'"', 0xff, '"'},
		"non-integer":   json.RawMessage(`1.5`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			for _, redact := range []bool{false, true} {
				draft := op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Payload: op.Obj{{K: "raw", V: raw}}}
				err := scanDrafts([]op.Draft{draft}, redact)
				if !errors.Is(err, ErrUsage) {
					t.Fatalf("malformed RawMessage accepted (redact=%v): %v", redact, err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatal("malformed RawMessage error leaked a secret")
				}
			}
		})
	}
}

func TestScanDraftsBoundsCyclicPayload(t *testing.T) {
	cycle := []any{nil}
	cycle[0] = cycle
	draft := op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Payload: op.Obj{{K: "cycle", V: cycle}}}
	if err := scanDrafts([]op.Draft{draft}, false); !errors.Is(err, ErrUsage) {
		t.Fatalf("cyclic payload was not bounded: %v", err)
	}
}

func rawMessageTicketPayload(secret string) op.Obj {
	payload := op.TicketCreate("raw", "", "task", "medium", nil, "todo", "unstarted")
	payload[4].V = json.RawMessage(`["safe","` + secret + `"]`)
	return payload
}

func assertSecretNotStored(t *testing.T, home, gitDir, secret string) {
	t.Helper()
	cmd := exec.Command("git", "--git-dir="+gitDir, "cat-file", "--batch-all-objects", "--batch")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("could not inspect Git objects: %v", err)
	}
	if bytes.Contains(out, []byte(secret)) {
		t.Fatal("secret reached a Git object")
	}
	if err := filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(contents, []byte(secret)) {
				t.Fatalf("secret reached stored file %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("could not inspect stored files: %v", err)
	}
}

func TestAppendRawMessageTicketSecrets(t *testing.T) {
	secret := "gh" + "p_" + strings.Repeat("ABCDEFGHIJ", 2) + "abcdef0123456789"
	for _, fromCallback := range []bool{false, true} {
		for _, redact := range []bool{false, true} {
			name := "direct/refuse"
			if fromCallback {
				name = "callback/refuse"
			}
			if redact {
				name = strings.TrimSuffix(name, "refuse") + "redact"
			}
			t.Run(name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				l, err := Init(Location{Cwd: home}, InitOptions{
					Slug: "raw-message", Name: "raw", NoRepo: true,
					Actor: op.Actor{Kind: "agent", Label: "test"},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()

				draft := op.Draft{Actor: op.Actor{Kind: "agent", Label: "test"}, Kind: op.KindTicketCreate}
				var check func(*fold.View, []op.Draft) error
				if fromCallback {
					check = func(_ *fold.View, drafts []op.Draft) error {
						drafts[0].Payload = rawMessageTicketPayload(secret)
						return nil
					}
				} else {
					draft.Payload = rawMessageTicketPayload(secret)
				}
				res, err := l.Append([]op.Draft{draft}, AppendOptions{RedactSecrets: redact}, check)
				if !redact {
					if !errors.Is(err, ErrSecret) {
						t.Fatalf("RawMessage ticket secret was not refused: %v", err)
					}
					if strings.Contains(err.Error(), secret) {
						t.Fatal("append refusal leaked the RawMessage secret")
					}
				} else {
					if err != nil {
						t.Fatalf("RawMessage ticket redaction failed: %v", err)
					}
					if res == nil || len(res.Ops) != 1 {
						t.Fatal("redacted append returned no op")
					}
					if bytes.Contains(res.Ops[0].Raw, []byte(secret)) || !bytes.Contains(res.Ops[0].Raw, []byte("[REDACTED:")) {
						t.Fatal("stored op was not redacted")
					}
				}
				assertSecretNotStored(t, home, l.Root, secret)
			})
		}
	}
}
