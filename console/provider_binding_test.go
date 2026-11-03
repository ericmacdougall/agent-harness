package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Observe the write while withholding its reply. The writer remains responsive.
func identityHeldReply(t *testing.T) (*app, *session, *rpcClient, func(), <-chan rpcPacket) {
	t.Helper()
	a, s, c := identityCodexFixture(t)
	writes := make(chan []byte, 1)
	answers := make(chan rpcPacket, 32)
	c.input = replySink{reply: func(data []byte) {
		var packet rpcPacket
		_ = json.Unmarshal(data, &packet)
		if packet.Method == "turn/start" {
			writes <- append([]byte(nil), data...)
		} else {
			answers <- packet
		}
	}}
	done := make(chan error, 1)
	go func() { done <- a.send(s.ID, "B", "bounded B", nil, false) }()
	var write []byte
	select {
	case write = <-writes:
	case <-time.After(5 * time.Second):
		t.Fatal("turn/start not written")
	}
	bound := false
	bind := func() {
		if bound {
			return
		}
		bound = true
		identityReply(c, write, "turn-B")
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("bind: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("binding did not finish")
		}
	}
	t.Cleanup(bind)
	return a, s, c, bind, answers
}
func identityRootFrame(a *app, c *rpcClient, method, turn, id string) {
	value := map[string]any{"threadId": "identity-thread", "turnId": turn, "itemId": id, "delta": "stream text", "item": map[string]any{"id": id, "type": "commandExecution", "command": "fixture command"}, "tokenUsage": map[string]any{"total": 99}, "error": map[string]any{"message": "fixture error"}}
	data, _ := json.Marshal(value)
	a.codexEvent(c, method, data)
}
func TestIdentityCodexRootEffectsWaitForExactReply(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	a.mu.Lock()
	before := len(s.Messages)
	a.mu.Unlock()
	stale := func() {
		for _, method := range []string{"item/agentMessage/delta", "item/completed", "thread/tokenUsage/updated", "error"} {
			identityRootFrame(a, c, method, "turn-A", "stale-"+method)
		}
	}
	stale()
	identityRootFrame(a, c, "item/agentMessage/delta", "turn-B", "genuine")
	identityRootFrame(a, c, "item/completed", "turn-B", "tool-B")
	a.mu.Lock()
	if len(s.Messages) != before || len(s.filters) != 0 || s.Supervision.progress != 0 || len(s.Usage) != 0 || s.Error != "" {
		t.Error("unbound notifications changed messages, filters, progress, usage or error")
	}
	a.mu.Unlock()
	bind()
	stale()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(s.Messages) != before+2 || len(s.filters) != 1 || s.Supervision.progress != 1 || len(s.Usage) != 0 || s.Error != "" {
		t.Errorf("B isolation failed: messages=%d filters=%d progress=%d usage=%v error=%q", len(s.Messages)-before, len(s.filters), s.Supervision.progress, s.Usage, s.Error)
	}
	count := 0
	for _, m := range s.Messages {
		if m.ID == "genuine" {
			count++
			if m.Text+s.filters[m.ID].Flush() != "stream text" {
				t.Errorf("buffered delta repeated: %q", m.Text)
			}
		}
	}
	if count != 1 {
		t.Errorf("genuine B item surfaced %d times", count)
	}
}
func TestIdentityCodexQuestionRejectsUnboundAndStale(t *testing.T) {
	for _, method := range []string{"item/commandExecution/requestApproval", "item/fileChange/requestApproval", "item/tool/requestUserInput", "mcpServer/elicitation/request"} {
		t.Run(method, func(t *testing.T) {
			a, s, c, bind, answers := identityHeldReply(t)
			question := func(turn string) {
				value := map[string]any{"threadId": s.ProviderID}
				if turn != "" {
					value["turnId"] = turn
				}
				params, _ := json.Marshal(value)
				a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`20`), Method: method, Params: params})
			}
			reject := func(turn string) {
				a.mu.Lock()
				beforeStatus := s.Status
				a.mu.Unlock()
				question(turn)
				a.mu.Lock()
				if len(s.PendingQuestions) != 0 || s.Status != beforeStatus {
					t.Errorf("unbound question changed root state: pending=%d status=%s", len(s.PendingQuestions), s.Status)
				}
				a.mu.Unlock()
				select {
				case packet := <-answers:
					if packet.Error == nil {
						t.Error("question not rejected")
					}
				default:
					t.Error("question rejection missing")
				}
			}
			reject("turn-A")
			reject("turn-B")
			reject("")
			bind()
			reject("turn-A")
			reject("")
			question("turn-B")
			a.mu.Lock()
			if len(s.PendingQuestions) != 1 || s.Status != "waiting" {
				a.mu.Unlock()
				t.Fatal("genuinely bound question did not surface")
			}
			id := s.PendingQuestions[0].ID
			a.mu.Unlock()
			var answer any = map[string]any{}
			if strings.Contains(method, "requestApproval") {
				answer = "accept"
			}
			if err := a.answerQuestion(s.ID, id, answer); err != nil {
				t.Errorf("bound answer rejected: %v", err)
			}
			select {
			case packet := <-answers:
				if packet.Error != nil || len(packet.Result) == 0 {
					t.Error("bound answer not delivered")
				}
			default:
				t.Error("bound answer response missing")
			}
			identityEvent(a, c, "turn/completed", "turn-B")
			reject("turn-B")
		})
	}
}
func TestIdentityCodexRootMissingAmbiguousAndTerminalIdentity(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	bind()
	a.mu.Lock()
	before := len(s.Messages)
	a.mu.Unlock()
	for _, raw := range []string{
		`{"threadId":"identity-thread","itemId":"bad","delta":"bad"}`,
		`{"threadId":"identity-thread","turnId":42,"itemId":"bad","delta":"bad"}`,
		`{"threadId":"identity-thread","turnId":"turn-B","turn":{"id":"turn-A"},"itemId":"bad","delta":"bad"}`,
		`{"threadId":"identity-thread","turnId":"turn-A","turnId":"turn-B","itemId":"bad","delta":"bad"}`,
	} {
		a.codexEvent(c, "item/agentMessage/delta", json.RawMessage(raw))
	}
	identityEvent(a, c, "turn/completed", "turn-B")
	identityRootFrame(a, c, "item/agentMessage/delta", "turn-B", "late-B")
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(s.Messages) != before || len(s.filters) != 0 {
		t.Error("missing, ambiguous or terminal identity changed root content")
	}
}
func TestIdentityCodexBufferBoundsAndCompletedDuplicates(t *testing.T) {
	for _, mode := range []string{"duplicates", "count", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			a, s, c, bind, _ := identityHeldReply(t)
			a.mu.Lock()
			before := len(s.Messages)
			a.mu.Unlock()
			switch mode {
			case "duplicates":
				identityRootFrame(a, c, "item/completed", "turn-B", "tool")
				identityRootFrame(a, c, "item/completed", "turn-B", "tool")
			case "count":
				for i := 0; i < 129; i++ {
					identityRootFrame(a, c, "item/completed", "turn-B", fmt.Sprintf("tool-%d", i))
				}
			case "bytes":
				raw, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turnId": "turn-B", "itemId": "large", "delta": strings.Repeat("x", 256*1024)})
				a.codexEvent(c, "item/agentMessage/delta", raw)
			}
			if mode != "duplicates" {
				identityRootFrame(a, c, "item/completed", "turn-B", "after-overflow")
			}
			a.mu.Lock()
			if len(s.Messages) != before || s.Supervision.progress != 0 {
				t.Error("buffer mutated visible state")
			}
			a.mu.Unlock()
			bind()
			if mode == "duplicates" {
				identityRootFrame(a, c, "item/completed", "turn-B", "tool")
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if mode == "duplicates" {
				if len(s.Messages) != before+1 || s.Supervision.progress != 1 {
					t.Error("duplicate completed item repeated effects")
				}
			} else if len(s.Messages) != before || len(s.filters) != 0 || s.Supervision.progress != 0 {
				t.Error("overflowed private buffer leaked content")
			}
			if s.requests["B"] != "accepted" {
				t.Error("content buffer changed request outcome")
			}
		})
	}
}
func TestIdentityCodexBufferFlushPrecedesCompletion(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	identityRootFrame(a, c, "item/completed", "turn-B", "early-tool")
	identityEvent(a, c, "turn/completed", "turn-B")
	bind()
	a.mu.Lock()
	if s.requests["B"] != "final" || s.Supervision.progress != 1 {
		t.Error("matching buffered content lost at finalization")
	}
	a.mu.Unlock()
	identityRootFrame(a, c, "item/completed", "turn-B", "late-tool")
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Supervision.progress != 1 {
		t.Error("post-final content applied")
	}
	assertIdentityFinalReceipts(t, a, "B", 1)
}

func TestIdentityCodexRootMalformedCompletionCannotFinalize(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	for _, early := range []bool{true, false} {
		if !early {
			bind()
		}
		for _, identity := range []string{
			`"turnId":"turn-A","turn":{"id":"turn-B","status":"completed"}`,
			`"turnId":42,"turn":{"id":"turn-B","status":"completed"}`,
			`"turnId":"","turn":{"id":"turn-B","status":"completed"}`,
			`"turn":{"id":"turn-A","id":"turn-B","status":"completed"}`,
			`"turnId":"turn-B","turn":{"status":"completed"}`,
		} {
			a.codexEvent(c, "turn/completed", json.RawMessage(`{"threadId":"identity-thread",`+identity+`}`))
		}
		a.mu.Lock()
		if s.providerFinal || s.requests["B"] == "final" || len(s.codexTurn.pending) != 0 {
			t.Error("ambiguous completion acquired authority")
		}
		a.mu.Unlock()
	}
	identityEvent(a, c, "turn/completed", "turn-B")
	assertIdentityFinalReceipts(t, a, "B", 1)
}
func TestIdentityCodexQuestionCheckpointRechecksBindingDuringCapture(t *testing.T) {
	a, s, input := checkpointFixture(t)
	c := &rpcClient{input: &repairSink{}, done: make(chan struct{})}
	t.Cleanup(func() {
		if c.writer != nil {
			c.writer.close()
		}
	})
	s.codex = c
	s.lastRequest = "B"
	s.requests["B"] = "accepted"
	s.turnID = "turn-B"
	s.Status = "running"
	s.codexTurn = &codexTurnBinding{requestID: "B", client: c, turnID: s.turnID}
	captured := false
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		a.mu.Lock()
		s.requests["B"] = "unknown"
		a.mu.Unlock()
		captured = true
		return defaultPolicy(provider, profile, stage)
	}
	params, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turnId": s.turnID, "tool": "harness_console_checkpoint", "arguments": input})
	a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`31`), Method: "item/tool/call", Params: params})
	if !captured {
		t.Fatal("checkpoint did not reach controlled capture")
	}
	if s.task.ReviewStatus == "queued" {
		t.Error("checkpoint committed after binding was revoked during capture")
	}
}

func TestIdentityCodexQuestionCheckpointRejectsUnknownTurn(t *testing.T) {
	a, s, c, bind, answers := identityHeldReply(t)
	call := func(turn string) {
		a.mu.Lock()
		input := checkpointInput{TaskID: s.task.ID, Generation: s.task.Generation, InputRevision: s.task.InputRevision, ObjectiveHash: s.task.ObjectiveHash, State: "blocked", Scope: "checkpoint fixture"}
		a.mu.Unlock()
		params, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turnId": turn, "tool": "harness_console_checkpoint", "arguments": input})
		a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`32`), Method: "item/tool/call", Params: params})
	}
	assertRejected := func(turn string) {
		a.mu.Lock()
		before := s.task.State
		a.mu.Unlock()
		call(turn)
		packet := <-answers
		if !strings.Contains(string(packet.Result), `"success":false`) {
			t.Error("unbound checkpoint succeeded")
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if s.task.State != before {
			t.Error("unbound checkpoint changed task")
		}
	}
	assertRejected("turn-B")
	bind()
	assertRejected("turn-A")
	call("turn-B")
	packet := <-answers
	if !strings.Contains(string(packet.Result), `"success":true`) {
		t.Error("bound checkpoint failed")
	}
	a.mu.Lock()
	s.requests["B"] = "unknown"
	s.task.State = "idle"
	a.mu.Unlock()
	assertRejected("turn-B")
}
func TestIdentityCodexRootAmbiguousReplyDiscardsContent(t *testing.T) {
	for _, result := range []string{
		`{"turn":{"id":"turn-A","id":"turn-B"}}`,
		`{"turn":{"id":"turn-A"},"turn":{"id":"turn-B"}}`,
		`{"turnId":null,"turn":{"id":"turn-B"}}`,
	} {
		t.Run(result, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			c.input = replySink{reply: func(data []byte) {
				identityRootFrame(a, c, "item/completed", "turn-B", "early-tool")
				identityEvent(a, c, "turn/completed", "turn-B")
				var packet rpcPacket
				_ = json.Unmarshal(data, &packet)
				c.mu.Lock()
				ch := c.pending[string(packet.ID)]
				c.mu.Unlock()
				ch <- rpcPacket{ID: packet.ID, Result: json.RawMessage(result)}
			}}
			if a.send(s.ID, "B", "bounded B", nil, false) == nil {
				t.Error("ambiguous reply accepted")
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if s.requests["B"] != "unknown" || s.providerFinal || s.Supervision.progress != 0 || s.turnID != "" || len(s.codexTurn.frames) != 0 {
				t.Error("ambiguous reply authorized root effects")
			}
			assertIdentityFinalReceipts(t, a, "B", 0)
		})
	}
}
func TestIdentityCodexBufferCompletionBytesFailClosed(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	identityRootFrame(a, c, "item/completed", "turn-B", "early-tool")
	raw, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turn": map[string]any{"id": "turn-B", "status": "failed", "error": map[string]any{"message": strings.Repeat("x", 256*1024)}}})
	a.codexEvent(c, "turn/completed", raw)
	bind()
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.requests["B"] != "unknown" || s.providerFinal || s.Supervision.progress != 0 || len(s.codexTurn.frames) != 0 || len(s.codexTurn.pending) != 0 || s.codexTurn.pendingBytes != 0 {
		t.Error("completion byte overflow retained content or acquired authority")
	}
}

func TestIdentityCodexRootRepeatedDeltasAndBoundTelemetry(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	identityRootFrame(a, c, "item/agentMessage/delta", "turn-B", "repeated")
	identityRootFrame(a, c, "item/agentMessage/delta", "turn-B", "repeated")
	identityRootFrame(a, c, "thread/tokenUsage/updated", "turn-B", "")
	identityRootFrame(a, c, "error", "turn-B", "")
	bind()
	a.mu.Lock()
	defer a.mu.Unlock()
	found := false
	for _, m := range s.Messages {
		if m.ID == "repeated" {
			found = true
			if m.Text+s.filters[m.ID].Flush() != "stream textstream text" {
				t.Error("legitimate repeated chunks collapsed")
			}
		}
	}
	if !found || s.Usage["total"] != float64(99) || s.Error != "fixture error" {
		t.Error("matching buffered content or telemetry lost")
	}
}
func TestIdentityCodexRootCompletedItemDedupBound(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	bind()
	for i := 0; i < 1025; i++ {
		identityRootFrame(a, c, "item/completed", "turn-B", fmt.Sprintf("tool-%d", i))
	}
	identityRootFrame(a, c, "item/completed", "turn-B", "tool-0")
	identityRootFrame(a, c, "item/completed", "turn-B", "")
	identityRootFrame(a, c, "item/completed", "turn-B", strings.Repeat("x", 1025))
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Supervision.progress != 1024 || len(s.codexTurn.completed) != 1024 {
		t.Error("completed item bound forgot IDs or repeated effects")
	}
}
func TestIdentityCodexBufferCompletionStatusBytesFailClosed(t *testing.T) {
	a, s, c, bind, _ := identityHeldReply(t)
	raw, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turn": map[string]any{"id": "turn-B", "status": strings.Repeat("x", 256*1024)}})
	a.codexEvent(c, "turn/completed", raw)
	bind()
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.requests["B"] != "unknown" || s.providerFinal || len(s.codexTurn.pending) != 0 || s.codexTurn.pendingBytes != 0 {
		t.Error("oversized status bypassed completion byte bound")
	}
}
