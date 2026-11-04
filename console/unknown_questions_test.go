package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireUnknownWithoutQuestions(t *testing.T, a *app, s *session) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.requests[s.lastRequest] != "unknown" || s.Status != "unknown" || len(s.PendingQuestions) != 0 {
		t.Fatalf("unknown request retained authority: request=%s status=%s pending=%d", s.requests[s.lastRequest], s.Status, len(s.PendingQuestions))
	}
}

func requireClaudeQuestionRevoked(t *testing.T, a *app, s *session, run *claudeRun, sink *lifecycleSink) {
	t.Helper()
	requireUnknownWithoutQuestions(t, a, s)
	select {
	case data := <-sink.writes:
		frame := object(data)
		response := mapField(frame, "response")
		if textField(frame, "type") != "control_response" || textField(response, "subtype") != "error" || textField(response, "request_id") != "permission" {
			t.Fatal("permission waiter did not receive its error response", string(data))
		}
	case <-time.After(time.Second):
		t.Fatal("revoked permission waiter received no error response")
	}
	if err := a.answerQuestion(s.ID, "permission", "allow"); err == nil {
		t.Fatal("later answer to revoked question succeeded")
	}
	// Repeated unknown handling must not send another rejection. A writer
	// barrier also exposes any erroneously queued successful answer.
	a.unknownSend(s, s.lastRequest, errors.New("repeated uncertainty"))
	if err := run.write(map[string]any{"type": "fixture-drain"}); err != nil {
		t.Fatal(err)
	}
	if data := <-sink.writes; textField(object(data), "type") != "fixture-drain" {
		t.Fatal("unexpected extra permission response", string(data))
	}
	select {
	case data := <-sink.writes:
		t.Fatal("unexpected extra write", string(data))
	default:
	}
}

func TestClaudeAcceptedReceiptFailureRevokesEarlierQuestion(t *testing.T) {
	for _, failReceipt := range []bool{false, true} {
		t.Run(map[bool]string{false: "durable-control", true: "failed-receipt"}[failReceipt], func(t *testing.T) {
			a, s, run, sink := lifecycleReaderSession(t)
			s.requests["active"] = "intent"
			run.requestID = ""
			s.policy, _ = defaultPolicy("claude", "", "main")
			a.runtime = func(string, string) (string, []string, error) { return "/fixture/claude", nil, nil }
			_, _, fingerprint, err := a.resolveRuntime(s.policy)
			if err != nil {
				t.Fatal(err)
			}
			run.cwd, run.runtimeHash, run.policy = s.CWD, fingerprint, s.policy
			if err := a.record(s, "active", "intent"); err != nil {
				t.Fatal(err)
			}
			blocker := &lifecycleBlockedSink{lifecycleSink: sink, entered: make(chan struct{}), release: make(chan struct{})}
			run.input = blocker
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(blocker.release) }) })
			done := make(chan error, 1)
			go func() { done <- a.sendClaude(s, "active", "fixture-block", s.CWD, "") }()
			select {
			case <-blocker.entered:
			case <-time.After(time.Second):
				t.Fatal("user frame never reached the controlled writer")
			}
			a.readClaude(s, run, strings.NewReader(lifecycleQuestion))
			a.mu.Lock()
			ready := s.requests["active"] == "intent" && s.Status == "waiting" && len(s.PendingQuestions) == 1 && run.requestID == "active"
			a.mu.Unlock()
			if !ready {
				t.Fatal("permission did not arrive while the input write was awaiting success")
			}
			if failReceipt {
				if err := a.journal.Close(); err != nil {
					t.Fatal(err)
				}
			}
			// This writer returns len(frame), nil; only receipt persistence fails.
			release.Do(func() { close(blocker.release) })
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("controlled user write did not succeed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("send did not return after successful input write")
			}
			if failReceipt {
				requireClaudeQuestionRevoked(t, a, s, run, sink)
				return
			}
			if s.requests["active"] != "accepted" || s.Status != "waiting" || len(s.PendingQuestions) != 1 {
				t.Fatal("durable accepted receipt revoked a valid question")
			}
			if err := a.answerQuestion(s.ID, "permission", "allow"); err != nil {
				t.Fatal("durable permission could not be answered", err)
			}
			if data := <-sink.writes; !bytes.Contains(data, []byte(`"subtype":"success"`)) {
				t.Fatal("durable control did not write a successful answer", string(data))
			}
		})
	}
}

func TestClaudeUnknownTransitionsRevokeEarlierQuestion(t *testing.T) {
	for _, transition := range []string{"unknown-send", "mismatched-result", "unfinished", "final-receipt-failure"} {
		t.Run(transition, func(t *testing.T) {
			a, s, run, sink := lifecycleReaderSession(t)
			if transition == "mismatched-result" {
				run.requestID = ""
			}
			a.readClaude(s, run, strings.NewReader(lifecycleQuestion))
			if len(s.PendingQuestions) != 1 {
				t.Fatal("missing earlier permission question")
			}
			switch transition {
			case "unknown-send":
				a.unknownSend(s, "active", errors.New("controlled ambiguous write"))
			case "mismatched-result":
				a.readClaude(s, run, strings.NewReader("{\"type\":\"result\"}\n"))
			case "unfinished":
				a.mu.Lock()
				a.claudeUnfinishedLocked(s, run, "controlled unfinished process")
				a.mu.Unlock()
			case "final-receipt-failure":
				if err := a.journal.Close(); err != nil {
					t.Fatal(err)
				}
				a.readClaude(s, run, strings.NewReader("{\"type\":\"result\"}\n"))
			}
			requireClaudeQuestionRevoked(t, a, s, run, sink)
		})
	}
}

func TestCodexUnknownTransitionsRevokeEarlierQuestions(t *testing.T) {
	for _, transition := range []string{"quarantine", "unknown-send", "final-receipt-failure"} {
		t.Run(transition, func(t *testing.T) {
			a, s, c, bind, answers := identityHeldReply(t)
			bind()
			s.Agents = append(s.Agents, agent{ID: "child-thread", turnID: "child-turn", Status: "running"})
			for i, target := range []string{s.ProviderID, "child-thread"} {
				turn := "turn-B"
				if i == 1 {
					turn = "child-turn"
				}
				params, _ := json.Marshal(map[string]any{"threadId": target, "turnId": turn})
				a.codexQuestion(c, rpcPacket{ID: json.RawMessage([]string{"20", "21"}[i]), Method: "item/commandExecution/requestApproval", Params: params})
			}
			if len(s.PendingQuestions) != 2 {
				t.Fatal("root and child questions did not surface")
			}
			questions := append([]question(nil), s.PendingQuestions...)
			switch transition {
			case "quarantine":
				a.mu.Lock()
				a.quarantineCodexLocked(s, "B", "controlled binding uncertainty")
				a.mu.Unlock()
			case "unknown-send":
				a.unknownSend(s, "B", errors.New("controlled ambiguous write"))
			case "final-receipt-failure":
				if err := a.journal.Close(); err != nil {
					t.Fatal(err)
				}
				identityEvent(a, c, "turn/completed", "turn-B")
			}
			requireUnknownWithoutQuestions(t, a, s)
			seen := map[string]bool{}
			for range questions {
				select {
				case packet := <-answers:
					id := string(packet.ID)
					if packet.Error == nil || len(packet.Result) != 0 || seen[id] || !oneOf(id, "20", "21") {
						t.Fatal("wrong or duplicate permission rejection", packet)
					}
					seen[id] = true
				case <-time.After(time.Second):
					t.Fatal("question waiter received no rejection")
				}
			}
			for _, q := range questions {
				if err := a.answerQuestion(s.ID, q.ID, "accept"); err == nil {
					t.Fatal("later answer succeeded")
				}
			}
			a.mu.Lock()
			a.quarantineCodexLocked(s, "B", "repeated quarantine")
			a.mu.Unlock()
			if err := c.write(map[string]any{"method": "fixture-drain"}); err != nil {
				t.Fatal(err)
			}
			if packet := <-answers; packet.Method != "fixture-drain" {
				t.Fatal("unexpected extra permission response", packet)
			}
			select {
			case packet := <-answers:
				t.Fatal("unexpected extra write", packet)
			default:
			}
		})
	}
}
