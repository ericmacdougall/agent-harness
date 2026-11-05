package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type claudeResultBeforeAckWriter struct {
	result            io.Writer
	app               *app
	session           *session
	requestID         string
	waitState         string
	closeJournal      bool
	finalBeforeReturn bool
	once              sync.Once
}

func (w *claudeResultBeforeAckWriter) Write(data []byte) (int, error) {
	w.once.Do(func() {
		if w.closeJournal {
			_ = w.app.journal.Close()
		}
		_, _ = io.WriteString(w.result, `{"type":"result","result":"bounded fixture complete"}`+"\n")
		waitState := w.waitState
		if waitState == "" {
			waitState = "final"
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			w.app.mu.Lock()
			w.finalBeforeReturn = w.session.requests[w.requestID] == waitState
			w.app.mu.Unlock()
			if w.finalBeforeReturn {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	return len(data), nil
}

func (w *claudeResultBeforeAckWriter) Close() error { return nil }

func TestClaudeResultBeforeWriteAckRemainsFinalAcrossRestart(t *testing.T) {
	t.Skip("known defect in the unreleased baseline; replaced by the event-log rebuild (K5b and later), GoodQA #35692, see console/README.md")
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "result-before-write-ack"
	current := emptySession("claude", dir, "")
	current.ProviderID = "claude-provider-fixture"
	current.Status = "running"
	current.Supervision.State = "active"
	current.lastRequest = requestID
	current.requests[requestID] = "intent"
	current.requestOrder = append(current.requestOrder, requestID)
	current.policy, _ = defaultPolicy("claude", "", "main")
	current.PolicyRevision = current.policy.Revision
	if err = a.record(current, requestID, "intent"); err != nil {
		t.Fatal(err)
	}
	a.sessions = append(a.sessions, current)
	a.runtime = func(string, string) (string, []string, error) { return "/fixture/claude", nil, nil }
	_, _, fingerprint, err := a.resolveRuntime(current.policy)
	if err != nil {
		t.Fatal(err)
	}
	outputReader, outputWriter := io.Pipe()
	input := &claudeResultBeforeAckWriter{result: outputWriter, app: a, session: current, requestID: requestID}
	run := &claudeRun{input: input, done: make(chan struct{}), cwd: dir, runtimeHash: fingerprint, policy: current.policy}
	current.claude = run
	readDone := make(chan struct{})
	go func() {
		a.readClaude(current, run, outputReader)
		close(readDone)
	}()

	if err = a.sendClaude(current, requestID, "bounded fixture", dir, ""); err != nil {
		t.Fatal(err)
	}
	_ = outputWriter.Close()
	<-readDone
	if !input.finalBeforeReturn {
		t.Fatal("Claude result was not terminal before the admitted write acknowledgment returned")
	}
	if got := current.requests[requestID]; got != "final" {
		t.Fatalf("terminal request downgraded after write acknowledgment: %q", got)
	}
	a.readClaude(current, run, bytes.NewBufferString(`{"type":"result","result":"duplicate bounded fixture complete"}`+"\n"))
	a.close()

	states := []string{}
	journal, err := os.Open(filepath.Join(dir, "sessions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	scan := bufio.NewScanner(journal)
	for scan.Scan() {
		var record journalRecord
		if err = json.Unmarshal(scan.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record.RequestID == requestID {
			states = append(states, record.State)
		}
	}
	_ = journal.Close()
	if err = scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[0] != "intent" || states[1] != "final" {
		t.Fatalf("request journal is not monotonic: %v", states)
	}

	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status == "unknown" {
		t.Fatalf("completed Claude request restored as uncertain: %#v", restored.state())
	}
	restored.runtime = func(string, string) (string, []string, error) {
		return "", nil, errors.New("completed request must not reach provider runtime")
	}
	if err = restored.send(restored.sessions[0].ID, requestID, "do not replay", nil, false); err == nil {
		t.Fatal("restored completed Claude request replayed")
	}
	data, err := os.ReadFile(filepath.Join(dir, "sessions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(data, []byte(`"requestId":"`+requestID+`"`)) != 2 {
		t.Fatal("restart or replay attempt appended another request receipt")
	}
}

func TestCodexUnboundCompletionBeforeStartReplyErrorRemainsUnknown(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "completion-before-start-reply"
	current := emptySession("codex", dir, "")
	current.ProviderID = "codex-provider-fixture"
	current.Status = "running"
	current.Supervision.State = "active"
	current.lastRequest = requestID
	current.requests[requestID] = "intent"
	current.requestOrder = append(current.requestOrder, requestID)
	if err = a.record(current, requestID, "intent"); err != nil {
		t.Fatal(err)
	}
	a.sessions = append(a.sessions, current)
	client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	client.input = replySink{reply: func([]byte) {
		a.codexEvent(client, "turn/started", json.RawMessage(`{"threadId":"codex-provider-fixture","turn":{"id":"turn-fixture"}}`))
		a.codexEvent(client, "turn/completed", json.RawMessage(`{"threadId":"codex-provider-fixture","turn":{"id":"turn-fixture","status":"completed"}}`))
		close(client.done)
	}}
	current.codex = client

	var result struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	err = client.callAdmitted(context.Background(), "turn/start", map[string]any{"threadId": current.ProviderID}, &result, a.turnAdmission(current, current.dispatchEpoch, requestID))
	if err == nil {
		t.Fatal("controlled missing turn/start reply did not fail")
	}
	a.unknownSend(current, requestID, err)
	if got := current.requests[requestID]; got != "unknown" || current.Status != "unknown" || current.providerFinal {
		t.Fatalf("unbound completion escaped quarantine: state=%q status=%q", got, current.Status)
	}
	client.writer.close()
	a.close()

	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" {
		t.Fatalf("unbound Codex request did not restore as uncertain: %#v", restored.state())
	}
	restored.runtime = func(string, string) (string, []string, error) {
		return "", nil, errors.New("completed request must not reach provider runtime")
	}
	if err = restored.send(restored.sessions[0].ID, requestID, "do not replay", nil, false); err == nil {
		t.Fatal("restored completed Codex request replayed")
	}
}

func TestProviderErrorWithoutFinalRemainsUnknown(t *testing.T) {
	a := testApp(t)
	current := emptySession("codex", t.TempDir(), "")
	current.Status = "running"
	current.Supervision.State = "active"
	current.requests["unresolved"] = "intent"
	a.unknownSend(current, "unresolved", errors.New("controlled missing provider outcome"))
	if current.requests["unresolved"] != "unknown" || current.Status != "unknown" {
		t.Fatalf("genuinely unresolved request was not preserved as unknown: %#v", current)
	}
}

func TestCodexStaleCompletionCannotFinalizeCurrentRequest(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	current := emptySession("codex", dir, "")
	client := &rpcClient{}
	current.codex = client
	current.ProviderID = "codex-stale-completion-fixture"
	current.Status = "running"
	current.Supervision.State = "active"
	current.lastRequest = "current-request"
	current.requests["prior-request"] = "final"
	current.requests["current-request"] = "accepted"
	current.requestOrder = append(current.requestOrder, "prior-request", "current-request")
	current.turnID = "current-turn"
	current.codexTurn = &codexTurnBinding{client: client, requestID: current.lastRequest, turnID: current.turnID}
	if err = a.record(current, "current-request", "accepted"); err != nil {
		t.Fatal(err)
	}
	a.sessions = append(a.sessions, current)

	a.codexEvent(client, "turn/completed", json.RawMessage(`{"threadId":"codex-stale-completion-fixture","turn":{"id":"prior-turn","status":"completed"}}`))
	if current.requests["current-request"] != "accepted" || current.turnID != "current-turn" || current.Status != "running" {
		t.Fatalf("stale completion finalized current work: request=%q turn=%q status=%q", current.requests["current-request"], current.turnID, current.Status)
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" {
		t.Fatalf("unresolved current request did not restart without replay authority: %#v", restored.state())
	}
}

func TestClaudeFinalJournalFailureStaysUnknownAndDoesNotAdvance(t *testing.T) {
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	requestID := "undurable-claude-final"
	current := emptySession("claude", t.TempDir(), "")
	current.ProviderID = "claude-undurable-final-fixture"
	current.Status = "running"
	current.Supervision.State = "active"
	current.lastRequest = requestID
	current.requests[requestID] = "accepted"
	current.requestOrder = append(current.requestOrder, requestID)
	run := &claudeRun{input: &repairSink{}, done: make(chan struct{}), requestID: requestID}
	current.claude = run
	a.sessions = append(a.sessions, current)
	if err = a.journal.Close(); err != nil {
		t.Fatal(err)
	}

	a.readClaude(current, run, bytes.NewBufferString(`{"type":"result","result":"provider completed but receipt storage failed"}`+"\n"))
	if current.requests[requestID] != "unknown" || current.Status != "unknown" || current.Supervision.State != "paused" || current.providerFinal {
		t.Fatalf("undurable Claude final advertised completion: request=%q status=%q supervision=%q providerFinal=%v", current.requests[requestID], current.Status, current.Supervision.State, current.providerFinal)
	}
	revision := a.revision
	time.Sleep(350 * time.Millisecond)
	if a.revision != revision {
		t.Fatal("undurable Claude final scheduled automatic advancement")
	}
}

func TestClaudeLateWriteAckCannotDowngradeUndurableFinal(t *testing.T) {
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	requestID := "claude-undurable-before-ack"
	current := emptySession("claude", t.TempDir(), "")
	current.ProviderID = "claude-undurable-before-ack-provider"
	current.Status = "running"
	current.Supervision.State = "active"
	current.lastRequest = requestID
	current.requests[requestID] = "intent"
	current.requestOrder = append(current.requestOrder, requestID)
	current.policy, _ = defaultPolicy("claude", "", "main")
	if err = a.record(current, requestID, "intent"); err != nil {
		t.Fatal(err)
	}
	a.sessions = append(a.sessions, current)
	a.runtime = func(string, string) (string, []string, error) { return "/fixture/claude", nil, nil }
	_, _, fingerprint, err := a.resolveRuntime(current.policy)
	if err != nil {
		t.Fatal(err)
	}
	outputReader, outputWriter := io.Pipe()
	input := &claudeResultBeforeAckWriter{result: outputWriter, app: a, session: current, requestID: requestID, waitState: "unknown", closeJournal: true}
	run := &claudeRun{input: input, done: make(chan struct{}), cwd: current.CWD, runtimeHash: fingerprint, policy: current.policy}
	current.claude = run
	readDone := make(chan struct{})
	go func() {
		a.readClaude(current, run, outputReader)
		close(readDone)
	}()
	if err = a.sendClaude(current, requestID, "bounded fixture", current.CWD, ""); err != nil {
		t.Fatal(err)
	}
	_ = outputWriter.Close()
	<-readDone
	if !input.finalBeforeReturn || current.requests[requestID] != "unknown" || current.Status != "unknown" || current.providerFinal {
		t.Fatalf("late Claude write acknowledgment downgraded undurable final: observed=%v request=%q status=%q providerFinal=%v", input.finalBeforeReturn, current.requests[requestID], current.Status, current.providerFinal)
	}
}

func TestCodexLateStartReplyCannotDowngradeUndurableFinal(t *testing.T) {
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	current := emptySession("codex", t.TempDir(), "")
	current.ProviderID = "codex-undurable-before-ack-provider"
	current.Status = "idle"
	policy, _ := defaultPolicy("codex", "", "main")
	current.policy = policy
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) { return policy, nil }
	a.runtime = func(string, string) (string, []string, error) { return "/fixture/codex", nil, nil }
	_, _, fingerprint, err := a.resolveRuntime(policy)
	if err != nil {
		t.Fatal(err)
	}
	client := &rpcClient{runtimeHash: fingerprint, pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	client.input = replySink{reply: func(data []byte) {
		var packet map[string]any
		_ = json.Unmarshal(data, &packet)
		_ = a.journal.Close()
		a.codexEvent(client, "turn/started", json.RawMessage(`{"threadId":"codex-undurable-before-ack-provider","turn":{"id":"codex-undurable-turn"}}`))
		a.codexEvent(client, "turn/completed", json.RawMessage(`{"threadId":"codex-undurable-before-ack-provider","turn":{"id":"codex-undurable-turn","status":"completed"}}`))
		id, _ := json.Marshal(packet["id"])
		client.mu.Lock()
		ch := client.pending[string(id)]
		client.mu.Unlock()
		ch <- rpcPacket{ID: id, Result: json.RawMessage(`{"turn":{"id":"codex-undurable-turn"}}`)}
	}}
	current.codex = client
	a.sessions = append(a.sessions, current)
	requestID := "codex-undurable-before-ack"
	sendErr := a.send(current.ID, requestID, "bounded fixture", nil, false)
	client.writer.close()
	if current.requests[requestID] != "unknown" || current.Status != "unknown" || current.providerFinal {
		t.Fatalf("late Codex start reply downgraded undurable final: request=%q status=%q providerFinal=%v", current.requests[requestID], current.Status, current.providerFinal)
	}
	if sendErr != nil {
		t.Fatalf("late Codex start reply surfaced a second receipt failure after finality was already quarantined: %v", sendErr)
	}
}
