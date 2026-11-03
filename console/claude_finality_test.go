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
	finalBeforeReturn bool
	once              sync.Once
}

func (w *claudeResultBeforeAckWriter) Write(data []byte) (int, error) {
	w.once.Do(func() {
		_, _ = io.WriteString(w.result, `{"type":"result","result":"bounded fixture complete"}`+"\n")
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			w.app.mu.Lock()
			w.finalBeforeReturn = w.session.requests[w.requestID] == "final"
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

func TestCodexCompletionBeforeStartReplyErrorRemainsFinal(t *testing.T) {
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
	if got := current.requests[requestID]; got != "final" || current.Status == "unknown" {
		t.Fatalf("late turn/start error downgraded terminal request: state=%q status=%q", got, current.Status)
	}
	client.writer.close()
	a.close()

	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status == "unknown" {
		t.Fatalf("completed Codex request restored as uncertain: %#v", restored.state())
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
