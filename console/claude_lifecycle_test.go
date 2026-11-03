package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This subprocess speaks only the local stream-json fixture protocol. It stays
// alive after a result, as a real CLI can while awaiting another input frame.
func claudeLifecycleProcess() {
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var frame map[string]any
		_ = json.Unmarshal(scan.Bytes(), &frame)
		file, err := os.OpenFile(os.Getenv("HARNESS_CONSOLE_LIFECYCLE_AUDIT"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(3)
		}
		_ = json.NewEncoder(file).Encode(map[string]any{"frame": frame, "args": os.Args, "pid": os.Getpid()})
		_ = file.Close()
		if textField(frame, "type") != "user" {
			continue
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "system", "session_id": frame["session_id"]})
		mode := os.Getenv("HARNESS_CONSOLE_LIFECYCLE_FIXTURE")
		if mode == "final" || mode == "final-control" {
			if gate := os.Getenv("HARNESS_CONSOLE_LIFECYCLE_GATE"); gate != "" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(gate); err == nil {
						break
					}
					if time.Now().After(deadline) {
						os.Exit(4)
					}
					time.Sleep(time.Millisecond)
				}
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "result", "result": "local lifecycle result"})
			if mode == "final-control" {
				_, _ = io.WriteString(os.Stdout, lifecycleQuestion)
			}
		}
	}
}

func lifecycleSession(t *testing.T, mode string) (*app, *session, string, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	binary, _ := os.Executable()
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_LIFECYCLE_FIXTURE="+mode, "HARNESS_CONSOLE_LIFECYCLE_AUDIT="+audit), nil
	}
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	s, err := a.createSession("claude", cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	return a, s, dir, audit
}

func waitLifecycle(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("local lifecycle fixture did not reach expected state")
}

func TestClaudeLifecycleCancelWithoutResultCannotResume(t *testing.T) {
	for _, action := range []string{"pause", "stop"} {
		t.Run(action, func(t *testing.T) {
			a, s, dir, audit := lifecycleSession(t, "no-result")
			source := filepath.Join(s.CWD, "retained.txt")
			if err := os.WriteFile(source, []byte("retained fixture input"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.selectAttachments(s.ID, []string{source}); err != nil {
				t.Fatal(err)
			}
			snapshot := s.attachmentSnapshots[source].Path
			if err := a.send(s.ID, "original", "bounded request", []string{source}, false); err != nil {
				t.Fatal(err)
			}
			waitLifecycle(t, func() bool { _, err := os.Stat(audit); return err == nil })
			a.mu.Lock()
			s.task.State = "active"
			run := s.claude
			a.mu.Unlock()
			if err := a.control(s.ID, action, ""); err != nil {
				t.Fatal(err)
			}
			<-run.done
			waitLifecycle(t, func() bool { a.mu.Lock(); defer a.mu.Unlock(); return s.claude == nil })
			a.mu.Lock()
			if s.requests["original"] != "unknown" || s.Status != "unknown" || s.providerFinal || queueEntry(s, "original").Status != "unknown" {
				t.Errorf("cancel without final escaped quarantine: request=%s status=%s final=%v input=%s", s.requests["original"], s.Status, s.providerFinal, queueEntry(s, "original").Status)
			}
			a.mu.Unlock()
			// Repeated controls must not hide the durable unknown receipt.
			_ = a.control(s.ID, action, "")
			if err := a.control(s.ID, "resume", ""); err == nil {
				t.Error("cancelled unresolved turn resumed")
			}
			a.mu.Lock()
			if len(s.requestOrder) != 1 {
				t.Error("resume minted another request")
			}
			a.mu.Unlock()
			a.close()
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.close()
			if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" {
				t.Fatal("restart forgot unresolved request after repeated control")
			}
			if entry := queueEntry(restored.sessions[0], "original"); entry == nil || entry.Status != "unknown" {
				t.Fatal("restart lost uncertain attachment owner")
			}
			if data, err := os.ReadFile(snapshot); err != nil || string(data) != "retained fixture input" {
				t.Fatal("uncertain cancellation discarded attachment", err)
			}
			if err := restored.control(s.ID, "resume", ""); err == nil {
				t.Fatal("restored unresolved writer resumed")
			}
			data, _ := os.ReadFile(audit)
			if bytes.Count(data, []byte(`"type":"user"`)) != 1 {
				t.Fatal("uncertain turn dispatched more than once", string(data))
			}
		})
	}
}

func TestClaudeLifecycleDurableFinalAllowsResume(t *testing.T) {
	for _, action := range []string{"pause", "stop"} {
		t.Run(action, func(t *testing.T) {
			a, s, _, audit := lifecycleSession(t, "final")
			if err := a.send(s.ID, "original", "bounded request", nil, false); err != nil {
				t.Fatal(err)
			}
			waitIdentityState(t, a, s, "original", "final")
			a.mu.Lock()
			s.task.State = "active"
			s.Supervision.RemainingBursts = 0
			run := s.claude
			a.mu.Unlock()
			if err := a.control(s.ID, action, ""); err != nil {
				t.Fatal(err)
			}
			<-run.done
			if err := a.control(s.ID, "resume", ""); err != nil {
				t.Fatal("durable final could not resume", err)
			}
			waitLifecycle(t, func() bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				return len(s.requestOrder) == 2 && s.requests[s.lastRequest] == "final"
			})
			a.mu.Lock()
			s.Supervision.State = "paused"
			if !s.providerFinal || s.requests["original"] != "final" {
				t.Error("confirmed final downgraded on exit")
			}
			a.mu.Unlock()
			data, _ := os.ReadFile(audit)
			lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
			if len(lines) != 2 || !bytes.Contains(lines[1], []byte("--resume")) {
				t.Fatal("durable continuation did not resume exactly once", string(data))
			}
			assertIdentityFinalReceipts(t, a, "original", 1)
		})
	}
}

func TestClaudeLifecycleSchedulerRequiresFinal(t *testing.T) {
	for _, source := range []string{"resume", "review", "progress"} {
		t.Run(source, func(t *testing.T) {
			a, s, _ := checkpointFixture(t)
			s.Provider = "claude"
			s.task.State = "active"
			s.Status = "idle"
			s.Supervision.State = "active"
			s.Supervision.progress = 1
			s.resumeRequested = source == "resume"
			if source == "review" {
				s.pendingReviewResult = "advisory result"
			}
			calls := 0
			a.runtime = func(string, string) (string, []string, error) {
				calls++
				return "", nil, errors.New("must not reach runtime")
			}
			a.scheduleInputs(s.ID)
			if calls != 0 || len(s.requestOrder) != 0 || s.Supervision.RemainingBursts != 3 {
				t.Fatal("unfinalized continuation consumed dispatch authority", calls, s.requestOrder, s.Supervision.RemainingBursts)
			}
		})
	}
}

func TestClaudeLifecycleResumeBeforeExitRequiresFinal(t *testing.T) {
	for _, state := range []string{"intent", "accepted"} {
		t.Run(state, func(t *testing.T) {
			a, s, _, _ := lifecycleReaderSession(t)
			s.requests["active"] = state
			s.Status = "paused"
			s.Supervision.State = "paused"
			s.task = &trackedTask{ID: "lifecycle-task", State: "active", Generation: 1}
			calls := 0
			a.runtime = func(string, string) (string, []string, error) {
				calls++
				return "", nil, errors.New("must not reach runtime")
			}
			if err := a.control(s.ID, "resume", ""); err == nil {
				t.Error("unfinished paused process resumed before exit")
			}
			if calls != 0 || len(s.requestOrder) != 0 || s.resumeRequested || s.Status != "paused" {
				t.Fatal("premature resume changed dispatch authority")
			}
		})
	}
}

func TestClaudeLifecycleOrdinarySendRequiresPriorOutcome(t *testing.T) {
	for _, phase := range []string{"initial", "after-runtime"} {
		for _, state := range []string{"intent", "accepted", "unknown"} {
			t.Run(phase+"-"+state, func(t *testing.T) {
				a, s, run, _ := lifecycleReaderSession(t)
				// A stopped process with unresolved tool effects is still not a
				// safe conversation to resume under a replacement user request.
				close(run.done)
				s.Status = "paused"
				s.Supervision.State = "paused"
				task := &trackedTask{ID: "blocked-task", State: "blocked", Generation: 1}
				s.task = task
				s.requests["active"] = state
				if phase == "after-runtime" {
					s.requests["active"] = "final"
				}
				calls := 0
				a.runtime = func(string, string) (string, []string, error) {
					calls++
					a.mu.Lock()
					s.requests["active"] = state
					a.mu.Unlock()
					return "/fixture/missing-claude", nil, nil
				}
				if err := a.send(s.ID, "replacement", "new ordinary objective", nil, false); err == nil {
					t.Error("unresolved ordinary send accepted")
				}
				wantCalls := 0
				if phase == "after-runtime" {
					wantCalls = 1
				}
				if calls != wantCalls || s.lastRequest != "active" || len(s.requestOrder) != 0 || s.task != task {
					t.Fatalf("ordinary send replaced unresolved authority: runtime=%d last=%s requests=%v sameTask=%v", calls, s.lastRequest, s.requestOrder, s.task == task)
				}
			})
		}
	}
}

func TestClaudeLifecycleOrdinarySendAllowsFreshFinalAndRejected(t *testing.T) {
	for _, state := range []string{"fresh", "final", "rejected"} {
		t.Run(state, func(t *testing.T) {
			a, s, _, _ := lifecycleReaderSession(t)
			s.Status = "paused"
			s.task = &trackedTask{ID: "prior-task", State: "blocked", Generation: 1}
			s.requests["active"] = state
			if state == "fresh" {
				s.lastRequest = ""
			}
			calls := 0
			control := errors.New("positive control reached runtime")
			a.runtime = func(string, string) (string, []string, error) { calls++; return "", nil, control }
			if err := a.send(s.ID, "replacement", "new ordinary objective", nil, false); calls != 1 || !errors.Is(err, control) {
				t.Fatal("valid ordinary request did not reach runtime", state, calls, err)
			}
		})
	}
}

func TestClaudeLifecycleResultThenPermissionDoesNotStallQueue(t *testing.T) {
	a, s, _, audit := lifecycleSession(t, "final-control")
	gate := filepath.Join(t.TempDir(), "release-result")
	runtime := a.runtime
	a.runtime = func(provider, profile string) (string, []string, error) {
		binary, env, err := runtime(provider, profile)
		return binary, append(env, "HARNESS_CONSOLE_LIFECYCLE_GATE="+gate), err
	}
	if err := a.send(s.ID, "original", "bounded request", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.enqueueInput(s.ID, "followup", "queued continuation", nil); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.Supervision.RemainingBursts = 0
	a.mu.Unlock()
	if err := os.WriteFile(gate, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	waitIdentityState(t, a, s, "followup", "final")
	waitLifecycle(t, func() bool {
		data, _ := os.ReadFile(audit)
		return bytes.Count(data, []byte(`"subtype":"error"`)) == 2
	})
	a.mu.Lock()
	if len(s.PendingQuestions) != 0 || s.Status != "idle" || len(s.requestOrder) != 2 || queueEntry(s, "followup").DeliveredInputRevision != 2 {
		t.Error("post-final permission stalled or duplicated queued continuation")
	}
	s.Supervision.State = "paused"
	a.mu.Unlock()
	data, _ := os.ReadFile(audit)
	if bytes.Count(data, []byte(`"type":"user"`)) != 2 || !bytes.Contains(data, []byte("--resume")) {
		t.Fatal("wrong continuation frames", string(data))
	}
}

func TestClaudeLifecycleControlPreservesRecoveryReceipt(t *testing.T) {
	for _, state := range []string{"accepted", "final", "unknown"} {
		t.Run(state, func(t *testing.T) {
			a, s, _, _ := lifecycleReaderSession(t)
			s.requests["active"] = state
			s.providerFinal = state == "final"
			if err := a.record(s, "active", state); err != nil {
				t.Fatal(err)
			}
			// No exit goroutine runs for this fake process: emulate restart in
			// the interval after cancellation but before an exit receipt.
			if err := a.control(s.ID, "pause", ""); err != nil {
				t.Fatal(err)
			}
			if err := a.control(s.ID, "stop", ""); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Dir(a.journal.Name())
			a.close()
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.close()
			want := "unknown"
			if state == "final" {
				want = "disconnected"
			}
			if len(restored.sessions) != 1 || restored.sessions[0].Status != want {
				t.Fatal("control masked request recovery state", state)
			}
		})
	}
}

type lifecycleSink struct{ writes chan []byte }

func (s *lifecycleSink) Write(p []byte) (int, error) {
	s.writes <- append([]byte(nil), p...)
	return len(p), nil
}
func (s *lifecycleSink) Close() error { return nil }

type lifecycleBlockedSink struct {
	*lifecycleSink
	entered chan struct{}
	release chan struct{}
}

func (s *lifecycleBlockedSink) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("fixture-block")) {
		close(s.entered)
		<-s.release
		return len(p), nil
	}
	return s.lifecycleSink.Write(p)
}

func lifecycleReaderSession(t *testing.T) (*app, *session, *claudeRun, *lifecycleSink) {
	t.Helper()
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	s.ProviderID = "lifecycle-conversation"
	s.lastRequest = "active"
	s.requests["active"] = "accepted"
	s.Status = "running"
	s.Supervision.State = "active"
	sink := &lifecycleSink{writes: make(chan []byte, 32)}
	run := &claudeRun{input: sink, done: make(chan struct{}), requestID: "active"}
	s.claude = run
	a.sessions = append(a.sessions, s)
	return a, s, run, sink
}

const lifecycleQuestion = `{"type":"control_request","request_id":"permission","request":{"subtype":"can_use_tool","tool_name":"Read","input":{"file_path":"fixture.txt"}}}` + "\n"

func TestClaudeLifecycleTerminalFramesCannotReopen(t *testing.T) {
	for _, terminal := range []string{"final", "unknown"} {
		t.Run(terminal, func(t *testing.T) {
			a, s, run, sink := lifecycleReaderSession(t)
			if terminal == "final" {
				a.readClaude(s, run, strings.NewReader(`{"type":"result","result":"finished"}`+"\n"))
			} else {
				a.unknownSend(s, "active", errors.New("controlled unknown"))
			}
			a.mu.Lock()
			before, status, supervision := len(s.Messages), s.Status, s.Supervision
			a.mu.Unlock()
			a.readClaude(s, run, strings.NewReader(lifecycleQuestion+`{"type":"assistant","message":{"id":"late","content":[{"type":"text","text":"late content"},{"type":"tool_use","name":"Task","id":"late-tool"}]}}`+"\n"+`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"late delta"}}}`+"\n"+`{"type":"system","session_id":"late-session","model":"late-model"}`+"\n"))
			a.mu.Lock()
			if len(s.PendingQuestions) != 0 || len(s.Messages) != before || s.Status != status || s.Supervision != supervision || s.ProviderID != "lifecycle-conversation" || len(s.filters) != 0 {
				t.Error("terminal content/control changed session authority or visible state")
			}
			a.mu.Unlock()
			select {
			case data := <-sink.writes:
				if !bytes.Contains(data, []byte(`"subtype":"error"`)) {
					t.Error("terminal control was not denied", string(data))
				}
			case <-time.After(time.Second):
				t.Error("terminal permission was left awaiting a response")
			}
		})
	}
}

func TestClaudeLifecycleQueuedAnswerChecksActiveAuthority(t *testing.T) {
	for _, state := range []string{"intent", "accepted", "final", "unknown", "different-run"} {
		t.Run(state, func(t *testing.T) {
			a, s, run, sink := lifecycleReaderSession(t)
			a.readClaude(s, run, strings.NewReader(lifecycleQuestion))
			// A prior write holds the writer so the answer must queue after UI
			// selection. Change authority before that queued frame is admitted.
			blocker := &lifecycleBlockedSink{lifecycleSink: sink, entered: make(chan struct{}), release: make(chan struct{})}
			run.input = blocker
			blocked := make(chan error, 1)
			go func() { blocked <- run.write(map[string]any{"type": "fixture-block"}) }()
			<-blocker.entered
			done := make(chan error, 1)
			go func() { done <- a.answerQuestion(s.ID, "permission", "allow") }()
			waitLifecycle(t, func() bool { return len(run.writer.queue) == 1 })
			a.mu.Lock()
			s.requests["active"] = state
			if state == "different-run" {
				s.requests["active"] = "accepted"
				run.requestID = "other-request"
			}
			a.mu.Unlock()
			close(blocker.release)
			if err := <-blocked; err != nil {
				t.Fatal(err)
			}
			err := <-done
			if oneOf(state, "intent", "accepted") {
				if err != nil {
					t.Fatal("active permission rejected", err)
				}
				select {
				case <-sink.writes:
				default:
					t.Fatal("active answer never written")
				}
			} else {
				if !isDispatchRefused(err) {
					t.Error("terminal answer not refused", err)
				}
				select {
				case data := <-sink.writes:
					t.Error("terminal answer wrote bytes", string(data))
				default:
				}
			}
		})
	}
}

type lifecycleErrorReader struct{}

func (lifecycleErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestClaudeLifecycleTerminalStreamFailureCannotDowngrade(t *testing.T) {
	for _, terminal := range []string{"final", "unknown"} {
		for _, oversized := range []bool{false, true} {
			t.Run(terminal+map[bool]string{false: "-error", true: "-oversized"}[oversized], func(t *testing.T) {
				a, s, run, _ := lifecycleReaderSession(t)
				s.requests["active"] = terminal
				s.providerFinal = terminal == "final"
				s.Status = terminal
				var reader io.Reader = lifecycleErrorReader{}
				if oversized {
					reader = strings.NewReader(strings.Repeat("x", (2<<20)+1))
				}
				a.readClaude(s, run, reader)
				if s.Status != terminal || s.requests["active"] != terminal || s.providerFinal != (terminal == "final") {
					t.Fatal("terminal stream error downgraded request", s.Status)
				}
			})
		}
	}
}
