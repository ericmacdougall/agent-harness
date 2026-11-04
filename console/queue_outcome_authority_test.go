package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func failQueueOutcome(t *testing.T, a *app, postReplace bool) {
	t.Helper()
	if postReplace {
		postReplaceQueueFault(t, a)
	} else {
		a.writeInputs = func(string, []byte) error { return errors.New("injected pre-replacement refusal") }
	}
}

func outcomeReaderSession(t *testing.T) (*app, *session, *claudeRun, *lifecycleSink) {
	t.Helper()
	a, s, run, sink := lifecycleReaderSession(t)
	s.inputs = []*queuedInput{{RequestID: "active", Status: "dispatching", Text: "retained input", DeliveredInputRevision: 1}}
	if err := a.saveInputsLocked(s); err != nil {
		t.Fatal(err)
	}
	if err := a.record(s, "active", "accepted"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.writeOnce.Do(func() { run.writer = newInputWriter(run.input) }); run.writer.close() })
	return a, s, run, sink
}

func TestQueueOutcomeFailureRevokesPermissionAuthority(t *testing.T) {
	for _, postReplace := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-replacement", true: "after-replacement"}[postReplace], func(t *testing.T) {
			a, s, run, sink := outcomeReaderSession(t)
			// Hold the original user write while the provider asks permission,
			// then fail only the accepted queue-outcome save (journal stays healthy).
			s.requests["active"] = "intent"
			run.requestID = ""
			s.policy, _ = defaultPolicy("claude", "", "main")
			a.runtime = func(string, string) (string, []string, error) { return "/fixture/claude", nil, nil }
			_, _, fingerprint, err := a.resolveRuntime(s.policy)
			if err != nil {
				t.Fatal(err)
			}
			run.cwd, run.runtimeHash, run.policy = s.CWD, fingerprint, s.policy
			blocker := &lifecycleBlockedSink{lifecycleSink: sink, entered: make(chan struct{}), release: make(chan struct{})}
			run.input = blocker
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(blocker.release) }) })
			done := make(chan error, 1)
			go func() { done <- a.sendClaude(s, "active", "fixture-block", s.CWD, "") }()
			select {
			case <-blocker.entered:
			case <-time.After(time.Second):
				t.Fatal("original user write never reached provider sink")
			}
			a.readClaude(s, run, strings.NewReader(lifecycleQuestion))
			if len(s.PendingQuestions) != 1 || s.Status != "waiting" {
				t.Fatal("control: active permission was not admitted")
			}
			failQueueOutcome(t, a, postReplace)
			release.Do(func() { close(blocker.release) })
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("original user write failed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("accepted outcome did not return")
			}
			a.mu.Lock()
			if s.requests["active"] != "unknown" || s.Status != "unknown" || len(s.PendingQuestions) != 0 || s.providerFinal {
				t.Error("queue failure left active request/question authority", s.requests["active"], s.Status, len(s.PendingQuestions))
			}
			if s.queueUncertain != postReplace {
				t.Error("pre/post replacement failure classification was lost")
			}
			a.mu.Unlock()
			if err := a.answerQuestion(s.ID, "permission", "allow"); err == nil {
				t.Error("old permission allowed after queue failure")
			}
			late := strings.Replace(lifecycleQuestion, `"permission"`, `"late-permission"`, 1)
			a.readClaude(s, run, strings.NewReader(late))
			if err := a.answerQuestion(s.ID, "late-permission", "allow"); err == nil {
				t.Error("late permission allowed after queue failure")
			}
			// Drain both revocation responses. Only error responses may reach the
			// local provider sink; a success/allow would authorize a tool effect.
			for i := 0; i < 2; i++ {
				select {
				case frame := <-sink.writes:
					if !bytes.Contains(frame, []byte(`"subtype":"error"`)) {
						t.Error("provider received successful permission/effect", string(frame))
					}
				case <-time.After(time.Second):
					t.Error("permission was not explicitly revoked")
				}
			}
			a.readClaude(s, run, strings.NewReader(`{"type":"result","result":"late final"}`+"\n"))
			a.mu.Lock()
			a.claudeUnfinishedLocked(s, run, "late exit")
			a.mu.Unlock()
			a.scheduleInputs(s.ID)
			if s.requests["active"] != "unknown" || s.Status != "unknown" || s.providerFinal || len(s.PendingQuestions) != 0 {
				t.Error("late provider events reopened unknown authority")
			}
			if err := a.send(s.ID, "active", "replay", nil, false); err == nil {
				t.Error("failed outcome replay was admitted")
			}
			if err := a.control(s.ID, "resume", ""); err == nil {
				t.Error("failed outcome resumed")
			}
			data, err := os.ReadFile(a.journal.Name())
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
			if !bytes.Contains(lines[len(lines)-1], []byte(`"state":"unknown"`)) {
				t.Error("accepted callback did not preserve unknown journal receipt", string(lines[len(lines)-1]))
			}
			a.close()
			restored, err := newApp(a.dataDir, nil)
			if err != nil {
				t.Fatal("healthy journal/queue could not recover", err)
			}
			defer restored.close()
			if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" || !restored.sessions[0].Restored {
				t.Error("restart reopened failed outcome")
			}
		})
	}
}

func TestQueueOutcomeFailureAfterDurableFinalPreservesReceipt(t *testing.T) {
	for _, postReplace := range []bool{false, true} {
		for _, phase := range []string{"retained", "cleanup-intent", "cleanup-completion"} {
			name := map[bool]string{false: "before", true: "after"}[postReplace] + "-" + phase
			t.Run(name, func(t *testing.T) {
				a, s, run, _ := outcomeReaderSession(t)
				s.inputs[0].RetentionOnly = phase != "retained"
				failQueueOutcome(t, a, postReplace)
				if phase == "cleanup-completion" {
					fail := a.writeInputs
					writes := 0
					a.writeInputs = func(path string, data []byte) error {
						writes++
						if writes == 1 {
							return settingsAtomicWrite(path, data)
						}
						return fail(path, data)
					}
				}
				a.readClaude(s, run, strings.NewReader(`{"type":"result","result":"durable final"}`+"\n"))
				if s.requests["active"] != "final" || !s.providerFinal || s.Status != "unknown" {
					t.Fatal("attachment ownership failure corrupted provider finality", s.requests["active"], s.providerFinal, s.Status)
				}
				data, err := os.ReadFile(a.journal.Name())
				if err != nil || !bytes.Contains(data, []byte(`"state":"final"`)) || bytes.Contains(data, []byte(`"state":"unknown"`)) {
					t.Fatal("cleanup failure downgraded durable final journal", err, string(data))
				}
			})
		}
	}
}

func TestQueueOutcomeCodexAcceptedFailurePreservesUnknown(t *testing.T) {
	for _, postReplace := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[postReplace], func(t *testing.T) {
			a, s, c, bind, _ := identityHeldReply(t)
			a.mu.Lock()
			s.inputs = []*queuedInput{{RequestID: "B", Status: "dispatching", TaskID: s.task.ID, Generation: s.task.Generation, DeliveredInputRevision: 1}}
			if err := a.saveInputsLocked(s); err != nil {
				a.mu.Unlock()
				t.Fatal(err)
			}
			failQueueOutcome(t, a, postReplace)
			a.mu.Unlock()
			bind()
			requireUnknownWithoutQuestions(t, a, s)
			identityEvent(a, c, "turn/completed", "turn-B")
			requireUnknownWithoutQuestions(t, a, s)
			data, err := os.ReadFile(a.journal.Name())
			if err != nil || !bytes.Contains(data, []byte(`"state":"unknown"`)) || bytes.Contains(data, []byte(`"state":"accepted"`)) {
				t.Fatal("accepted callback did not preserve unknown receipt", err, string(data))
			}
		})
	}
}

func TestQueueOutcomeLifecycleRejectsIncomingQuestions(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, state := range []string{"queue-uncertain", "unknown", "blocked"} {
			t.Run(provider+"-"+state, func(t *testing.T) {
				var a *app
				var s *session
				var receive func()
				var denied func()
				if provider == "claude" {
					var run *claudeRun
					var sink *lifecycleSink
					a, s, run, sink = lifecycleReaderSession(t)
					receive = func() { a.readClaude(s, run, strings.NewReader(lifecycleQuestion)) }
					denied = func() {
						select {
						case frame := <-sink.writes:
							if !bytes.Contains(frame, []byte(`"subtype":"error"`)) {
								t.Error("permission not denied", string(frame))
							}
						case <-time.After(time.Second):
							t.Error("permission not rejected")
						}
					}
				} else {
					var c *rpcClient
					var bind func()
					var answers <-chan rpcPacket
					a, s, c, bind, answers = identityHeldReply(t)
					bind()
					receive = func() {
						params, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turnId": "turn-B"})
						a.codexQuestion(c, rpcPacket{ID: json.RawMessage("20"), Method: "item/commandExecution/requestApproval", Params: params})
					}
					denied = func() {
						select {
						case packet := <-answers:
							if packet.Error == nil || len(packet.Result) != 0 {
								t.Error("permission not denied", packet)
							}
						case <-time.After(time.Second):
							t.Error("permission not rejected")
						}
					}
				}
				a.mu.Lock()
				switch state {
				case "queue-uncertain":
					s.queueUncertain = true
				case "unknown":
					s.Status = "unknown"
				case "blocked":
					s.Supervision.State = "blocked"
				}
				beforeStatus, beforeSupervision := s.Status, s.Supervision
				a.mu.Unlock()
				receive()
				denied()
				if len(s.PendingQuestions) != 0 || s.Status != beforeStatus || s.Supervision != beforeSupervision {
					t.Error("incoming permission reopened blocked lifecycle")
				}
				// Turn admission must independently reject the same lifecycle even
				// if a caller presents an otherwise runnable session.
				admit := a.turnAdmission(s, s.controlEpoch, s.lastRequest)
				if release, err := admit(); err == nil {
					release()
					t.Error("blocked turn admitted to native writer")
				}
			})
		}
	}
}
