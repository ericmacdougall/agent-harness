package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQueueStoreDedupRetentionAndRecovery(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	s := emptySession("codex", cwd, "")
	s.ProviderID = "native"
	s.Status = "running"
	s.Supervision.State = "active"
	s.task = &trackedTask{ID: "objective", Generation: 1, State: "active", objective: "original", passes: map[string]string{}, attempts: map[string]int{}}
	ensureTaskAuthority(s.task)
	s.Work = s.task
	a.sessions = append(a.sessions, s)
	if err = a.record(s, "initial", "accepted"); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(s.CWD, "file.txt")
	if err = os.WriteFile(original, []byte("immutable queued bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.selectAttachments(s.ID, []string{original}); err != nil {
		t.Fatal(err)
	}
	entry, err := a.enqueueInput(s.ID, "queued", "private unsent payload", []string{original})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := entry.Snapshots[original].Path
	if _, err = a.enqueueInput(s.ID, "queued", "private unsent payload", []string{original}); err != nil {
		t.Fatal("retry was not idempotent", err)
	}
	if _, err = a.enqueueInput(s.ID, "queued", "changed payload", nil); err == nil {
		t.Fatal("same request ID accepted new contents")
	}
	if err = a.selectAttachments(s.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(snapshot); err != nil {
		t.Fatal("composer change removed queued consumer snapshot", err)
	}
	journal, _ := os.ReadFile(filepath.Join(dir, "sessions.jsonl"))
	if strings.Contains(string(journal), "private unsent payload") {
		t.Fatal("payload leaked to metadata journal")
	}
	state, _ := json.Marshal(a.state())
	if strings.Contains(string(state), "snapshots") || strings.Contains(string(state), "payloadHash") {
		t.Fatal("private store fields entered state")
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	recovered := restored.sessions[0]
	if len(recovered.inputs) != 1 || recovered.inputs[0].Status != "held" || !recovered.Restored {
		t.Fatal("restart failed to hold unsent input")
	}
	if recovered.inputs[0].Text != "private unsent payload" {
		t.Fatal("recovery lost accepted unsent input")
	}
	if err = restored.discardInput(recovered.ID, "queued", false); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(snapshot); !os.IsNotExist(err) {
		t.Fatal("cancelled private snapshot not released")
	}
}
func TestQueueBoundsAndHeldInputDoNotBypass(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	s.Status = "running"
	s.task.State = "active"
	s.Supervision.State = "active"
	for i := 0; i < 8; i++ {
		if _, err := a.enqueueInput(s.ID, string(rune('a'+i)), "small followup", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.enqueueInput(s.ID, "ninth", "preserve draft", nil); err == nil {
		t.Fatal("queue overflow accepted")
	}
	if s.task.Generation != 1 || s.task.InputRevision != 1 {
		t.Fatal("enqueue changed input authority")
	}
}

func TestQueueCrashAfterDispatchIntentIsUnknownAndNeverReplayed(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	s := emptySession("codex", cwd, "")
	s.ProviderID = "native"
	s.Status = "running"
	s.Supervision.State = "active"
	s.task = &trackedTask{ID: "task", Generation: 1, State: "active", objective: "initial", passes: map[string]string{}, attempts: map[string]int{}}
	ensureTaskAuthority(s.task)
	s.Work = s.task
	a.sessions = append(a.sessions, s)
	if err = a.record(s, "original", "accepted"); err != nil {
		t.Fatal(err)
	}
	q, err := a.enqueueInput(s.ID, "uncertain", "changed objective", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.task.InputRevision = 2
	s.task.objective += "\nchanged objective"
	s.task.ObjectiveHash = objectiveHash(s.task.objective)
	q.Status = "dispatching"
	q.DeliveredInputRevision = 2
	if err = a.saveInputsLocked(s); err == nil {
		err = a.record(s, q.RequestID, "intent")
	}
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	recovered := restored.sessions[0]
	if recovered.inputs[0].Status != "unknown" || recovered.task.InputRevision != 2 || !recovered.Restored {
		t.Fatal("dispatch intent lost unknown authority")
	}
	restored.scheduleInputs(recovered.ID)
	if recovered.inputs[0].DeliveredInputRevision != 2 || recovered.codex != nil {
		t.Fatal("restored delivery replayed")
	}
}
