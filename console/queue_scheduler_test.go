package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func queueNativeFixture(t *testing.T) (*app, *session) {
	t.Helper()
	a, base, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil
	}
	s, err := a.createSession("codex", base.CWD, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.send(s.ID, "original", "Original bounded objective", nil, false); err != nil {
		t.Fatal(err)
	}
	return a, s
}
func finishNativeQueueTurn(a *app, s *session) {
	data, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turn": map[string]any{"id": "fixture-turn", "status": "completed"}})
	a.codexEvent(s.codex, "turn/completed", data)
}
func TestQueueDispatchPreservesTaskAndInvalidatesOldReviewAtZeroBursts(t *testing.T) {
	a, s := queueNativeFixture(t)
	a.mu.Lock()
	task := s.task
	oldRevision := task.InputRevision
	oldHash := task.ObjectiveHash
	task.State = "active"
	task.passes["plan_review"] = "old-pass"
	task.passes["final_review"] = "old-pass"
	s.Supervision.RemainingBursts = 0
	a.mu.Unlock()
	q, err := a.enqueueInput(s.ID, "follow-up", "Add a user-requested validation rule", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	if task.InputRevision != oldRevision {
		t.Fatal("mere queue acceptance invalidated an in-flight review")
	}
	a.mu.Unlock()
	finishNativeQueueTurn(a, s)
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.task != task || task.Generation != 1 || task.InputRevision != oldRevision+1 || task.ObjectiveHash == oldHash {
		t.Fatal("follow-up replaced task or failed revision transition")
	}
	if len(task.passes) != 0 {
		t.Fatal("old passes survived changed input authority")
	}
	if !strings.Contains(task.objective, "Add a user-requested validation rule") {
		t.Fatal("revised objective lost actual user input")
	}
	if q.DeliveredInputRevision != task.InputRevision || q.Status != "retained" || s.Supervision.RemainingBursts != 0 {
		t.Fatal("queue delivery or burst accounting wrong", q.Status, s.Supervision)
	}
	prompt := reviewPrompt(task, "fixture")
	if !strings.Contains(prompt, "Add a user-requested validation rule") || !strings.Contains(prompt, task.ObjectiveHash) {
		t.Fatal("new reviewer did not receive revised objective")
	}
}
func TestQueueOldPassCannotCompleteUnchangedEvidence(t *testing.T) {
	a, s, input := checkpointFixture(t)
	base, err := a.captureSubject(s.CWD, input.Kind, input.Head, input.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	old := bindSubject(base, s.task)
	s.task.passes["final_review"] = old.Digest
	s.task.InputRevision++
	s.task.objective = "new objective at identical HEAD"
	s.task.ObjectiveHash = objectiveHash(s.task.objective)
	input.State = "complete"
	if a.checkpointUpdate(s.ID, input) == nil {
		t.Fatal("old authority checkpoint completed new objective")
	}
	input.InputRevision = s.task.InputRevision
	input.ObjectiveHash = s.task.ObjectiveHash
	if a.checkpointUpdate(s.ID, input) == nil {
		t.Fatal("unchanged evidence restored an old PASS")
	}
	verdict := reviewVerdict{TaskID: s.task.ID, Generation: s.task.Generation, InputRevision: old.InputRevision, ObjectiveHash: old.ObjectiveHash, Stage: s.task.Stage, Digest: old.Digest, Verdict: "PASS", Findings: []string{}}
	raw, _ := json.Marshal(verdict)
	if _, err = decodeReviewVerdict(string(raw), s.task); err == nil {
		t.Fatal("old input revision verdict accepted")
	}
}

func TestQueueReviewResultAndFollowupOneTurnFIFO(t *testing.T) {
	a, s := queueNativeFixture(t)
	q, err := a.enqueueInput(s.ID, "first", "First queued request", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.enqueueInput(s.ID, "second", "Second queued request", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.task.State = "active"
	s.task.ReviewStatus = "running"
	a.mu.Unlock()
	finishNativeQueueTurn(a, s)
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	if q.DeliveredInputRevision != 0 {
		t.Fatal("queue bypassed running review")
	}
	s.task.ReviewStatus = "passed"
	s.pendingReviewResult = "Actual independent plan_review PASS for OLD objective"
	a.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.scheduleInputs(s.ID) }()
	}
	wg.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	userMessages := 0
	combined := false
	for _, m := range s.Messages {
		if m.Role == "user" {
			userMessages++
			if strings.Contains(m.Text, "Actual independent") && strings.Contains(m.Text, "First queued request") {
				combined = true
			}
		}
	}
	if userMessages != 2 || !combined || s.inputs[1].DeliveredInputRevision != 0 {
		t.Fatal("review and queued input raced into duplicate/out-of-order turns")
	}
}
func TestQueueHeldHeadAndPauseWinBeforeWrite(t *testing.T) {
	a, s := queueNativeFixture(t)
	first, err := a.enqueueInput(s.ID, "first", "held first", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.enqueueInput(s.ID, "second", "later second", nil)
	if err != nil {
		t.Fatal(err)
	}
	finishNativeQueueTurn(a, s)
	a.mu.Lock()
	first.Status = "held"
	first.Reason = "Changed settings require explicit reconciliation"
	a.mu.Unlock()
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	if second.DeliveredInputRevision != 0 {
		t.Fatal("held FIFO head bypassed")
	}
	first.Status = "queued"
	oldTask := *s.task
	next := oldTask
	next.InputRevision++
	next.objective += "followup"
	next.ObjectiveHash = objectiveHash(next.objective)
	s.delivery = &queuedDelivery{entry: first, task: s.task, next: next, epoch: s.controlEpoch}
	s.Status = "running"
	s.lastRequest = first.RequestID
	admission := a.turnAdmission(s, s.controlEpoch, first.RequestID)
	s.controlEpoch++
	s.Supervision.State = "paused"
	a.mu.Unlock()
	if release, err := admission(); err == nil {
		release()
		t.Fatal("pause lost actual write admission race")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.task.InputRevision != oldTask.InputRevision || first.DeliveredInputRevision != 0 {
		t.Fatal("revoked dispatch advanced authority")
	}
}
func TestQueueAttachmentsSurviveAcceptanceAndParentFinality(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
	a, s := queueNativeFixture(t)
	source := filepath.Join(s.CWD, "input.txt")
	if err := os.WriteFile(source, []byte("delayed owner bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.selectAttachments(s.ID, []string{source}); err != nil {
		t.Fatal(err)
	}
	q, err := a.enqueueInput(s.ID, "with-file", "Read the selected file later", []string{source})
	if err != nil {
		t.Fatal(err)
	}
	path := q.Snapshots[source].Path
	finishNativeQueueTurn(a, s)
	a.scheduleInputs(s.ID)
	if _, err = os.ReadFile(path); err != nil {
		t.Fatal("acceptance removed delayed-consumer bytes", err)
	}
	finishNativeQueueTurn(a, s)
	if _, err = os.ReadFile(path); err != nil {
		t.Fatal("main finality removed delayed-owner bytes", err)
	}
	a.mu.Lock()
	q.Status = "unknown"
	s.Status = "unknown"
	a.mu.Unlock()
	if err = a.discardInput(s.ID, q.RequestID, false); err == nil {
		t.Fatal("ordinary cancel erased uncertain consumer snapshot")
	}
	if err = a.discardInput(s.ID, q.RequestID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("explicit local discard did not release snapshot")
	}
}

func TestQueueVerdictRejectsOlderObjectiveEvenAtSameSubjectDigest(t *testing.T) {
	task := &trackedTask{ID: "same-task", Generation: 1, InputRevision: 2, ObjectiveHash: "new-objective", Stage: "plan_review", Subject: reviewSubject{Digest: "identical-files"}}
	old := reviewVerdict{TaskID: task.ID, Generation: 1, InputRevision: 1, ObjectiveHash: "old-objective", Stage: task.Stage, Digest: task.Subject.Digest, Verdict: "PASS", Findings: []string{}}
	bytes, _ := json.Marshal(old)
	if _, err := decodeReviewVerdict(string(bytes), task); err == nil {
		t.Fatal("same-artifact older objective verdict accepted")
	}
}
func TestQueueUnknownReviewAndPolicyDriftNeverDispatch(t *testing.T) {
	for _, condition := range []string{"unknown-review", "policy-drift"} {
		t.Run(condition, func(t *testing.T) {
			a, s := queueNativeFixture(t)
			q, err := a.enqueueInput(s.ID, "followup", "Keep me until safe", nil)
			if err != nil {
				t.Fatal(err)
			}
			a.mu.Lock()
			if condition == "unknown-review" {
				s.task.ReviewStatus = "unknown"
			} else {
				q.PolicyRevision = "different-settings"
			}
			a.mu.Unlock()
			finishNativeQueueTurn(a, s)
			a.scheduleInputs(s.ID)
			a.mu.Lock()
			defer a.mu.Unlock()
			if q.DeliveredInputRevision != 0 || s.task.InputRevision != 1 || q.Status != "held" {
				t.Fatal("unknown/drift input dispatched", q.Status)
			}
		})
	}
}

func TestQueueClaudeStreamingFollowupPreservesNativeContextAndNewBinding(t *testing.T) {
	a, base, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	audit := filepath.Join(t.TempDir(), "frames.jsonl")
	gate := filepath.Join(t.TempDir(), "release")
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_CLAUDE_QUEUE_FIXTURE=1", "HARNESS_CONSOLE_CLAUDE_QUEUE_AUDIT="+audit, "HARNESS_CONSOLE_CLAUDE_QUEUE_GATE="+gate), nil
	}
	s, err := a.createSession("claude", base.CWD, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.send(s.ID, "original", "Initial Claude objective", nil, false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	nativeID := s.ProviderID
	taskID := s.task.ID
	status := s.Status
	s.Supervision.RemainingBursts = 0
	a.mu.Unlock()
	if status != "running" {
		t.Fatal("fixture failed to preserve actual busy input boundary", status)
	}
	if _, err = a.enqueueInput(s.ID, "followup", "Claude queued user request", nil); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(gate, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		done := s.task.InputRevision == 2 && s.Status == "idle"
		a.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.ProviderID != nativeID || s.task.ID != taskID || s.task.InputRevision != 2 || s.Supervision.RemainingBursts != 0 {
		t.Fatal("Claude followup changed native owner context or burst authority")
	}
	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "inputRevision=2") || !strings.Contains(lines[1], "Claude queued user request") || !strings.Contains(lines[1], "--resume") {
		t.Fatal("Claude did not receive exactly one new revision-bound frame", string(data))
	}
}

func TestQueueResumeAndFinalCallbackHaveOneDispatcher(t *testing.T) {
	a, s := queueNativeFixture(t)
	q, err := a.enqueueInput(s.ID, "followup", "Resume me once", nil)
	if err != nil {
		t.Fatal(err)
	}
	finishNativeQueueTurn(a, s)
	a.mu.Lock()
	s.Status = "paused"
	s.Supervision.State = "paused"
	q.Status = "held"
	q.Reason = "User paused; explicit Resume required"
	s.Supervision.RemainingBursts = 0
	a.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.control(s.ID, "resume", "") }()
	go func() { defer wg.Done(); a.scheduleInputs(s.ID) }()
	wg.Wait()
	a.mu.Lock()
	defer a.mu.Unlock()
	if q.DeliveredInputRevision != 2 || s.Supervision.RemainingBursts != 0 {
		t.Fatal("Resume lost or refilled explicit queue delivery")
	}
	count := 0
	for _, m := range s.Messages {
		if m.Role == "user" {
			count++
		}
	}
	if count != 2 {
		t.Fatal("Resume bypassed single scheduler", count)
	}
}
func TestQueueRetainedBytesCountTowardQuota(t *testing.T) {
	a, s := queueNativeFixture(t)
	first, err := a.enqueueInput(s.ID, "first", "retained input", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	first.Status = "retained"
	first.Snapshots = map[string]attachmentSnapshot{"prior": {Path: "not-read-by-quota-accounting", Size: queueAttachmentLimit}}
	a.mu.Unlock()
	source := filepath.Join(s.CWD, "one-byte.txt")
	if err = os.WriteFile(source, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.selectAttachments(s.ID, []string{source}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.enqueueInput(s.ID, "second", "Do not evict delayed consumers", []string{source}); err == nil {
		t.Fatal("retained bytes were excluded from attachment quota")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if first.Status != "retained" || len(first.Snapshots) != 1 {
		t.Fatal("quota pressure evicted retained consumer")
	}
}
