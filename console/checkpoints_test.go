package main

import (
	"os"
	"path/filepath"
	"testing"
)

func checkpointFixture(t *testing.T) (*app, *session, checkpointInput) {
	t.Helper()
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	a, e := newApp(t.TempDir(), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.close)
	s := emptySession("codex", dir, "")
	s.Status = "idle"
	s.ProviderID = "test-provider"
	s.task = &trackedTask{ID: "task", Generation: 1, passes: map[string]string{}, attempts: map[string]int{}}
	ensureTaskAuthority(s.task)
	a.sessions = append(a.sessions, s)
	if e = os.WriteFile(filepath.Join(dir, "proof.txt"), []byte("bounded proof"), 0600); e != nil {
		t.Fatal(e)
	}
	return a, s, checkpointInput{TaskID: "task", Generation: 1, InputRevision: s.task.InputRevision, ObjectiveHash: s.task.ObjectiveHash, State: "needs_review", Stage: "plan_review", Kind: "artifact", Evidence: []string{"proof.txt"}, Scope: "small fixture"}
}
func TestCheckpointIdentityStagesAndDedup(t *testing.T) {
	a, s, input := checkpointFixture(t)
	bad := input
	bad.Generation = 2
	if a.checkpointUpdate(s.ID, bad) == nil {
		t.Fatal("stale generation accepted")
	}
	bad = input
	bad.Stage = "code_review"
	if a.checkpointUpdate(s.ID, bad) == nil {
		t.Fatal("stage skip accepted")
	}
	bad = input
	bad.State = "complete"
	if a.checkpointUpdate(s.ID, bad) == nil {
		t.Fatal("unreviewed completion accepted")
	}
	if err := a.checkpointUpdate(s.ID, input); err != nil {
		t.Fatal(err)
	}
	if err := a.checkpointUpdate(s.ID, input); err != nil {
		t.Fatal("identical duplicate not idempotent", err)
	}
	s.task.ReviewStatus = "blocked"
	s.task.lastBlocked = s.task.Subject.Digest
	if a.checkpointUpdate(s.ID, input) == nil {
		t.Fatal("unchanged repair accepted")
	}
}
func TestCheckpointSubjectDetectsEvidenceMutation(t *testing.T) {
	a, s, input := checkpointFixture(t)
	first, e := a.captureSubject(s.CWD, "artifact", "", input.Evidence)
	if e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(filepath.Join(s.CWD, "proof.txt"), []byte("different proof"), 0600)
	second, e := a.captureSubject(s.CWD, "artifact", "", input.Evidence)
	if e != nil {
		t.Fatal(e)
	}
	if first.Digest == second.Digest {
		t.Fatal("evidence mutation retained digest")
	}
	if _, e = a.captureSubject(s.CWD, "artifact", "", []string{"../foreign.txt"}); e == nil {
		t.Fatal("foreign evidence accepted")
	}
}
func TestManagedReviewerEventsPreferActualReviewSession(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	review := emptySession("codex", parent.CWD, "")
	review.ProviderID = "independent-review-thread"
	review.reviewParent = parent.ID
	review.reviewDone = make(chan struct{})
	done := review.reviewDone
	review.lastRequest = "review-request"
	review.requests[review.lastRequest] = "accepted"
	review.turnID = "turn"
	a.reviews = append(a.reviews, review)
	parent.Agents = append(parent.Agents, agent{ID: review.ProviderID, Role: "reviewer"})
	actual, child := a.sessionForThreadLocked(review.ProviderID)
	if actual != review || child != nil {
		t.Fatal("reviewer root routed into parent child slot")
	}
	a.codexEvent(nil, "turn/completed", []byte(`{"threadId":"independent-review-thread","turn":{"id":"turn","status":"completed"}}`))
	select {
	case <-done:
	default:
		t.Fatal("reviewer completion did not release review gate")
	}
	if parent.Status != "idle" {
		t.Fatal("reviewer changed parent session lifecycle")
	}
}
