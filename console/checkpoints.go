package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type trackedTask struct {
	InputRevision uint64        `json:"inputRevision"`
	ObjectiveHash string        `json:"objectiveHash"`
	ID            string        `json:"id"`
	Generation    uint64        `json:"generation"`
	State         string        `json:"state"`
	Stage         string        `json:"stage"`
	Subject       reviewSubject `json:"subject"`
	ReviewStatus  string        `json:"reviewStatus"`
	Findings      string        `json:"findings,omitempty"`
	objective     string
	scope         string
	passes        map[string]string
	attempts      map[string]int
	reviewing     bool
	lastBlocked   string
	capability    string
	reviewPolicy  resolvedPolicy
}
type checkpointInput struct {
	InputRevision uint64   `json:"inputRevision"`
	ObjectiveHash string   `json:"objectiveHash"`
	SubjectRoot   string   `json:"subjectRoot,omitempty"`
	TaskID        string   `json:"taskId"`
	Generation    uint64   `json:"generation"`
	State         string   `json:"state"`
	Stage         string   `json:"stage"`
	Kind          string   `json:"kind"`
	Head          string   `json:"head"`
	Evidence      []string `json:"evidence"`
	Scope         string   `json:"scope"`
}

func checkpointTool() map[string]any {
	return map[string]any{"type": "function", "name": "harness_console_checkpoint", "description": "Track substantive work, request independent review and verified completion. Use the taskId/generation/inputRevision/objectiveHash from application context. Casual questions need no checkpoint. Review requires bounded real evidence. End your turn after needs_review; the console dispatches an independent reviewer.", "inputSchema": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"subjectRoot": map[string]any{"type": "string", "description": "Current cwd or a registered feature worktree of the same Git repository; leave empty for current cwd"}, "taskId": map[string]any{"type": "string"}, "generation": map[string]any{"type": "integer"}, "inputRevision": map[string]any{"type": "integer"}, "objectiveHash": map[string]any{"type": "string"}, "state": map[string]any{"type": "string", "enum": []string{"active", "needs_review", "complete", "blocked", "handoff"}}, "stage": map[string]any{"type": "string", "enum": []string{"plan_review", "code_review", "final_review"}}, "kind": map[string]any{"type": "string", "enum": []string{"code", "artifact"}}, "head": map[string]any{"type": "string"}, "evidence": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "scope": map[string]any{"type": "string"}}, "required": []string{"taskId", "generation", "inputRevision", "objectiveHash", "state", "stage", "kind", "head", "evidence", "scope"}}}
}
func (a *app) checkpointUpdate(id string, input checkpointInput) error {
	return a.checkpointUpdateGuarded(id, input, nil)
}

// Provider entry points supply an exact binding guard, checked at every mutation lock.
func (a *app) checkpointUpdateGuarded(id string, input checkpointInput, guard func(*session) bool) error {
	a.mu.Lock()
	current := a.findLocked(id)
	if current == nil || current.task == nil || (guard != nil && !guard(current)) {
		a.mu.Unlock()
		return errors.New("no admitted task")
	}
	task := current.task
	if task.ID != input.TaskID || task.Generation != input.Generation || task.InputRevision != input.InputRevision || task.ObjectiveHash != input.ObjectiveHash || current.reviewParent != "" {
		a.mu.Unlock()
		return errors.New("foreign, stale or recursive checkpoint")
	}
	if current.Supervision.State == "paused" {
		a.mu.Unlock()
		return errors.New("user paused work")
	}
	if task.ReviewStatus == "unknown" {
		a.mu.Unlock()
		return errors.New("prior review or checkpoint outcome is unknown; continue in a new session after reconciliation")
	}
	if len(input.Scope) > 2000 {
		a.mu.Unlock()
		return errors.New("scope exceeds checkpoint bound")
	}
	cwd := current.CWD
	provider, profile := current.Provider, current.ProfileID
	epoch := current.controlEpoch
	if input.State == "active" || input.State == "blocked" || input.State == "handoff" {
		task.State = input.State
		task.scope = input.Scope
		current.Supervision.State = input.State
		current.Supervision.Reason = input.Scope
		recordErr := a.recordCheckpoint(current)
		a.changedLocked()
		a.mu.Unlock()
		return recordErr
	}
	a.mu.Unlock()
	if input.State != "needs_review" && input.State != "complete" {
		return errors.New("invalid checkpoint state")
	}
	if !oneOf(input.Stage, "plan_review", "code_review", "final_review") {
		return errors.New("invalid review stage")
	}
	root, err := allowedSubjectRoot(cwd, input.SubjectRoot)
	if err != nil {
		return err
	}
	subject, err := a.captureSubject(root, input.Kind, input.Head, input.Evidence)
	if err != nil {
		return err
	}
	policy, err := a.policyFor(provider, profile, input.Stage)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if (guard != nil && !guard(current)) || current.task != task || task.Generation != input.Generation || task.InputRevision != input.InputRevision || task.ObjectiveHash != input.ObjectiveHash || current.controlEpoch != epoch || current.CWD != cwd || current.Supervision.State == "paused" {
		return errors.New("task changed during capture")
	}
	if task.ReviewStatus == "unknown" {
		return errors.New("prior review or checkpoint outcome became unknown during capture")
	}
	subject = bindSubject(subject, task)
	if input.State == "complete" {
		if task.passes["final_review"] != subject.Digest {
			return errors.New("final review has not passed this exact subject")
		}
		task.State = "complete"
		current.Supervision.State = "complete"
		current.Supervision.Reason = "Independent final gate passed"
		err := a.recordCheckpoint(current)
		a.changedLocked()
		return err
	}
	if task.reviewing || task.ReviewStatus == "queued" {
		if task.Stage == input.Stage && task.Subject.Digest == subject.Digest {
			return nil
		}
		return errors.New("a review is already queued")
	}
	if input.Stage != "plan_review" && task.passes["plan_review"] == "" {
		return errors.New("plan review must pass first")
	}
	if input.Stage == "final_review" && input.Kind == "code" && task.passes["code_review"] != subject.Digest {
		return errors.New("code review must pass this subject first")
	}
	if task.lastBlocked == subject.Digest {
		return errors.New("repair must change subject/evidence before another review")
	}
	if task.attempts[attemptKey(task, input.Stage)] >= 3 {
		return errors.New("two repair rounds exhausted; main agent must judge rescue or pause")
	}
	task.State = "needs_review"
	task.Stage = input.Stage
	task.Subject = subject
	task.scope = input.Scope
	task.ReviewStatus = "queued"
	task.reviewPolicy = policy
	current.Supervision.State = "active"
	current.Supervision.Reason = "Independent " + input.Stage + " queued"
	err = a.recordCheckpoint(current)
	a.changedLocked()
	return err
}
func (a *app) recordCheckpoint(s *session) error {
	err := a.record(s, "", "checkpoint:"+s.task.State+":"+s.task.Stage+":"+s.task.ID+":"+fmt.Sprint(s.task.Generation))
	if err != nil {
		// record does not distinguish a pre-write refusal from a partial write
		// or failed sync. Conservatively quarantine every failure; a retry
		// must never acknowledge tentative state or dispatch it as durable.
		// Revoke admissions already resolving policy or awaiting review.
		s.controlEpoch++
		s.task.State = "unknown"
		s.task.ReviewStatus = "unknown"
		s.task.reviewing = false
		s.task.passes = map[string]string{}
		s.Supervision.State = "blocked"
		s.Supervision.Reason = "Checkpoint persistence is unconfirmed; reconcile in a new session, no replay"
		s.pendingReviewResult = ""
	}
	return err
}
func checkpointMetadata(task *trackedTask) string {
	return fmt.Sprintf("Current console taskId=%s generation=%d inputRevision=%d objectiveHash=%s. For substantive work use harness_console_checkpoint. Request plan_review before implementation, code_review after tests/commit, and final_review before complete. End turn after needs_review and await review findings. Tiny reversible fixes and casual chat need no checkpoint. Never claim a review that has not actually run.", task.ID, task.Generation, task.InputRevision, task.ObjectiveHash)
}
func parseCheckpoint(raw any) (checkpointInput, error) {
	var input checkpointInput
	b, e := json.Marshal(raw)
	if e != nil {
		return input, e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	e = d.Decode(&input)
	return input, e
}
