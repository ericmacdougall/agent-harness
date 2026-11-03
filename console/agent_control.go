package main

import (
	"context"
	"errors"
	"time"
)

const nativeChildResumeReason = "Direct child resume is unavailable without a verified child-context capability probe. Reconcile this owner's WAL, messages, branch/worktree, processes, and possible in-flight effects; confirm the old writer is quiescent; then dispatch one fresh owner in the current authenticated parent context. Replacement is pending and is not automatic."

func denyNativeChildResume(child *agent) {
	child.CanResume = false
	child.ControlReason = nativeChildResumeReason
}

func (a *app) controlAgent(parent *session, id, action string) error {
	parent.dispatchMu.Lock()
	released := false
	release := func() {
		if !released {
			released = true
			parent.dispatchMu.Unlock()
		}
	}
	defer release()
	a.mu.Lock()
	if parent.Restored {
		a.mu.Unlock()
		return errors.New("restored agents have no exclusive writer admission")
	}
	var selected *agent
	for i := range parent.Agents {
		if parent.Agents[i].ID == id {
			selected = &parent.Agents[i]
			break
		}
	}
	if selected == nil {
		a.mu.Unlock()
		return errors.New("agent is not owned by this session")
	}
	if action == "pause" || action == "stop" {
		parent.controlEpoch++
		parent.resumeRequested = false
		a.holdInputsLocked(parent, "User paused an owner; explicit Resume required")
		a.revokeQuestionsLocked(parent, id)
		selected.Status = "paused"
		a.changedLocked()
	}
	provider := selected.Provider
	client := parent.codex
	var review *session
	for _, candidate := range a.reviews {
		if candidate.reviewParent == parent.ID && candidate.ProviderID == id {
			review = candidate
			client = review.codex
			break
		}
	}
	if action == "resume" && review != nil {
		a.mu.Unlock()
		return errors.New("independent review must restart through a fresh validated gate")
	}
	if action == "resume" && provider != "claude" {
		denyNativeChildResume(selected)
		a.changedLocked()
		a.mu.Unlock()
		return errors.New(nativeChildResumeReason)
	}
	if provider == "claude" {
		if review != nil && review.claude != nil && (action == "pause" || action == "stop") {
			run := review.claude
			review.Status = "paused"
			a.finishReviewLocked(review)
			selected.Status = "paused"
			selected.CanStop = false
			a.changedLocked()
			a.mu.Unlock()
			release()
			run.cancel()
			return nil
		}
		a.mu.Unlock()
		return errors.New("this native Claude subagent has no independent control channel; control its owning main session")
	}
	if client == nil {
		a.mu.Unlock()
		return errors.New("agent connection unavailable")
	}
	a.mu.Unlock()
	release()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if action == "pause" || action == "stop" {
		var turns struct {
			Data []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := client.call(ctx, "thread/turns/list", map[string]any{"threadId": id, "limit": 1, "sortDirection": "desc"}, &turns); err != nil {
			return err
		}
		if len(turns.Data) == 0 {
			return errors.New("agent has no current turn")
		}
		if err := client.call(ctx, "turn/interrupt", map[string]any{"threadId": id, "turnId": turns.Data[0].ID}, nil); err != nil {
			return err
		}
	} else {
		return errors.New("unknown agent control")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range parent.Agents {
		if parent.Agents[i].ID == id {
			parent.Agents[i].Status = "paused"
		}
	}
	a.changedLocked()
	return nil
}
