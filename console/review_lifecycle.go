package main

import (
	"context"
	"time"
)

func (a *app) reviewAdmission(parent *session, task *trackedTask, review *session) inputAdmission {
	return func() (func(), error) {
		parent.dispatchMu.Lock()
		a.mu.Lock()
		valid := parent.task == task && parent.controlEpoch == review.dispatchEpoch && parent.Supervision.State == "active" && task.ReviewStatus == "running" && task.InputRevision == review.reviewInputRevision && task.ObjectiveHash == review.reviewObjectiveHash
		a.mu.Unlock()
		if !valid {
			parent.dispatchMu.Unlock()
			return nil, refused("review admission revoked before dispatch")
		}
		return parent.dispatchMu.Unlock, nil
	}
}
func (a *app) cancelReview(review *session, reason string) {
	a.mu.Lock()
	if review.cancelRequested || review.providerFinal {
		a.mu.Unlock()
		return
	}
	review.cancelRequested = true
	review.Status = "unknown"
	review.Error = reason
	review.Supervision.State = "paused"
	a.revokeQuestionsLocked(review, "")
	client, turn, thread, run := review.codex, review.turnID, review.ProviderID, review.claude
	_ = a.record(review, review.lastRequest, "review_unknown")
	a.syncReviewAgentLocked(review)
	a.finishReviewLocked(review)
	a.changedLocked()
	a.mu.Unlock()
	if run != nil {
		run.cancel()
		select {
		case <-run.done:
		case <-time.After(3 * time.Second):
		}
		return
	}
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if turn == "" {
		var result struct {
			Data []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"data"`
		}
		if client.call(ctx, "thread/turns/list", map[string]any{"threadId": thread, "limit": 1, "sortDirection": "desc"}, &result) == nil && len(result.Data) > 0 {
			turn = result.Data[0].ID
		}
	}
	cancellation := "Cancellation unconfirmed; provider identity retained for reconciliation"
	if turn != "" && client.call(ctx, "turn/interrupt", map[string]any{"threadId": thread, "turnId": turn}, nil) == nil {
		cancellation = "Interrupt acknowledged; final review outcome remains unverified"
	}
	a.mu.Lock()
	review.Error = reason + ". " + cancellation
	a.syncReviewAgentLocked(review)
	_ = a.record(review, review.lastRequest, "review_unknown")
	a.changedLocked()
	a.mu.Unlock()
}
func (a *app) cancelParentReviews(parent *session) {
	a.mu.Lock()
	owned := []*session{}
	for _, r := range a.reviews {
		if r.reviewParent == parent.ID && (r.Status == "running" || r.Status == "waiting" || r.Status == "starting") {
			owned = append(owned, r)
		}
	}
	a.mu.Unlock()
	for _, r := range owned {
		a.cancelReview(r, "user paused owning session")
	}
}
func (a *app) managedReviewAdmission(review *session) inputAdmission {
	return func() (func(), error) {
		a.mu.Lock()
		parent := a.findLocked(review.reviewParent)
		a.mu.Unlock()
		if parent == nil {
			return nil, refused("review owner is unavailable")
		}
		parent.dispatchMu.Lock()
		a.mu.Lock()
		valid := parent.task != nil && parent.task.ID == review.reviewTaskID && parent.task.Generation == review.reviewGeneration && parent.task.InputRevision == review.reviewInputRevision && parent.task.ObjectiveHash == review.reviewObjectiveHash && parent.controlEpoch == review.dispatchEpoch && parent.Supervision.State == "active" && parent.task.ReviewStatus == "running" && review.Status == "running"
		a.mu.Unlock()
		if !valid {
			parent.dispatchMu.Unlock()
			return nil, refused("review owner revoked dispatch")
		}
		return parent.dispatchMu.Unlock, nil
	}
}

func (a *app) cancelUnfinishedReview(review *session) {
	a.mu.Lock()
	unfinished := !review.providerFinal
	a.mu.Unlock()
	if unfinished {
		a.cancelReview(review, "review exited without a native final outcome")
	}
}

func (a *app) syncReviewAgentLocked(review *session) {
	if review.reviewParent == "" {
		return
	}
	for _, parent := range a.sessions {
		if parent.ID == review.reviewParent {
			for i := range parent.Agents {
				if parent.Agents[i].ID == review.ProviderID {
					child := &parent.Agents[i]
					child.Status = review.Status
					child.CanStop = !review.providerFinal && !review.Restored
					child.ControlReason = review.Error
					if review.Restored {
						child.CanPause, child.CanResume = false, false
						if !review.providerFinal {
							quarantineCodexChild(child)
						}
					}
				}
			}
		}
	}
}
