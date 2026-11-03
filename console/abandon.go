package main

import (
	"errors"
	"strings"
)

// abandonedTurn is the user's explicit decision to stop tracking a turn with no
// native final. It is not a provider outcome: it carries no success, verdict or
// review pass, and it does not prove the provider stopped.
type abandonedTurn struct {
	RequestID string `json:"requestId"`
	Reason    string `json:"reason"`
	At        string `json:"at"`
}

const abandonedNotice = "You discarded this turn. Provider work may still finish; its output is ignored here."
const abandonReasonLimit = 500

// canAbandonLocked reports whether discard is on offer. Unknown status without an
// unresolved request is the case a lifecycle failure leaves behind, where the
// last receipt may be a real final that discard must not touch.
func canAbandonLocked(s *session) bool {
	if s.abandoned != nil || s.reviewParent != "" || s.queueUncertain || oneOf(s.Status, "starting", "running", "waiting") {
		return false
	}
	return requestUnresolved(s.requests[s.lastRequest]) || s.Status == "unknown"
}

func (a *app) abandonTurn(id, expectedRequest, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > abandonReasonLimit {
		return errors.New("a reason of up to 500 bytes is required to discard a turn")
	}
	a.mu.Lock()
	current := a.findLocked(id)
	a.mu.Unlock()
	if current == nil {
		return errors.New("session not found")
	}
	// Same order as control, so a queued write cannot pass admission mid-discard.
	current.dispatchMu.Lock()
	defer current.dispatchMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	// A lost response retries here. It succeeds without a second record and keeps
	// the first reason and timestamp.
	if current.abandoned != nil {
		if current.abandoned.RequestID == expectedRequest {
			return nil
		}
		return errors.New("this tab was already discarded for a different turn")
	}
	if current.lastRequest != expectedRequest {
		return errors.New("the turn changed since this was confirmed; check it and try again")
	}
	if current.queueUncertain {
		return queueUncertainError()
	}
	if oneOf(current.Status, "starting", "running", "waiting") {
		return errors.New("stop or pause this turn before discarding it")
	}
	if !canAbandonLocked(current) {
		return errors.New("this turn has a final outcome; there is nothing to discard")
	}

	// Apply under a.mu and roll back on failure, so the durable record carries the
	// post-discard task and nothing outside this lock sees a discard that failed.
	var oldTask trackedTask
	if current.task != nil {
		oldTask = *current.task
		if current.task.State != "complete" {
			current.task.State = "blocked"
			current.task.reviewing = false
			current.task.ReviewStatus = "invalidated"
		}
	}
	current.abandoned = &abandonedTurn{RequestID: expectedRequest, Reason: a.clean(reason), At: now()}
	if err := a.record(current, "", "abandoned"); err != nil {
		current.abandoned = nil
		if current.task != nil {
			*current.task = oldTask
		}
		return errors.New("could not save the discard; this turn is still unresolved")
	}

	state := current.requests[expectedRequest]
	unresolved := requestUnresolved(state)
	if unresolved {
		a.transitionRequestLocked(current, expectedRequest, "abandoned")
		current.providerFinal = false
	}
	current.Restored = true
	current.controlEpoch++
	current.resumeRequested = false
	current.Status = "abandoned"
	current.Error = abandonedNotice
	current.Supervision.State = "paused"
	current.Supervision.Reason = abandonedNotice
	a.revokeQuestionsLocked(current, "")
	for i := range current.Agents {
		child := &current.Agents[i]
		if !oneOf(child.Status, "completed", "failed", "interrupted") {
			quarantineCodexChild(child)
			child.ControlReason = "Parent turn was discarded. " + nativeChildResumeReason
		}
	}
	// The entry for this turn would otherwise stay dispatching, which nothing can
	// discard or close until a restart.
	if entry := queueEntry(current, expectedRequest); entry != nil && entry.Status == "dispatching" {
		entry.Status = "unknown"
		entry.Reason = "Turn discarded with no final outcome; discard this local payload when you are done with it"
	}
	current.delivery = nil
	a.holdInputsLocked(current, "Turn discarded; copy into a new session, never automatic replay")

	run, client, binding, turn := current.claude, current.codex, current.codexTurn, current.turnID
	current.claude, current.codex = nil, nil
	if run != nil {
		go run.cancel()
	}
	if client != nil {
		if turn != "" {
			go a.interruptBoundTurn(current, client, expectedRequest, turn)
		} else if binding != nil && binding.turnID == "" {
			binding.interruptOnBind = true
		}
	}
	go a.cancelParentReviews(current)
	a.addMessageLocked(current, message{Role: "system", Text: abandonedNotice})
	a.changedLocked()
	return nil
}
