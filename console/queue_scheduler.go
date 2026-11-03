package main

import (
	"errors"
	"os"
	"strings"
)

func (a *app) holdInputsLocked(s *session, reason string) {
	for _, entry := range s.inputs {
		if oneOf(entry.Status, "queued", "held") {
			entry.Status = "held"
			entry.Reason = reason
		}
	}
	if len(s.inputs) > 0 {
		if err := a.saveInputsLocked(s); err != nil {
			s.Error = "Could not persist held input state"
			s.Supervision.State = "blocked"
		}
	}
}
func (a *app) followupSnapshotsLocked(s *session, entry *queuedInput, policy resolvedPolicy, runtime string) ([]string, error) {
	if queueEntry(s, entry.RequestID) != entry || entry.TaskID != s.task.ID || entry.Generation != s.task.Generation || entry.DeliveredInputRevision != 0 {
		return nil, refused("queued task binding changed or delivery was already attempted")
	}
	canonical, canonicalErr := validCWD(s.CWD)
	if canonicalErr != nil || canonical != entry.CWD {
		return nil, refused("queued working directory was redirected")
	}
	info, err := os.Stat(s.CWD)
	if err != nil || entry.cwdInfo == nil || !os.SameFile(info, entry.cwdInfo) || s.CWD != entry.CWD {
		return nil, refused("queued working directory changed")
	}
	if entry.PolicyRevision != policy.Revision || entry.PolicyHash != policyHash(policy) || entry.RuntimeHash != "" && entry.RuntimeHash != runtime {
		return nil, refused("queued account/model/tools or settings changed")
	}
	// Validate the queue-owned immutable copies using the existing integrity checks.
	holder := &session{attachmentSnapshots: entry.Snapshots}
	paths := make([]string, 0, len(entry.Snapshots))
	for path := range entry.Snapshots {
		paths = append(paths, path)
	}
	return a.selectedAttachments(holder, paths)
}
func (a *app) scheduleInputs(id string) {
	a.mu.Lock()
	s := a.findLocked(id)
	if s == nil || s.scheduled || s.queueUncertain || s.Restored || s.Status != "idle" || s.task == nil {
		a.mu.Unlock()
		return
	}
	task := s.task
	if s.Supervision.State == "paused" || oneOf(task.ReviewStatus, "unknown", "invalidated", "paused") || oneOf(task.State, "complete", "blocked", "handoff") {
		a.holdInputsLocked(s, "Work is paused/terminal or review needs reconciliation")
		a.changedLocked()
		a.mu.Unlock()
		return
	}
	if task.reviewing || task.ReviewStatus == "running" {
		a.mu.Unlock()
		return
	}
	if task.ReviewStatus == "queued" {
		a.mu.Unlock()
		a.runReviews(s)
		return
	}
	var head *queuedInput
	for _, entry := range s.inputs {
		if pendingInput(entry) {
			head = entry
			break
		}
	}
	if head != nil && head.Status != "queued" {
		a.changedLocked()
		a.mu.Unlock()
		return
	}
	var text, request string
	binding := sendBinding{task.ID, s.controlEpoch}
	if head != nil {
		if !s.providerFinal {
			head.Status = "held"
			head.Reason = "Prior native turn finality is not established"
			_ = a.saveInputsLocked(s)
			a.changedLocked()
			a.mu.Unlock()
			return
		}
		text = head.Text
		request = head.RequestID
		if s.pendingReviewResult != "" {
			text = s.pendingReviewResult + "\nThis result is advisory for the previous objective: delivery of this user follow-up advances inputRevision and invalidates ALL prior gates. Reconcile findings and obtain fresh applicable review.\n\nUser follow-up:\n" + text
		}
		head.Status = "dispatching"
		head.Reason = "Preparing next-turn delivery"
		s.Supervision.State = "active"
	} else {
		if s.Supervision.State != "active" {
			a.mu.Unlock()
			return
		}
		if !s.providerFinal {
			s.Supervision.State = "waiting"
			s.Supervision.Reason = "Prior native turn finality is not established; reconcile before continuation"
			a.changedLocked()
			a.mu.Unlock()
			return
		}
		if s.resumeRequested {
			text = s.pendingReviewResult + "\nResume the authorized current objective from the last verified checkpoint. Reuse existing owners; obtain fresh applicable reviews before completion."
		} else if s.pendingReviewResult != "" {
			if s.Supervision.RemainingBursts <= 0 {
				s.Supervision.State = "waiting"
				s.Supervision.Reason = "Review finished; automatic continuation budget exhausted"
				a.changedLocked()
				a.mu.Unlock()
				return
			}
			text = s.pendingReviewResult
		} else {
			if task.State != "active" {
				s.Supervision.State = "idle"
				s.Supervision.Reason = "Turn finished; no active tracked checkpoint"
				a.changedLocked()
				a.mu.Unlock()
				return
			}
			if s.Supervision.RemainingBursts <= 0 || s.Supervision.progress <= s.Supervision.lastProgress {
				s.Supervision.State = "waiting"
				s.Supervision.Reason = "Continuation budget or progress guard reached"
				a.changedLocked()
				a.mu.Unlock()
				return
			}
			text = "Continue the next authorized step for the active tracked work. Reconcile existing owners, tests and review results. Honor user pause and update actual structured evidence."
		}
		if !s.resumeRequested {
			s.Supervision.RemainingBursts--
		}
		s.Supervision.lastProgress = s.Supervision.progress
		request = "continue-" + freshID()
	}
	s.scheduled = true
	reviewResult := s.pendingReviewResult
	a.changedLocked()
	a.mu.Unlock()
	err := a.sendInput(id, request, text, nil, true, head, binding)
	a.mu.Lock()
	s.scheduled = false
	if err == nil {
		s.resumeRequested = false
		if s.pendingReviewResult == reviewResult {
			s.pendingReviewResult = ""
		}
	}
	if err != nil && head != nil && head.Status == "dispatching" {
		if head.DeliveredInputRevision == 0 {
			head.Status = "held"
			head.Reason = "Delivery held: " + a.clean(publicError(err))
		} else {
			head.Status = "unknown"
			head.Reason = "Delivery outcome requires reconciliation; no replay"
		}
		_ = a.saveInputsLocked(s)
		a.changedLocked()
	}
	again := err == nil && s.Status == "idle"
	a.mu.Unlock()
	if again {
		go a.advance(id)
	}
}
func queuedTaskObjective(s *session, entry *queuedInput) (string, error) {
	text := s.task.objective + "\n\nUser follow-up:\n" + objectiveInput(entry.Text, entry.Snapshots)
	if len(text) > queueTextLimit || strings.TrimSpace(entry.Text) == "" {
		return "", errors.New("revised objective exceeds bound")
	}
	return text, nil
}
