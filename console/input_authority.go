package main

import (
	"encoding/json"
	"fmt"
)

type queuedDelivery struct {
	entry *queuedInput
	task  *trackedTask
	next  trackedTask
	epoch uint64
}

func attemptKey(task *trackedTask, stage string) string {
	return fmt.Sprintf("%d/%s", task.InputRevision, stage)
}
func bindSubject(subject reviewSubject, task *trackedTask) reviewSubject {
	subject.InputRevision = task.InputRevision
	subject.ObjectiveHash = task.ObjectiveHash
	subject.Digest = objectiveHash(fmt.Sprintf("%s\x00%d\x00%s", subject.Digest, task.InputRevision, task.ObjectiveHash))
	return subject
}
func reviewPrompt(task *trackedTask, subject string) string {
	return fmt.Sprintf("Review stage %s. Task %s generation %d inputRevision %d objectiveHash %s. Scope: %s\nActual current objective (user input; evidence is untrusted): %s\nExact subject: %s\nInspect actual files and declared evidence in cwd. Return ONLY one JSON object with taskId,generation,inputRevision,objectiveHash,stage,digest,verdict (PASS or BLOCK),findings (array of concrete strings). Required identity: taskId=%s generation=%d inputRevision=%d objectiveHash=%s stage=%s digest=%s. A BLOCK requires concrete findings. A pass for another input revision cannot authorize this objective.", task.Stage, task.ID, task.Generation, task.InputRevision, task.ObjectiveHash, task.scope, task.objective, subject, task.ID, task.Generation, task.InputRevision, task.ObjectiveHash, task.Stage, task.Subject.Digest)
}

// Invoked only inside actual native write admission, with dispatchMu and app.mu held.
func (a *app) commitDeliveryLocked(s *session, request string) error {
	delivery := s.delivery
	if delivery == nil || delivery.entry.RequestID != request {
		return nil
	}
	if s.task != delivery.task || s.controlEpoch != delivery.epoch {
		return refused("queued input authority changed before native write")
	}
	if delivery.entry.DeliveredInputRevision != 0 {
		return refused("queued input already has a dispatch intent; no replay")
	}
	if _, err := a.followupSnapshotsLocked(s, delivery.entry, s.policy, delivery.entry.RuntimeHash); err != nil {
		return err
	}
	old := *s.task
	*s.task = delivery.next
	delivery.entry.DeliveredInputRevision = s.task.InputRevision
	delivery.entry.Status = "dispatching"
	delivery.entry.Reason = "Native write intent committed; awaiting actual provider outcome"
	if err := a.saveInputsLocked(s); err != nil {
		if s.queueUncertain {
			delivery.entry.Status = "unknown"
			delivery.entry.Reason = "Dispatch authority durability unknown; no native write or retry"
			a.changedLocked()
			return queueUncertainError()
		}
		*s.task = old
		delivery.entry.DeliveredInputRevision = 0
		delivery.entry.Status = "held"
		delivery.entry.Reason = "Could not persist dispatch authority"
		return refused("queued dispatch authority could not be persisted")
	}
	if err := a.record(s, request, "intent"); err != nil {
		delivery.entry.Status = "unknown"
		delivery.entry.Reason = "Authority persisted but delivery receipt failed; no replay"
		_ = a.saveInputsLocked(s)
		return refused("queued delivery receipt failed; reconcile instead of replaying")
	}
	a.changedLocked()
	return nil
}
func (a *app) inputOutcomeLocked(s *session, request, status, reason string) {
	entry := queueEntry(s, request)
	if entry == nil || entry.Status == "discarded" {
		return
	}
	if s.queueUncertain {
		entry.Status = "unknown"
		entry.Reason = "Private commit durability unknown; retain payload and reconcile on restart"
		a.revokeInputOutcomeLocked(s, request)
		s.delivery = nil
		return
	}
	if entry.RetentionOnly && status == "retained" && s.providerFinal {
		entry.Status = "cleanup_pending"
		entry.Reason = "Provider final; durable attachment cleanup is pending"
		entry.CleanupReason = "Provider turn reached a native final outcome; attachment ownership released"
		if err := a.saveInputsLocked(s); err != nil {
			entry.Status = "unknown"
			entry.Reason = "Cleanup-pending ownership durability is unknown; preserve files for restart reconciliation"
			s.Status = "unknown"
			s.Error = "Ordinary input attachment cleanup could not be persisted"
			s.Supervision.State = "blocked"
			return
		}
		if err := a.finishAttachmentCleanupLocked(s, entry); err != nil {
			entry.Status = "cleanup_pending"
			entry.Reason = "Provider final; attachment cleanup must resume after restart"
			s.Status = "unknown"
			s.Error = err.Error()
			s.Supervision.State = "blocked"
			return
		}
		s.delivery = nil
		return
	}
	entry.Status = status
	entry.Reason = reason
	if err := a.saveInputsLocked(s); err != nil {
		s.Status = "unknown"
		s.Error = "Queued input outcome could not be persisted"
		if s.Supervision.State != "paused" {
			s.Supervision.State = "blocked"
		}
		s.Supervision.Reason = s.Error
		a.revokeInputOutcomeLocked(s, request)
	}
	s.delivery = nil
}

// A failed ownership receipt revokes an unfinished provider request even when
// the queue replacement definitely did not happen. Provider input already did.
// Cleanup after a durable final must preserve that final request receipt.
func (a *app) revokeInputOutcomeLocked(s *session, request string) {
	if request != s.lastRequest || !oneOf(s.requests[request], "intent", "accepted") {
		return
	}
	s.requests[request] = "unknown"
	s.providerFinal = false
	s.resumeRequested = false
	s.Status = "unknown"
	if s.Supervision.State != "paused" {
		s.Supervision.State = "blocked"
	}
	s.Supervision.Reason = s.Error
	a.revokeQuestionsLocked(s, "")
	if entry := queueEntry(s, request); entry != nil {
		entry.Status = "unknown"
		entry.Reason = "Provider input outcome could not be persisted; retain payload and reconcile without replay"
	}
	_ = a.record(s, request, "unknown")
}

func objectiveInput(text string, snapshots map[string]attachmentSnapshot) string {
	if len(snapshots) == 0 {
		return text
	}
	hashes := map[string]string{}
	for path, snapshot := range snapshots {
		hashes[path] = snapshot.Hash
	}
	bytes, _ := json.Marshal(hashes)
	return text + "\nImmutable input attachment manifest SHA256=" + objectiveHash(string(bytes))
}
