package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Recovery promotion can change Reason before retiring the cleanup beforeimage.
// Both pending candidates must independently authorize exactly the same cleanup:
// compare all persisted identity, payload, outcome and snapshot-owner metadata,
// ignoring only the explanatory Reason (and the non-persisted cwdInfo).
func compatiblePendingCleanup(current, previous *queuedInput) bool {
	if current.Status != "cleanup_pending" || previous.Status != "cleanup_pending" ||
		current.RequestID != previous.RequestID || current.RequestHash != previous.RequestHash ||
		current.TaskID != previous.TaskID || current.Generation != previous.Generation ||
		current.RetentionOnly != previous.RetentionOnly || current.CleanupReason != previous.CleanupReason ||
		current.Text != previous.Text || current.PayloadHash != previous.PayloadHash ||
		current.QueuedAtInputRevision != previous.QueuedAtInputRevision || current.DeliveredInputRevision != previous.DeliveredInputRevision ||
		current.CreatedAt != previous.CreatedAt || current.CWD != previous.CWD ||
		current.PolicyRevision != previous.PolicyRevision || current.PolicyHash != previous.PolicyHash || current.RuntimeHash != previous.RuntimeHash ||
		len(current.Snapshots) != len(previous.Snapshots) {
		return false
	}
	for path, snapshot := range current.Snapshots {
		if prior, ok := previous.Snapshots[path]; !ok || prior != snapshot {
			return false
		}
	}
	return true
}

// compatibleCompletedCleanup recognizes only the exact durable transition made
// by finishAttachmentCleanupLocked. Every persisted identity, payload binding,
// revision and policy field must survive unchanged. Only the cleanup state and
// released snapshot owners may differ, and Reason must prove the same outcome.
func compatibleCompletedCleanup(current, previous *queuedInput) bool {
	if current.Status != "discarded" || previous.Status != "cleanup_pending" ||
		len(previous.Snapshots) == 0 || len(current.Snapshots) != 0 ||
		current.Text != "" || previous.Text != "" || current.CleanupReason != "" ||
		current.RequestID != previous.RequestID || current.RequestHash != previous.RequestHash ||
		current.TaskID != previous.TaskID || current.Generation != previous.Generation ||
		current.RetentionOnly != previous.RetentionOnly || current.PayloadHash != previous.PayloadHash ||
		current.QueuedAtInputRevision != previous.QueuedAtInputRevision || current.DeliveredInputRevision != previous.DeliveredInputRevision ||
		current.CreatedAt != previous.CreatedAt || current.CWD != previous.CWD ||
		current.PolicyRevision != previous.PolicyRevision || current.PolicyHash != previous.PolicyHash || current.RuntimeHash != previous.RuntimeHash {
		return false
	}
	outcome := previous.CleanupReason
	if outcome == "" {
		outcome = "Private attachment ownership released"
	}
	return current.Reason == outcome
}

// Merge only interrupted commits from this session. This never admits a provider
// writer: all recovered payload is held/unknown and requires explicit user action.
func mergeQueueCandidates(current, previous queueDisk) (queueDisk, error) {
	if current.SessionID != previous.SessionID {
		return current, errors.New("foreign queued input beforeimage")
	}
	chosen := current
	if chosen.TaskID == "" {
		chosen = previous
	}
	if current.TaskID != "" && previous.TaskID != "" {
		if current.TaskID != previous.TaskID || current.Generation != previous.Generation {
			return current, errors.New("conflicting active queued task candidates; preserve state")
		}
		if previous.InputRevision > current.InputRevision {
			chosen = previous
		}
		if previous.InputRevision == current.InputRevision && previous.ObjectiveHash != current.ObjectiveHash {
			return current, errors.New("conflicting queued objective candidates; preserve state")
		}
	}
	byID := map[string]*queuedInput{}
	cleanupAuthorized := map[string]bool{}
	order := []string{}
	for candidateIndex, disk := range []queueDisk{previous, current} {
		seen := map[string]bool{}
		for _, entry := range disk.Entries {
			if entry == nil || entry.RequestID == "" || seen[entry.RequestID] {
				return current, errors.New("invalid interrupted queue entry")
			}
			seen[entry.RequestID] = true
			prior := byID[entry.RequestID]
			if prior == nil {
				copy := *entry
				copy.Snapshots = map[string]attachmentSnapshot{}
				for path, snapshot := range entry.Snapshots {
					copy.Snapshots[path] = snapshot
				}
				byID[entry.RequestID] = &copy
				order = append(order, entry.RequestID)
				continue
			}
			if prior.TaskID != entry.TaskID || prior.Generation != entry.Generation || prior.RequestHash != entry.RequestHash {
				return current, errors.New("conflicting queued input identity; preserve state")
			}
			if prior.Text != "" && entry.Text != "" && prior.Text != entry.Text {
				return current, errors.New("conflicting queued payload; preserve state")
			}
			// Decide before merging payload or snapshot maps: a union of different
			// owners must not acquire either candidate's cleanup authorization.
			if candidateIndex == 1 && compatiblePendingCleanup(entry, prior) {
				cleanupAuthorized[entry.RequestID] = true
			}
			if prior.Text == "" {
				prior.Text = entry.Text
			}
			// Main discarded + beforeimage cleanup_pending is also a safe
			// interrupted-cleanup transition: unlink was authorized durably and
			// may already be complete. Retain the pending owner so idempotent,
			// confined cleanup can finish. The opposite direction remains unknown.
			if candidateIndex == 1 && compatibleCompletedCleanup(entry, prior) {
				cleanupAuthorized[entry.RequestID] = true
			}
			for path, snapshot := range entry.Snapshots {
				if old, ok := prior.Snapshots[path]; ok && old != snapshot {
					return current, errors.New("conflicting attachment candidates; preserve state")
				}
				prior.Snapshots[path] = snapshot
			}
			if entry.DeliveredInputRevision > prior.DeliveredInputRevision {
				prior.DeliveredInputRevision = entry.DeliveredInputRevision
			}
			if entry.Status != "discarded" {
				prior.Status = entry.Status
			}
		}
	}
	chosen.Entries = []*queuedInput{}
	for _, id := range order {
		entry := byID[id]
		if cleanupAuthorized[id] {
			entry.Status = "cleanup_pending"
			entry.Reason = "Interrupted cleanup completion; resume idempotent private cleanup, never provider replay"
		} else if entry.Text != "" || len(entry.Snapshots) > 0 || entry.Status != "discarded" {
			entry.Status = "unknown"
			entry.Reason = "Interrupted private commit; payload and snapshot owners retained, never replay automatically"
		}
		chosen.Entries = append(chosen.Entries, entry)
	}
	if len(chosen.Entries) > queueReceiptLimit {
		return current, errors.New("interrupted queue exceeds receipt bound")
	}
	return neutralQueue(chosen), nil
}

// Recovery already holds all validated candidates in memory. Never call the
// ordinary writer here: it rotates .previous from the possibly incomplete main
// and can destroy the sole original owner before the merged main is written.
func (a *app) promoteRecoveredInputs(s *session) error {
	data, err := json.Marshal(queueSnapshot(s))
	if err != nil || len(data) > 1<<20 {
		return errors.New("recovered queued input exceeds bound")
	}
	path := a.queuePath(s)
	write := a.writeInputs
	if write == nil {
		write = settingsAtomicWrite
	}
	if err = write(path, data); err != nil {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	// Establish actual file + namespace durability before retiring ANY candidate.
	// Readability by itself is not a durability proof.
	if err = settingsDurableReadback(path); err != nil {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	actual, err := settingsRead(path, 1<<20)
	if err != nil || settingsDigest(actual) != settingsDigest(data) {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	if err = os.Remove(path + ".previous"); err != nil && !os.IsNotExist(err) {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	if err = settingsSyncParent(filepath.Dir(path)); err != nil {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	return nil
}
