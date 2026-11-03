package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

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
	cleanupCompleted := map[string]bool{}
	order := []string{}
	for candidateIndex, disk := range []queueDisk{previous, current} {
		for _, entry := range disk.Entries {
			if entry == nil || entry.RequestID == "" {
				return current, errors.New("invalid interrupted queue entry")
			}
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
			if prior.Text == "" {
				prior.Text = entry.Text
			}
			// Main discarded + beforeimage cleanup_pending is the one safe
			// interrupted-cleanup transition: unlink was authorized durably and
			// may already be complete. Retain the pending owner so idempotent,
			// confined cleanup can finish. The opposite direction remains unknown.
			if candidateIndex == 1 && prior.Status == "cleanup_pending" && entry.Status == "discarded" && entry.Text == "" && len(entry.Snapshots) == 0 {
				cleanupCompleted[entry.RequestID] = true
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
		if cleanupCompleted[id] {
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
