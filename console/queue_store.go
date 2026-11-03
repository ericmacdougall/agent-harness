package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const queueTextLimit = 256 << 10
const queueAttachmentLimit = 16 << 20
const queueReceiptLimit = 256

type queueDisk struct {
	Schema        int            `json:"schema"`
	SessionID     string         `json:"sessionId"`
	TaskID        string         `json:"taskId"`
	Generation    uint64         `json:"generation"`
	InputRevision uint64         `json:"inputRevision"`
	ObjectiveHash string         `json:"objectiveHash"`
	Objective     string         `json:"objective"`
	Entries       []*queuedInput `json:"entries"`
}

// This bounded private payload file is deliberately separate from the metadata journal.
func (a *app) queuePath(s *session) string {
	return filepath.Join(a.dataDir, "queued-inputs", objectiveHash(s.ID)+".json")
}

var errQueueDurability = errors.New("queued input commit outcome is unknown")

func queueUncertainError() error {
	return errors.Join(errQueueDurability, errSettingsDurability, refused("private queued input durability is unknown; restart to reconcile; no replay"))
}
func (a *app) quarantineQueueLocked(s *session) {
	s.queueUncertain = true
	s.Status = "unknown"
	s.Error = "Private queued input commit is uncertain; restart to reconcile before further work"
	s.Supervision.State = "paused"
	s.Supervision.Reason = s.Error
	s.resumeRequested = false
	a.changedLocked()
}
func neutralQueue(disk queueDisk) queueDisk {
	for _, entry := range disk.Entries {
		if entry == nil || entry.Status != "discarded" || entry.Text != "" || len(entry.Snapshots) != 0 {
			return disk
		}
	}
	disk.TaskID = ""
	disk.Generation = 0
	disk.InputRevision = 0
	disk.ObjectiveHash = ""
	disk.Objective = ""
	return disk
}
func queueSnapshot(s *session) queueDisk {
	disk := queueDisk{Schema: 1, SessionID: s.ID, Entries: s.inputs}
	if s.task != nil {
		disk.TaskID = s.task.ID
		disk.Generation = s.task.Generation
		disk.InputRevision = s.task.InputRevision
		disk.ObjectiveHash = s.task.ObjectiveHash
		disk.Objective = s.task.objective
	}
	return neutralQueue(disk)
}
func (a *app) saveInputsLocked(s *session) error {
	if s.queueUncertain {
		return queueUncertainError()
	}
	path := a.queuePath(s)
	dir := filepath.Dir(path)
	if err := settingsPrivateDirectory(dir); err != nil {
		return errors.New("private input directory unavailable")
	}
	if err := settingsSyncParent(a.dataDir); err != nil {
		return errors.New("private input directory namespace could not be persisted")
	}
	data, err := json.Marshal(queueSnapshot(s))
	if err != nil || len(data) > 1<<20 {
		return errors.New("private input store exceeds recovery bound")
	}
	before, err := settingsRead(path, 1<<20)
	beforeMissing := os.IsNotExist(err)
	if os.IsNotExist(err) {
		before, _ = json.Marshal(queueDisk{Schema: 1, SessionID: s.ID, Entries: []*queuedInput{}})
	} else if err != nil {
		return errors.New("private input beforeimage unavailable")
	}
	// Preserve the last durable metadata/snapshot owners through main replacement.
	// A readable replacement alone is never treated as durable success.
	previous := path + ".previous"
	if err = settingsAtomicWrite(previous, before); err != nil {
		if errors.Is(err, errSettingsDurability) {
			a.quarantineQueueLocked(s)
			return queueUncertainError()
		}
		return errors.New("private input beforeimage could not be stored")
	}
	write := a.writeInputs
	if write == nil {
		write = settingsAtomicWrite
	}
	if err = write(path, data); err != nil {
		actual, readErr := settingsRead(path, 1<<20)
		unchanged := readErr == nil && settingsDigest(actual) == settingsDigest(before) || os.IsNotExist(readErr) && beforeMissing
		if errors.Is(err, errSettingsDurability) || !unchanged {
			a.quarantineQueueLocked(s)
			return queueUncertainError()
		}
		return errors.New("private input write refused before replacement")
	}
	// Retire the beforeimage only after the new main file is known durable.
	// A crash between these steps leaves both candidates, recovered as unknown.
	if err = os.Remove(previous); err != nil {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	if err = settingsSyncParent(dir); err != nil {
		a.quarantineQueueLocked(s)
		return queueUncertainError()
	}
	return nil
}

func (a *app) restoreInputs() error {
	for _, s := range a.sessions {
		path := a.queuePath(s)
		_, statErr := os.Lstat(path)
		missingMain := os.IsNotExist(statErr)
		readPath := path
		if missingMain {
			readPath = path + ".previous"
			if _, err := os.Lstat(readPath); os.IsNotExist(err) {
				continue
			}
		}
		data, err := settingsRead(readPath, 1<<20)
		if err != nil {
			return errors.New("private queued input recovery refused; preserve state")
		}
		var disk queueDisk
		if err = settingsDecode(data, &disk); err != nil || disk.Schema != 1 || disk.SessionID != s.ID || len(disk.Entries) > queueReceiptLimit || len(disk.Objective) > queueTextLimit {
			return errors.New("invalid private queued input recovery")
		}
		disk = neutralQueue(disk)
		mismatch := missingMain
		previousPath := path + ".previous"
		if previousData, readErr := settingsRead(previousPath, 1<<20); readErr == nil {
			if err := settingsDurableReadback(previousPath); err != nil {
				return errors.New("queued input beforeimage durability cannot be reconciled")
			}
			var previous queueDisk
			if settingsDecode(previousData, &previous) != nil || previous.Schema != 1 || previous.SessionID != s.ID || len(previous.Entries) > queueReceiptLimit || len(previous.Objective) > queueTextLimit {
				return errors.New("invalid queued input beforeimage")
			}
			if settingsDigest(previousData) != settingsDigest(data) {
				disk, err = mergeQueueCandidates(disk, neutralQueue(previous))
				if err != nil {
					return err
				}
				mismatch = true
			}
		} else if !os.IsNotExist(readErr) {
			return errors.New("queued input beforeimage unavailable")
		}
		if !missingMain {
			if err := settingsDurableReadback(path); err != nil {
				return errors.New("queued input durability cannot be reconciled")
			}
		}
		if disk.TaskID != "" {
			if s.task == nil || disk.TaskID != s.task.ID || disk.Generation != s.task.Generation {
				return errors.New("queued input task identity disagrees with journal; preserve state")
			}
			// An uncertain commit advances the journal one revision past a queue file
			// the replacement may never have reached. That is the state restart exists
			// to reconcile: this session is unknown and read-only, so the durable file
			// wins. Any other gap is still corruption.
			uncertainCommit := s.Status == "unknown" && disk.InputRevision+1 == s.task.InputRevision
			if disk.InputRevision < s.task.InputRevision && !uncertainCommit {
				return errors.New("queued input authority is older than journal")
			}
			if uncertainCommit {
				s.task.passes = map[string]string{}
				s.task.Subject = reviewSubject{}
				s.task.Stage = ""
			}
			if disk.InputRevision > s.task.InputRevision {
				s.task.passes = map[string]string{}
				s.task.Subject = reviewSubject{}
				s.task.Stage = ""
			}
			s.task.InputRevision = disk.InputRevision
			s.task.ObjectiveHash = disk.ObjectiveHash
			s.task.objective = disk.Objective
			if objectiveHash(s.task.objective) != s.task.ObjectiveHash {
				return errors.New("private task objective digest mismatch")
			}
		}
		seen := map[string]bool{}
		totalText := 0
		for _, entry := range disk.Entries {
			if entry == nil || entry.RequestID == "" || len(entry.RequestID) > 128 || seen[entry.RequestID] || (entry.Status != "discarded" && (entry.TaskID != disk.TaskID || entry.Generation != disk.Generation)) || len(entry.Text) > 128<<10 {
				return errors.New("invalid recovered queue entry")
			}
			seen[entry.RequestID] = true
			totalText += len(entry.Text)
			for _, attachment := range entry.Snapshots {
				if attachment.Size < 0 || filepath.Clean(attachment.Path) != attachment.Path || !strings.HasPrefix(attachment.Path, filepath.Join(a.dataDir, "attachments")+string(filepath.Separator)) {
					return errors.New("queued attachment recovery path refused")
				}
			}
			switch entry.Status {
			case "queued", "held":
				entry.Status = "held"
				entry.Reason = "App restarted; copy into a new session, never automatic replay"
			case "dispatching", "unknown":
				entry.Status = "unknown"
				s.Status = "unknown"
				s.Error = "A queued provider dispatch has no reconciled outcome; no replay"
				entry.Reason = "Prior provider delivery is uncertain; never replay automatically"
			case "cleanup_pending":
				entry.Reason = "Resuming durable attachment cleanup; never provider replay"
			case "retained", "discarded": // Retained bytes are read-only recovery data.
			default:
				return errors.New("unknown queued input state")
			}
		}
		if totalText > queueTextLimit {
			return errors.New("recovered queue exceeds retention bound")
		}
		if err := attachmentRetentionBound(disk.Entries, nil); err != nil {
			return errors.New("recovered queue exceeds retention bound")
		}
		for _, entry := range disk.Entries {
			if entry.Status == "cleanup_pending" {
				continue
			}
			holder := &session{attachmentSnapshots: entry.Snapshots}
			paths := []string{}
			for path := range entry.Snapshots {
				paths = append(paths, path)
			}
			if _, err := a.selectedAttachments(holder, paths); err != nil {
				return errors.New("recovered attachment snapshot integrity failed; preserve state")
			}
		}
		s.inputs = disk.Entries
		if mismatch {
			s.Status = "unknown"
			s.Error = "Queued input commit was interrupted; reconciled both private metadata slots without replay"
			if err := a.promoteRecoveredInputs(s); err != nil {
				return errors.New("reconciled queued input could not be durably promoted; beforeimage preserved")
			}
		}
		for _, entry := range s.inputs {
			if entry.Status == "cleanup_pending" {
				if err := a.finishAttachmentCleanupLocked(s, entry); err != nil {
					return errors.New("pending attachment cleanup could not be reconciled; preserve state")
				}
			}
		}
	}
	return nil
}
