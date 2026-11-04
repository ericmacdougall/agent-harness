package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *app) restore() error {
	info, err := a.journal.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 8<<20 {
		return errors.New("console journal exceeds recovery bound; preserve it and choose a new state directory")
	}
	if err = a.preserveTornJournalTail(info.Size()); err != nil {
		return err
	}
	if _, err = a.journal.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scan := bufio.NewScanner(a.journal)
	scan.Buffer(make([]byte, 4096), 65536)
	records := map[string]journalRecord{}
	receipts := map[string]journalRecord{}
	abandons := map[string]journalRecord{}
	checkpoints := map[string]journalRecord{}
	reviewRecords := map[string]journalRecord{}
	order := []string{}
	for scan.Scan() {
		var record journalRecord
		if err = json.Unmarshal(scan.Bytes(), &record); err != nil {
			return errors.New("console journal is incomplete; preserve it for recovery")
		}
		if record.ReviewParent != "" {
			reviewRecords[record.SessionID] = record
			continue
		}
		if record.TaskID != "" || record.Checkpoint != nil {
			checkpoints[record.SessionID] = record
		}
		if strings.HasPrefix(record.State, "checkpoint:") {
			continue
		}
		if record.SessionID == "" || record.ProviderID == "" {
			continue
		}
		if _, exists := records[record.SessionID]; !exists {
			order = append(order, record.SessionID)
		}
		records[record.SessionID] = record
		if record.State == "abandoned" {
			// The first decision stands; a retry after a failed sync can add a copy.
			if _, exists := abandons[record.SessionID]; !exists {
				abandons[record.SessionID] = record
			}
			continue
		}
		// Bookkeeping records such as cwd carry no request. They must not stand in
		// for the last request receipt when deciding what restart can trust.
		if record.RequestID != "" {
			receipts[record.SessionID] = record
		}
	}
	if err = scan.Err(); err != nil {
		return err
	}
	active := []string{}
	for _, id := range order {
		if records[id].State != "closed" {
			active = append(active, id)
		}
	}
	order = active
	order = a.trimRestoredSessions(order, receipts)
	for _, id := range order {
		record := records[id]
		current := emptySession(record.Provider, record.CWD, record.ProfileID)
		current.ID = id
		current.ProviderID = record.ProviderID
		current.claudeStarted = record.Provider == "claude" && record.State != "created"
		current.Status = "disconnected"
		current.Restored = true
		current.Cascade = record.Cascade
		restoreCheckpoint(current, checkpoints[id])
		current.Title = "Restored " + record.Provider + " session"
		current.Supervision.State = "paused"
		current.Supervision.Reason = "App restarted. Prior writer is read-only; continue in a new session with available context."
		receipt := receipts[id]
		if receipt.RequestID != "" {
			// One projection of the receipt: an unacknowledged send can only be
			// unknown here, since nothing can confirm it after a restart.
			state := receipt.State
			if oneOf(state, "intent", "accepted") {
				state = "unknown"
			}
			current.lastRequest = receipt.RequestID
			current.requests[receipt.RequestID] = state
			current.requestOrder = append(current.requestOrder, receipt.RequestID)
		}
		if requestUnresolved(receipt.State) {
			current.Status = "unknown"
			current.Error = "A prior send has no durable final outcome. It was not replayed."
		}
		if record, exists := abandons[id]; exists {
			if record.AbandonedRequest == receipt.RequestID && requestUnresolved(receipt.State) {
				current.requests[receipt.RequestID] = "abandoned"
			}
			current.abandoned = &abandonedTurn{RequestID: record.AbandonedRequest, Reason: record.AbandonReason, At: record.At}
			current.Status = "abandoned"
			current.Error = abandonedNotice
			current.Supervision.Reason = abandonedNotice
		}
		a.sessions = append(a.sessions, current)
	}
	for _, record := range reviewRecords {
		review := emptySession(record.Provider, record.CWD, record.ProfileID)
		review.ID = record.SessionID
		review.ProviderID = record.ProviderID
		review.reviewParent = record.ReviewParent
		review.reviewTaskID = record.ReviewTaskID
		review.reviewGeneration = record.ReviewGeneration
		review.reviewStage = record.ReviewStage
		review.reviewDigest = record.ReviewDigest
		review.reviewInputRevision = record.ReviewInputRevision
		review.reviewObjectiveHash = record.ReviewObjectiveHash
		review.Status = "unknown"
		review.Restored = true
		review.Supervision.State = "paused"
		a.reviews = append(a.reviews, review)
		for _, parent := range a.sessions {
			if parent.ID == record.ReviewParent {
				parent.Agents = append(parent.Agents, agent{ID: record.ProviderID, ParentID: parent.ProviderID, Provider: record.Provider, Role: "reviewer", Name: "Recovered independent review", Status: "unknown", Task: record.ReviewStage})
			}
		}
	}
	_, err = a.journal.Seek(0, io.SeekEnd)
	return err
}

// A final line with no newline was never acknowledged: record returns only after
// a complete line is synced. Each record's predecessor is a safe state to fall
// back to (accepted to intent, final to accepted, closed to open, abandoned to
// unresolved), and appending after it would corrupt the next record, so the tail
// is moved aside and kept. Any other unreadable line still refuses startup.
func (a *app) preserveTornJournalTail(size int64) error {
	if size == 0 {
		return nil
	}
	data := make([]byte, size)
	if _, err := a.journal.ReadAt(data, 0); err != nil {
		return err
	}
	end := bytes.LastIndexByte(data, '\n') + 1
	if int64(end) == size {
		return nil
	}
	aside := filepath.Join(a.dataDir, fmt.Sprintf("sessions.jsonl.torn-%d", time.Now().UnixNano()))
	if err := os.WriteFile(aside, data[end:], 0o600); err != nil {
		return errors.New("console journal has an incomplete final line that could not be preserved")
	}
	if err := a.journal.Truncate(int64(end)); err != nil {
		return err
	}
	return a.journal.Sync()
}

// Restored tabs do not count toward the live limit, so more can exist than one
// screen should show. Only resolved history is trimmed, oldest first: an unresolved
// turn or a retained payload must stay visible until the user discards it.
func (a *app) trimRestoredSessions(order []string, receipts map[string]journalRecord) []string {
	if len(order) <= maxSessions {
		return order
	}
	keep := map[string]bool{}
	protected := func(id string) bool {
		if requestUnresolved(receipts[id].State) {
			return true
		}
		path := a.queuePath(&session{ID: id})
		for _, candidate := range []string{path, path + ".previous"} {
			if _, err := os.Lstat(candidate); err == nil {
				return true
			}
		}
		return false
	}
	budget := maxSessions
	for _, id := range order {
		if protected(id) {
			keep[id] = true
			budget--
		}
	}
	for i := len(order) - 1; i >= 0 && budget > 0; i-- {
		if !keep[order[i]] {
			keep[order[i]] = true
			budget--
		}
	}
	kept := order[:0:0]
	for _, id := range order {
		if keep[id] {
			kept = append(kept, id)
		}
	}
	return kept
}
