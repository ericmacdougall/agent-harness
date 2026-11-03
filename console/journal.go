package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

func (a *app) restore() error {
	info, err := a.journal.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 8<<20 {
		return errors.New("console journal exceeds recovery bound; preserve it and choose a new state directory")
	}
	if _, err = a.journal.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scan := bufio.NewScanner(a.journal)
	scan.Buffer(make([]byte, 4096), 65536)
	records := map[string]journalRecord{}
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
	if len(order) > maxSessions {
		order = order[len(order)-maxSessions:]
	}
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
		if record.State == "intent" || record.State == "accepted" {
			current.Status = "unknown"
			current.Error = "A prior send has no durable final outcome. It was not replayed."
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
