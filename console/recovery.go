package main

import (
	"encoding/json"
	"errors"
	"net/http"
)

type checkpointRecord struct {
	InputRevision uint64            `json:"inputRevision"`
	ObjectiveHash string            `json:"objectiveHash"`
	ID            string            `json:"id"`
	Generation    uint64            `json:"generation"`
	State         string            `json:"state"`
	Stage         string            `json:"stage"`
	ScopeHash     string            `json:"scopeHash,omitempty"`
	Subject       reviewSubject     `json:"subject"`
	ReviewStatus  string            `json:"reviewStatus"`
	Attempts      map[string]int    `json:"attempts"`
	Passes        map[string]string `json:"passes"`
	Bursts        int               `json:"bursts"`
}

func checkpointSnapshot(s *session) *checkpointRecord {
	t := s.task
	if t == nil {
		return nil
	}
	subject := t.Subject
	subject.Files = nil
	return &checkpointRecord{InputRevision: t.InputRevision, ObjectiveHash: t.ObjectiveHash, ID: t.ID, Generation: t.Generation, State: t.State, Stage: t.Stage, ScopeHash: objectiveHash(t.scope), Subject: subject, ReviewStatus: t.ReviewStatus, Attempts: t.attempts, Passes: t.passes, Bursts: s.Supervision.RemainingBursts}
}
func restoreCheckpoint(s *session, r journalRecord) {
	checkpoint := r.Checkpoint
	if checkpoint == nil && r.TaskID != "" {
		checkpoint = &checkpointRecord{ID: r.TaskID, Generation: r.TaskGeneration, Stage: r.TaskStage, ReviewStatus: r.ReviewStatus, State: "unknown", Subject: reviewSubject{Digest: r.SubjectDigest}}
	}
	if checkpoint == nil {
		return
	}
	s.task = &trackedTask{InputRevision: checkpoint.InputRevision, ObjectiveHash: checkpoint.ObjectiveHash, ID: checkpoint.ID, Generation: checkpoint.Generation, State: checkpoint.State, Stage: checkpoint.Stage, Subject: checkpoint.Subject, ReviewStatus: "unknown", passes: checkpoint.Passes, attempts: checkpoint.Attempts}
	s.Work = s.task
	s.Supervision.RemainingBursts = checkpoint.Bursts
}
func (a *app) continueAsNew(id string) (*session, error) {
	a.mu.Lock()
	source := a.findLocked(id)
	if source == nil {
		a.mu.Unlock()
		return nil, errors.New("session not found")
	}
	provider, cwd, profile, providerID := source.Provider, source.CWD, source.ProfileID, source.ProviderID
	metadata, _ := json.Marshal(source.Work)
	excerpt := ""
	for _, m := range source.Messages {
		if len(excerpt) > 128<<10 {
			break
		}
		excerpt += m.Role + ": " + m.Text + "\n"
	}
	a.mu.Unlock()
	target, err := a.createSession(provider, cwd, profile)
	if err != nil {
		return target, err
	}
	if provider == "codex" {
		a.importContext(target, providerID)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	context := "Continued in a NEW provider session. The prior writer was not resumed. Prior session identity: " + providerID + "\nRecovered work metadata (unverified evidence): " + string(metadata) + "\n" + excerpt
	target.context = context + target.context
	a.addMessageLocked(target, message{Role: "context", Text: context})
	target.Title = "New continuation of " + source.Title
	a.changedLocked()
	return target, nil
}
func (a *app) continueAsNewHTTP(w http.ResponseWriter, r *http.Request) {
	target, err := a.continueAsNew(r.PathValue("id"))
	if err != nil {
		a.apiError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": target.ID})
}
