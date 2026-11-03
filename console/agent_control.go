package main

import (
	"context"
	"errors"
	"time"
)

func (a *app) controlAgent(parent *session, id, action string) error {
	parent.dispatchMu.Lock()
	released := false
	release := func() {
		if !released {
			released = true
			parent.dispatchMu.Unlock()
		}
	}
	defer release()
	a.mu.Lock()
	if parent.Restored {
		a.mu.Unlock()
		return errors.New("restored agents have no exclusive writer admission")
	}
	var selected *agent
	for i := range parent.Agents {
		if parent.Agents[i].ID == id {
			selected = &parent.Agents[i]
			break
		}
	}
	if selected == nil {
		a.mu.Unlock()
		return errors.New("agent is not owned by this session")
	}
	if action == "pause" || action == "stop" {
		parent.controlEpoch++
		parent.resumeRequested = false
		a.holdInputsLocked(parent, "User paused an owner; explicit Resume required")
		a.revokeQuestionsLocked(parent, id)
		selected.Status = "paused"
		a.changedLocked()
	}
	provider := selected.Provider
	client := parent.codex
	var review *session
	for _, candidate := range a.reviews {
		if candidate.reviewParent == parent.ID && candidate.ProviderID == id {
			review = candidate
			client = review.codex
			break
		}
	}
	if action == "resume" && review != nil {
		a.mu.Unlock()
		return errors.New("independent review must restart through a fresh validated gate")
	}
	if provider == "claude" {
		if review != nil && review.claude != nil && (action == "pause" || action == "stop") {
			run := review.claude
			review.Status = "paused"
			a.finishReviewLocked(review)
			selected.Status = "paused"
			selected.CanStop = false
			a.changedLocked()
			a.mu.Unlock()
			release()
			run.cancel()
			return nil
		}
		a.mu.Unlock()
		return errors.New("this native Claude subagent has no independent control channel; control its owning main session")
	}
	if client == nil {
		a.mu.Unlock()
		return errors.New("agent connection unavailable")
	}
	epoch := parent.controlEpoch
	a.mu.Unlock()
	release()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if action == "resume" {
		var result struct {
			Thread struct {
				ID       string  `json:"id"`
				CWD      string  `json:"cwd"`
				Model    string  `json:"model"`
				Effort   *string `json:"reasoningEffort"`
				Runtime  string  `json:"modelProvider"`
				CanInput *bool   `json:"canAcceptDirectInput"`
			} `json:"thread"`
		}
		if err := client.call(ctx, "thread/read", map[string]any{"threadId": id, "includeTurns": false}, &result); err != nil {
			return err
		}
		metadata := result.Thread
		if metadata.ID != id || metadata.Model == "" || metadata.Effort == nil || *metadata.Effort == "" || metadata.Runtime == "" || metadata.CanInput == nil || !*metadata.CanInput {
			return errors.New("native owner runtime metadata or direct-input admission unavailable; resume refused")
		}
		actualCWD, cwdErr := validCWD(metadata.CWD)
		if cwdErr != nil || actualCWD != metadata.CWD {
			return errors.New("native owner working directory unavailable or redirected")
		}
		a.mu.Lock()
		for i := range parent.Agents {
			if parent.Agents[i].ID == id {
				parent.Agents[i].CWD = metadata.CWD
				parent.Agents[i].Model = metadata.Model
				parent.Agents[i].Effort = *metadata.Effort
				parent.Agents[i].RuntimeProvider = metadata.Runtime
			}
		}
		a.changedLocked()
		a.mu.Unlock()
		// Every runtime override is deliberately omitted: native turn/start preserves
		// this loaded owner's cwd/model/effort/provider/permissions rather than the main's.
		params := map[string]any{"threadId": id, "input": []any{map[string]any{"type": "text", "text": "Resume your previously assigned scoped work from its last verified checkpoint. Coordinate with your owner and honor its current scope."}}}
		if err := client.callAdmitted(ctx, "turn/start", params, nil, a.childAdmission(parent, id, epoch)); err != nil {
			return err
		}
	} else if action == "pause" || action == "stop" {
		var turns struct {
			Data []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := client.call(ctx, "thread/turns/list", map[string]any{"threadId": id, "limit": 1, "sortDirection": "desc"}, &turns); err != nil {
			return err
		}
		if len(turns.Data) == 0 {
			return errors.New("agent has no current turn")
		}
		if err := client.call(ctx, "turn/interrupt", map[string]any{"threadId": id, "turnId": turns.Data[0].ID}, nil); err != nil {
			return err
		}
	} else {
		return errors.New("unknown agent control")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range parent.Agents {
		if parent.Agents[i].ID == id {
			if action == "resume" {
				parent.Agents[i].Status = "running"
			} else {
				parent.Agents[i].Status = "paused"
			}
		}
	}
	a.changedLocked()
	return nil
}
