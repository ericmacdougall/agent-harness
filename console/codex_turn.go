package main

import (
	"context"
	"encoding/json"
	"errors"
)

// This binding is owned by one correlated turn/start RPC, never by notifications.
// Pending completion metadata is bounded and cannot authorize a final receipt.
type codexTurnBinding struct {
	pendingBytes  int
	requestID     string
	client        *rpcClient
	turnID        string
	pending       []codexCompletion
	frames        []codexPendingFrame
	frameBytes    int
	framesDropped bool
	completed     map[string]bool
}
type codexCompletion struct {
	turnID  string
	status  string
	message string
}

func (a *app) quarantineCodexLocked(current *session, requestID, reason string) {
	if !oneOf(current.requests[requestID], "intent", "accepted") {
		return
	}
	current.providerFinal = false
	if current.codexTurn != nil {
		current.codexTurn.clearFrames()
		current.codexTurn.pending = nil
		current.codexTurn.pendingBytes = 0
	}
	current.requests[requestID] = "unknown"
	a.revokeQuestionsLocked(current, "")
	current.Status = "unknown"
	current.Error = reason
	current.Supervision.State = "paused"
	current.Supervision.Reason = reason
	a.inputOutcomeLocked(current, requestID, "unknown", "Provider completion has no durable exact request binding; no replay")
	_ = a.record(current, requestID, "unknown")
	a.changedLocked()
}

func (a *app) startCodexTurn(ctx context.Context, current *session, client *rpcClient, requestID string, params map[string]any, admit inputAdmission) error {
	binding := &codexTurnBinding{requestID: requestID, client: client}
	a.mu.Lock()
	if current.codex != client || current.lastRequest != requestID || current.requests[requestID] != "intent" {
		a.mu.Unlock()
		return refused("Codex request binding changed before dispatch")
	}
	current.codexTurn = binding
	current.turnID = ""
	a.mu.Unlock()
	var result json.RawMessage
	err := client.callAdmitted(ctx, "turn/start", params, &result, admit)
	a.mu.Lock()
	defer a.mu.Unlock()
	if current.codexTurn != binding || current.codex != client || current.lastRequest != requestID {
		return err
	}
	if !oneOf(current.requests[requestID], "intent", "accepted") {
		binding.pending = nil
		binding.pendingBytes = 0
		binding.clearFrames()
		return err
	}
	if err != nil {
		if len(binding.pending) > 0 {
			// A completion plus a failed reply is ambiguous, even if the reply says
			// rejection. No event can prove which request executed.
			a.quarantineCodexLocked(current, requestID, "Codex completion arrived without a successful turn/start binding. No request was replayed.")
		}
		binding.pending = nil
		binding.pendingBytes = 0
		binding.clearFrames()
		return err
	}
	turnID := codexFrameTurn(result, true)
	if turnID == "" {
		err = errors.New("Codex turn/start reply omitted or ambiguously specified the turn binding. No request was replayed.")
		a.quarantineCodexLocked(current, requestID, err.Error())
		binding.pending = nil
		binding.pendingBytes = 0
		binding.clearFrames()
		return err
	}
	binding.turnID = turnID
	current.turnID = binding.turnID
	current.context = ""
	frames := binding.frames
	binding.clearFrames()
	for _, frame := range frames {
		if frame.turnID == binding.turnID {
			a.applyCodexEventLocked(current, nil, client, frame.method, object(frame.raw), current.ProviderID)
		}
	}
	if current.reviewParent != "" {
		a.syncReviewAgentLocked(current)
	}
	pending := binding.pending
	binding.pending = nil
	binding.pendingBytes = 0
	for _, completion := range pending {
		if completion.turnID == binding.turnID {
			a.codexCompletionLocked(current, client, completion)
			a.changedLocked()
			return nil
		}
	}
	current.requests[requestID] = "accepted"
	a.inputOutcomeLocked(current, requestID, "retained", "Provider accepted; files retained for delayed consumers until explicit discard")
	if err = a.record(current, requestID, "accepted"); err != nil {
		a.quarantineCodexLocked(current, requestID, "Provider accepted input but receipt could not be persisted")
	}
	a.changedLocked()
	return err
}

func (a *app) codexCompletionLocked(current *session, client *rpcClient, completion codexCompletion) {
	requestID := current.lastRequest
	if oneOf(current.requests[requestID], "final", "unknown") {
		return
	}
	binding := current.codexTurn
	if binding == nil || binding.client != client || binding.requestID != requestID || completion.turnID == "" {
		a.quarantineCodexLocked(current, requestID, "Codex returned a completion without the exact active turn binding. No request was replayed.")
		return
	}
	if binding.turnID == "" {
		for _, pending := range binding.pending {
			if pending.turnID == completion.turnID {
				return
			}
		}
		if len(binding.pending) >= 16 || len(completion.turnID)+len(completion.status)+len(completion.message) > maxCodexPendingBytes-binding.pendingBytes {
			a.quarantineCodexLocked(current, requestID, "Codex exceeded the pending completion bound before request identity was established. No request was replayed.")
			binding.pending = nil
			binding.pendingBytes = 0
			return
		}
		binding.pending = append(binding.pending, completion)
		binding.pendingBytes += len(completion.turnID) + len(completion.status) + len(completion.message)
		return
	}
	if binding.turnID != completion.turnID || !oneOf(current.requests[requestID], "intent", "accepted") {
		return
	}
	status := completion.status
	current.providerFinal = true
	a.revokeQuestionsLocked(current, current.ProviderID)
	current.turnID = ""
	current.requests[requestID] = "final"
	current.Status = "idle"
	if current.Supervision.State == "paused" {
		current.Status = "paused"
	}
	if status == "failed" {
		current.Status = "error"
		current.Error = a.clean(completion.message)
		current.Supervision.State = "blocked"
		current.Supervision.Reason = current.Error
	}
	if status == "interrupted" {
		current.Status = "paused"
		current.Supervision.State = "paused"
		current.Supervision.Reason = "User or provider interrupted this turn"
	}
	if err := a.record(current, requestID, "final"); err != nil {
		current.providerFinal = false
		current.requests[requestID] = "unknown"
		a.revokeQuestionsLocked(current, "")
		current.Status = "unknown"
		current.Error = "Could not persist the final outcome"
		current.Supervision.State = "paused"
		current.Supervision.Reason = current.Error
		a.inputOutcomeLocked(current, requestID, "unknown", "Provider completed but final receipt durability is unknown; no replay")
		return
	}
	a.inputOutcomeLocked(current, requestID, "retained", "Main turn final; files retained for possible owner/tool readers until explicit discard")
	if current.queueUncertain {
		current.Status = "unknown"
		current.Supervision.State = "paused"
	}
	if current.reviewParent != "" {
		a.finishReviewLocked(current)
	} else if status == "completed" {
		go a.advance(current.ID)
	}
}
