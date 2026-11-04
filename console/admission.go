package main

import (
	"errors"
	"time"
)

type dispatchRefusedError struct{ reason string }

func (e *dispatchRefusedError) Error() string { return e.reason }
func refused(reason string) error             { return &dispatchRefusedError{reason} }
func isDispatchRefused(err error) bool {
	var target *dispatchRefusedError
	return errors.As(err, &target)
}

func inputLifecycleBlocked(s *session) bool {
	return s.queueUncertain || s.Restored || oneOf(s.Status, "unknown", "blocked", "paused") || oneOf(s.Supervision.State, "unknown", "blocked", "paused")
}

func (a *app) turnAdmission(s *session, epoch uint64, request string) inputAdmission {
	if s.reviewParent != "" {
		return a.managedReviewAdmission(s)
	}
	return func() (func(), error) {
		s.dispatchMu.Lock()
		a.mu.Lock()
		valid := s.controlEpoch == epoch && s.Status == "running" && s.lastRequest == request && !inputLifecycleBlocked(s)
		if valid {
			if err := a.commitDeliveryLocked(s, request); err != nil {
				a.mu.Unlock()
				s.dispatchMu.Unlock()
				return nil, err
			}
		}
		a.mu.Unlock()
		if !valid {
			s.dispatchMu.Unlock()
			return nil, refused("turn admission changed or user paused before dispatch")
		}
		return s.dispatchMu.Unlock, nil
	}
}
func (a *app) bindQuestionLocked(s *session, q *question, target, turn string) {
	q.epoch = s.controlEpoch
	q.turnID = turn
	q.target = target
	q.requestID = s.lastRequest
	q.client = s.codex
	q.run = s.claude
	if s.task != nil {
		q.generation = s.task.Generation
		q.inputRevision = s.task.InputRevision
		q.objectiveHash = s.task.ObjectiveHash
	}
}
func (a *app) revokeQuestionsLocked(s *session, target string) {
	kept := []question{}
	for _, q := range s.PendingQuestions {
		if target != "" && q.target != target {
			kept = append(kept, q)
			continue
		}
		go rejectRevoked(q)
	}
	s.PendingQuestions = kept
}
func rejectRevoked(q question) {
	if q.client != nil {
		_ = q.client.reject(q.rpcID, "question revoked by lifecycle change")
	} else if q.run != nil {
		_ = q.run.write(map[string]any{"type": "control_response", "response": map[string]any{"subtype": "error", "request_id": q.ID, "error": "question revoked by lifecycle change"}})
	}
}
func (a *app) questionAdmission(s *session, selected question) inputAdmission {
	return func() (func(), error) {
		s.dispatchMu.Lock()
		a.mu.Lock()
		generation := uint64(0)
		revision := uint64(0)
		hash := ""
		if s.task != nil {
			generation = s.task.Generation
			revision = s.task.InputRevision
			hash = s.task.ObjectiveHash
		}
		index := -1
		for i, q := range s.PendingQuestions {
			if q.ID == selected.ID {
				index = i
				break
			}
		}
		turn := s.turnID
		if selected.target != "" && selected.target != s.ProviderID {
			turn = ""
			for _, child := range s.Agents {
				if child.ID == selected.target {
					turn = child.turnID
				}
			}
		}
		expiry, expiryErr := time.Parse(time.RFC3339, selected.ExpiresAt)
		active := oneOf(s.requests[selected.requestID], "intent", "accepted")
		if selected.run != nil {
			active = active && selected.run.requestID == selected.requestID
		}
		// The queued writer checks authority here immediately before dispatch,
		// under app.mu, rather than trusting the earlier UI answer selection.
		valid := !inputLifecycleBlocked(s) && active && expiryErr == nil && time.Now().Before(expiry) && (selected.client != nil || selected.run != nil) && selected.requestID != "" && index >= 0 && s.Status == "waiting" && s.controlEpoch == selected.epoch && selected.requestID == s.lastRequest && selected.generation == generation && selected.inputRevision == revision && selected.objectiveHash == hash && selected.turnID == turn && (selected.client == s.codex && selected.run == s.claude)
		if !valid {
			a.mu.Unlock()
			s.dispatchMu.Unlock()
			return nil, refused("question expired, revoked or belongs to a different turn")
		}
		s.PendingQuestions = append(s.PendingQuestions[:index], s.PendingQuestions[index+1:]...)
		if len(s.PendingQuestions) == 0 {
			s.Status = "running"
		}
		a.changedLocked()
		a.mu.Unlock()
		return s.dispatchMu.Unlock, nil
	}
}

func (a *app) childAdmission(parent *session, id string, epoch uint64) inputAdmission {
	return func() (func(), error) {
		parent.dispatchMu.Lock()
		a.mu.Lock()
		owned := false
		for _, child := range parent.Agents {
			if child.ID == id {
				owned = true
			}
		}
		valid := owned && !parent.Restored && parent.controlEpoch == epoch
		a.mu.Unlock()
		if !valid {
			parent.dispatchMu.Unlock()
			return nil, refused("child control admission changed")
		}
		return parent.dispatchMu.Unlock, nil
	}
}
