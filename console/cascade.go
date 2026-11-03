package main

import (
	"errors"
	"os/exec"
)

type cascadeAttempt struct {
	Stage     int    `json:"stage"`
	Provider  string `json:"provider"`
	ProfileID string `json:"profileId"`
	Model     string `json:"model"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}
type cascadeSelection struct {
	ConfigStage policyStep       `json:"configStage"`
	AdmissionID string           `json:"admissionId"`
	Revision    string           `json:"revision"`
	RequestID   string           `json:"requestId,omitempty"`
	Stage       int              `json:"stage"`
	Selected    policyStep       `json:"selected"`
	Reason      string           `json:"reason"`
	Attempts    []cascadeAttempt `json:"attempts"`
}

type localUnavailableError struct{ provider string }

func (e *localUnavailableError) Error() string {
	return e.provider + " executable is unavailable before dispatch"
}
func isLocalUnavailable(err error) bool {
	var local *localUnavailableError
	if errors.As(err, &local) {
		return true
	}
	var executable *exec.Error
	return errors.As(err, &executable) && errors.Is(executable.Err, exec.ErrNotFound)
}
func (a *app) chooseFreshPolicy(provider, profile string) (resolvedPolicy, *cascadeSelection, error) {
	selected := &cascadeSelection{AdmissionID: freshID(), Attempts: []cascadeAttempt{}}
	base, err := a.policyFor(provider, profile, "main")
	if err != nil {
		return resolvedPolicy{}, selected, err
	}
	selected.Revision = base.Revision
	if len(base.Cascade) > 8 {
		return resolvedPolicy{}, selected, errors.New("cascade exceeds the eight configured-stage bound")
	}
	candidates := append([]policyStep{{Provider: base.Provider, ProfileID: base.ProfileID, Model: base.Model, Effort: base.Effort}}, base.Cascade...)
	for index, spec := range candidates {
		policy := base
		if index > 0 {
			policy, err = a.policyFor(spec.Provider, spec.ProfileID, "main")
			if err != nil {
				return resolvedPolicy{}, selected, err
			}
			if policy.Revision != base.Revision {
				return resolvedPolicy{}, selected, errors.New("settings changed during cascade admission; no stage dispatched")
			}
			if policy.Provider != spec.Provider || policy.ProfileID != spec.ProfileID {
				return resolvedPolicy{}, selected, errors.New("cascade profile does not match explicit stage")
			}
			if spec.Model != "" {
				policy.Model = spec.Model
			}
			if spec.Effort != "" {
				policy.Effort = spec.Effort
			}
		}
		_, _, _, err = a.resolveRuntime(policy)
		attempt := cascadeAttempt{Stage: index, Provider: policy.Provider, ProfileID: policy.ProfileID, Model: policy.Model, Status: "selected", Reason: "Primary runtime available"}
		if err != nil {
			attempt.Status = "stopped"
			attempt.Reason = "Runtime admission failed; no retry authorized"
			if isLocalUnavailable(err) {
				attempt.Status = "unavailable"
				attempt.Reason = "Executable unavailable before dispatch"
			}
			selected.Attempts = append(selected.Attempts, attempt)
			if isLocalUnavailable(err) {
				continue
			}
			return resolvedPolicy{}, selected, err
		}
		if index > 0 {
			attempt.Reason = "Explicit fallback selected after local executable unavailability"
		}
		selected.Attempts = append(selected.Attempts, attempt)
		selected.Stage = index
		selected.Selected = policyStep{Provider: policy.Provider, ProfileID: policy.ProfileID, Model: policy.Model, Effort: policy.Effort}
		selected.ConfigStage = spec
		selected.Reason = attempt.Reason
		return policy, selected, nil
	}
	return resolvedPolicy{}, selected, errors.New("all explicitly configured runtime stages are unavailable; no provider input was sent")
}
func sessionStagePolicy(policy resolvedPolicy, selection *cascadeSelection) (resolvedPolicy, error) {
	if selection == nil || selection.Stage == 0 {
		return policy, nil
	}
	index := selection.Stage - 1
	if policy.Provider != selection.Selected.Provider || policy.ProfileID != selection.Selected.ProfileID || index >= len(policy.Cascade) || policy.Cascade[index] != selection.ConfigStage {
		return resolvedPolicy{}, errors.New("selected cascade stage changed; continue in a new session rather than switching active account")
	}
	if selection.ConfigStage.Model != "" {
		policy.Model = selection.ConfigStage.Model
	}
	if selection.ConfigStage.Effort != "" {
		policy.Effort = selection.ConfigStage.Effort
	}
	return policy, nil
}
func (a *app) failedFreshAdmission(provider, cwd, profile string, selection *cascadeSelection, cause error) (*session, error) {
	current := emptySession(provider, cwd, profile)
	current.Cascade = selection
	current.Status = "error"
	current.Error = a.clean(publicError(cause))
	current.Supervision.State = "blocked"
	current.Supervision.Reason = "No provider input was dispatched"
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) >= maxSessions {
		return nil, errors.New("session limit reached; close an inactive tab")
	}
	a.sessions = append(a.sessions, current)
	a.active = current.ID
	_ = a.record(current, "", "admission_failed")
	a.changedLocked()
	return current, cause
}
