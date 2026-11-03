package main

import "errors"

func (a *app) closeSession(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.findLocked(id)
	if current == nil {
		return errors.New("session not found")
	}
	if activeQueue(current) {
		return errors.New("queued or retained input remains; cancel or explicitly discard it before closing")
	}
	switch current.Status {
	case "starting", "running", "waiting", "unknown":
		return errors.New("pause or reconcile active work before closing this tab")
	}
	// A paused status is a UI state, not a provider outcome. Restore drops closed
	// sessions, so closing here would erase the only receipt of an unresolved turn.
	if oneOf(current.requests[current.lastRequest], "intent", "accepted", "unknown") {
		return errors.New("the last request has no native final outcome; stop or reconcile it before closing this tab")
	}
	for _, child := range current.Agents {
		if child.CanPause || child.Status == "starting" || child.Status == "running" || child.Status == "active" {
			return errors.New("an owner is still active; stop or reconcile it before closing")
		}
	}
	if err := a.record(current, "", "closed"); err != nil {
		return errors.New("could not persist tab closure")
	}
	if current.claude != nil {
		current.claude.cancel()
		current.claude = nil
	}
	for i, s := range a.sessions {
		if s.ID == id {
			a.sessions = append(a.sessions[:i], a.sessions[i+1:]...)
			break
		}
	}
	if a.active == id {
		a.active = ""
		if len(a.sessions) > 0 {
			a.active = a.sessions[0].ID
		}
	}
	a.changedLocked()
	return nil
}
