package kernel

// MustAppend reports whether f may use the event log's reserve once ordinary facts
// reach their limit, judged against p, the projection f was decided on. Section 11
// of the K1a tables gives each row's bound and the proof that the reserve suffices:
// every eligible fact consumes a one-way change that only an ordinary fact can
// create again, so once ordinary facts stop, each session has few left to spend.
func MustAppend(p Projection, f Fact) bool {
	switch f.Kind {
	case FactProcessRestarted, FactProviderCompleted, FactOutcomeUnknown, FactProviderRefused,
		FactAbandoned, FactSessionClosed, FactAuthBoundaryCrossed, FactSessionQuarantined:
		return true
	case FactProviderDisconnected:
		// Each row's condition is checked here, not only trusted from Decide.
		s := p.Sessions[f.SessionID]
		return s != nil && (s.Connected || s.Requests[s.LastRequest].open())
	case FactControlRequested:
		s := p.Sessions[f.SessionID]
		if s == nil || f.Control != "stop" {
			return false
		}
		changesPaused := s.Requests[s.LastRequest] != ReceiptUnknown && !s.Paused
		return changesPaused || interruptOwed(s) && !s.PendingInterrupt
	case FactControlOutcome:
		s := p.Sessions[f.SessionID]
		return s != nil && s.ControlPending
	case FactLateFrameObserved:
		s := p.Sessions[f.SessionID]
		return s != nil && f.LateKind == "final" && f.RequestID == s.LastRequest
	}
	return false
}
