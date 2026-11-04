package main

// Request receipts have one transition table. Terminal states never move, so a
// late provider frame, control or restart path cannot reopen a turn or overwrite
// a native final, whichever site it comes from.
var requestTransitions = map[string][]string{
	"":         {"intent"},
	"intent":   {"accepted", "final", "unknown", "rejected", "abandoned"},
	"accepted": {"final", "unknown", "rejected", "abandoned"},
	"unknown":  {"abandoned"},
}

func requestTerminal(state string) bool {
	return oneOf(state, "final", "unknown", "abandoned")
}

func requestUnresolved(state string) bool {
	return oneOf(state, "intent", "accepted", "unknown")
}

// transitionRequestLocked applies one receipt change and reports whether it was
// legal. An illegal change leaves the receipt untouched, which fails closed: the
// caller's guard was wrong, and the existing outcome stays authoritative.
func (a *app) transitionRequestLocked(s *session, request, next string) bool {
	current := s.requests[request]
	if current == next {
		return true
	}
	for _, allowed := range requestTransitions[current] {
		if allowed == next {
			s.requests[request] = next
			return true
		}
	}
	return false
}
