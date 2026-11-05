package ledger

import "github.com/ericmacdougall/agent-harness/internal/ledger/fold"

// Sync states.
const (
	StateNone      = "none"
	StateLocalOnly = "local-only"
	StatePending   = "pending"
	StateSynced    = "synced"
	StateDiverged  = "diverged"
	StateTracked   = "tracked"
)

// SyncReport is what sync-state shows.
type SyncReport struct {
	State         string
	Unsynced      int // folded ops not covered by the binding (all folded ops when never bound)
	GoodQAProject string
	Writers       int // folded writers
}

// SyncState classifies the ledger from one snapshot. tracked says a GoodQA repos pattern matches a remote;
// it only matters when the ledger was never bound.
func (l *Ledger) SyncState(in fold.Input, tracked bool) SyncReport {
	cur := FoldedFrontier(in)
	total := 0
	for _, f := range cur {
		total += f.Ops
	}
	r := SyncReport{Unsynced: total, Writers: len(cur)}
	b := l.ReadBinding()
	if b == nil {
		r.State = StateLocalOnly
		if tracked {
			r.State = StateTracked
		}
		return r
	}
	r.GoodQAProject = b.GoodQAProject
	rel, extra := Compare(in, b.Frontier)
	switch rel {
	case RelDiverged:
		r.State = StateDiverged
	case RelBehind:
		r.State, r.Unsynced = StatePending, extra
	default:
		r.State, r.Unsynced = StateSynced, 0
	}
	return r
}
