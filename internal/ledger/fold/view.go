// Package fold turns validated ops into the ledger view. Fold is a pure function of its Input: only ops
// from self and trusted writers are folded, project-level ops are honoured only from them, and the
// project id must equal the ULID of its project.create op.
package fold

import (
	"sort"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

// Writer classes.
const (
	ClassSelf       = "self"
	ClassTrusted    = "trusted"
	ClassUnverified = "unverified"
	ClassBlocked    = "blocked"
)

// Folded reports whether ops from a writer of class c enter the view.
func Folded(c string) bool { return c == ClassSelf || c == ClassTrusted }

// View is the materialized ledger state. Field order is the --json and cache order.
type View struct {
	Project  string      `json:"project"`
	Slug     string      `json:"slug"`
	Name     string      `json:"name"`
	CreateMs int64       `json:"create_ms"`
	Statuses []Status    `json:"statuses"`
	Tickets  []Ticket    `json:"tickets"`
	Writers  []Writer    `json:"writers"`
	Ignored  []Ignored   `json:"ignored"`
	Flags    FlagCounts  `json:"clock_flags"`
	Pending  []PendingOp `json:"pending"` // unverified ops, for writers --show only; never rendered in list/show/MCP
}

// Status mirrors op.Status for JSON.
type Status struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// FlagCounts counts clock flags over folded ops.
type FlagCounts struct {
	Ahead  int `json:"clock_ahead"`
	Behind int `json:"clock_behind"`
}

// Writer describes one writer ref.
type Writer struct {
	ID       string  `json:"id"`
	Class    string  `json:"class"`
	Ops      int     `json:"ops"`
	FirstMs  int64   `json:"first_ms"`
	LastMs   int64   `json:"last_ms"`
	Clocks   []Clock `json:"top_clocks"` // highest distinct clocks, descending, at most TopClocks
	Rejected string  `json:"rejected"`
}

// Clock is an HLC value in JSON form.
type Clock struct {
	WallMs int64 `json:"wall_ms"`
	Ctr    int64 `json:"ctr"`
}

// TopClocks bounds the per-writer clock list kept for witnessing.
const TopClocks = 64

// Winner records which op currently wins a ticket field (for "pinned by a future-dated op").
type Winner struct {
	Field  string `json:"field"`
	Op     string `json:"op"`
	Writer string `json:"writer"`
	WallMs int64  `json:"wall_ms"`
}

// Ignored is a folded-class op the fold did not apply, with the reason.
type Ignored struct {
	Op     string `json:"op"`
	Writer string `json:"writer"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// PendingOp is a sanitized preview of an unverified op (writers --show).
type PendingOp struct {
	Op     string `json:"op"`
	Writer string `json:"writer"`
	Kind   string `json:"kind"`
	WallMs int64  `json:"wall_ms"`
	Actor  string `json:"claimed_actor"`
	Ticket string `json:"ticket"`
	Title  string `json:"title"`
}

// Ticket is the folded state of one ticket.
type Ticket struct {
	ID                  string    `json:"id"`
	Handle              string    `json:"handle"`
	HandleHash          string    `json:"handle_hash"`
	Title               string    `json:"title"`
	Body                string    `json:"body"`
	Type                string    `json:"type"`
	Priority            string    `json:"priority"`
	Status              string    `json:"status"`
	Category            string    `json:"category"`
	Labels              []string  `json:"labels"`
	CreatedMs           int64     `json:"created_ms"`
	UpdatedMs           int64     `json:"updated_ms"`
	CreatedBy           string    `json:"created_by"`
	TouchedByUnverified bool      `json:"touched_by_unverified"`
	Comments            []Comment `json:"comments"`
	History             []Event   `json:"history"`
	Winners             []Winner  `json:"winners"`
	ClockFlags          []string  `json:"clock_flags"`   // filled by Annotate (time-dependent)
	Pinned              []Pinned  `json:"pinned_fields"` // filled by Annotate (time-dependent)
}

// Comment on a ticket.
type Comment struct {
	ID     string `json:"id"`
	Op     string `json:"op"`
	Writer string `json:"writer"`
	Actor  string `json:"claimed_actor"`
	WallMs int64  `json:"created_ms"`
	Body   string `json:"body"`
}

// Event is one applied op in a ticket's history.
type Event struct {
	Op     string `json:"op"`
	Writer string `json:"writer"`
	Actor  string `json:"claimed_actor"`
	Kind   string `json:"kind"`
	WallMs int64  `json:"wall_ms"`
	Ctr    int64  `json:"ctr"`
	Field  string `json:"field"`
	From   string `json:"from"`
	To     string `json:"to"`
	Flag   string `json:"clock_flag"`
}

// Pinned marks a field whose current winner is a future-dated op.
type Pinned struct {
	Field  string `json:"field"`
	Writer string `json:"writer"`
	Op     string `json:"op"`
	WallMs int64  `json:"wall_ms"`
}

// FindTicket returns the ticket with id.
func (v *View) FindTicket(id string) *Ticket {
	for i := range v.Tickets {
		if v.Tickets[i].ID == id {
			return &v.Tickets[i]
		}
	}
	return nil
}

// StatusByKey returns a status of the project.
func (v *View) StatusByKey(k string) (Status, bool) {
	for _, s := range v.Statuses {
		if s.Key == k {
			return s, true
		}
	}
	return Status{}, false
}

// WriterByID returns a writer entry.
func (v *View) WriterByID(id string) *Writer {
	for i := range v.Writers {
		if v.Writers[i].ID == id {
			return &v.Writers[i]
		}
	}
	return nil
}

// Witness returns the highest clock among folded writers other than me that may be witnessed at now
// (a writer whose maximum clock is too far ahead is not witnessed at all).
func (v *View) Witness(me string, now int64) op.HLC {
	var w op.HLC
	for _, x := range v.Writers {
		if x.ID == me || !Folded(x.Class) || x.Rejected != "" || x.Ops == 0 {
			continue
		}
		for _, c := range x.Clocks { // descending: the first witnessable one is this writer's best
			h := op.HLC{WallMs: c.WallMs, Ctr: c.Ctr}
			if op.Witnessable(h, now) {
				if w.Less(h) {
					w = h
				}
				break
			}
		}
	}
	return w
}

// Annotate returns a copy of v with the time-dependent clock_ahead flags and pinned fields filled in for
// now. The cached view never contains them, so a rebuild is byte-identical whatever the time.
func Annotate(v *View, now int64) *View {
	out := *v
	out.Tickets = make([]Ticket, len(v.Tickets))
	bound := now + op.WitnessBound
	for i, t := range v.Tickets {
		t.History = append([]Event(nil), t.History...)
		flags := append([]string(nil), t.ClockFlags...)
		for j := range t.History {
			if t.History[j].WallMs > bound {
				t.History[j].Flag = strings.TrimSpace("clock_ahead " + t.History[j].Flag)
				out.Flags.Ahead++
				if !contains(flags, "clock_ahead") {
					flags = append(flags, "clock_ahead")
				}
			}
		}
		sort.Strings(flags)
		t.ClockFlags = flags
		t.Pinned = []Pinned{}
		for _, w := range t.Winners {
			if w.WallMs > bound {
				t.Pinned = append(t.Pinned, Pinned{Field: w.Field, Writer: w.Writer, Op: w.Op, WallMs: w.WallMs})
			}
		}
		out.Tickets[i] = t
	}
	return &out
}
