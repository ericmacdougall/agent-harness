package fold

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

// Ref is one writer ref's validated ops in ref order, or the reason the ref was rejected.
type Ref struct {
	Writer   string
	Ops      []*op.Op
	Rejected string
}

// Input is everything the fold depends on (no clock: time-dependent flags are added by Annotate).
type Input struct {
	Project string
	Refs    []Ref
	Classes map[string]string // writer -> class; missing means unverified
}

// Class returns the class of writer w.
func (in Input) Class(w string) string {
	if c, ok := in.Classes[w]; ok {
		return c
	}
	return ClassUnverified
}

type key struct {
	wall, ctr    int64
	writer, opid string
}

func keyOf(o *op.Op) key { return key{o.HLC.WallMs, o.HLC.Ctr, o.Writer, o.ID} }

func (a key) less(b key) bool {
	if a.wall != b.wall {
		return a.wall < b.wall
	}
	if a.ctr != b.ctr {
		return a.ctr < b.ctr
	}
	if a.writer != b.writer {
		return a.writer < b.writer
	}
	return a.opid < b.opid
}

// SortOps orders ops by (wall_ms, ctr, writer, id).
func SortOps(ops []*op.Op) {
	sort.SliceStable(ops, func(i, j int) bool { return keyOf(ops[i]).less(keyOf(ops[j])) })
}

type fieldWin struct {
	k     key
	op    *op.Op
	value string
}

type labelState struct {
	display string
	present bool
	k       key
}

type tstate struct {
	t      *Ticket
	fields map[string]*fieldWin // title body priority type status
	labels map[string]*labelState
}

// HandleHash is the full hex sha256 of a ticket id; handles are its prefixes.
func HandleHash(ticketID string) string {
	s := sha256.Sum256([]byte(ticketID))
	return hex.EncodeToString(s[:])
}

func actorLabel(o *op.Op) string { return o.Actor.Kind + ":" + o.Actor.Label }

func topClocks(ops []*op.Op) []Clock {
	hs := make([]op.HLC, 0, len(ops))
	for _, o := range ops {
		hs = append(hs, o.HLC)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[j].Less(hs[i]) })
	out := []Clock{}
	for _, h := range hs {
		if n := len(out); n > 0 && out[n-1].WallMs == h.WallMs && out[n-1].Ctr == h.Ctr {
			continue
		}
		out = append(out, Clock{h.WallMs, h.Ctr})
		if len(out) == TopClocks {
			break
		}
	}
	return out
}

// Fold computes the view. It never reads the clock, the filesystem or map iteration order.
func Fold(in Input) *View {
	v := &View{Project: in.Project, Statuses: []Status{}, Tickets: []Ticket{}, Writers: []Writer{},
		Ignored: []Ignored{}, Pending: []PendingOp{}}
	refs := append([]Ref(nil), in.Refs...)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Writer < refs[j].Writer })

	var folded []*op.Op
	unverifiedTickets := map[string]bool{}
	for _, r := range refs {
		w := Writer{ID: r.Writer, Class: in.Class(r.Writer), Ops: len(r.Ops), Rejected: r.Rejected}
		for i, o := range r.Ops {
			if i == 0 || o.HLC.WallMs < w.FirstMs {
				w.FirstMs = o.HLC.WallMs
			}
			if o.HLC.WallMs > w.LastMs {
				w.LastMs = o.HLC.WallMs
			}
		}
		w.Clocks = topClocks(r.Ops)
		v.Writers = append(v.Writers, w)
		if r.Rejected != "" {
			continue
		}
		if Folded(w.Class) {
			folded = append(folded, r.Ops...)
			continue
		}
		if w.Class == ClassUnverified {
			for _, o := range r.Ops {
				unverifiedTickets[o.Ticket] = true
				p := PendingOp{Op: o.ID, Writer: o.Writer, Kind: o.Kind, WallMs: o.HLC.WallMs, Actor: actorLabel(o),
					Ticket: o.Ticket}
				if o.Kind == op.KindTicketCreate || o.Kind == op.KindProjectCreate {
					p.Title = o.Str("title") + o.Str("slug")
				}
				v.Pending = append(v.Pending, p)
			}
		}
	}
	SortOps(folded)
	sort.SliceStable(v.Pending, func(i, j int) bool {
		if v.Pending[i].WallMs != v.Pending[j].WallMs {
			return v.Pending[i].WallMs < v.Pending[j].WallMs
		}
		return v.Pending[i].Op < v.Pending[j].Op
	})

	// Root rule: the only honoured project.create is the folded one whose op ULID equals the project ULID.
	ignore := func(o *op.Op, reason string) {
		v.Ignored = append(v.Ignored, Ignored{Op: o.ID, Writer: o.Writer, Kind: o.Kind, Reason: reason})
	}
	var root *op.Op
	for _, o := range folded {
		if o.Kind != op.KindProjectCreate {
			continue
		}
		if root == nil && strings.TrimPrefix(o.ID, op.PrefixOp) == strings.TrimPrefix(in.Project, op.PrefixProject) &&
			o.Project == in.Project {
			root = o
			continue
		}
		ignore(o, "second_or_mismatched_project_create")
	}
	if root == nil {
		return v // no root: callers refuse to open
	}
	v.Slug, v.Name, v.CreateMs = root.Str("slug"), root.Str("name"), root.HLC.WallMs
	sv, _ := root.Payload.Get("statuses")
	for _, x := range sv.([]any) {
		s := x.(op.Obj)
		k, _ := s.Get("key")
		n, _ := s.Get("name")
		c, _ := s.Get("category")
		v.Statuses = append(v.Statuses, Status{k.(string), n.(string), c.(string)})
	}

	// Only the time-independent flag is computed here; clock_ahead depends on now (see Annotate).
	flag := func(o *op.Op) string {
		if o.HLC.WallMs < v.CreateMs-op.BehindSlack || o.HLC.WallMs < op.Epoch {
			return "clock_behind"
		}
		return ""
	}

	// Pass 1: tickets from creates.
	tickets := map[string]*tstate{}
	var order []string
	for _, o := range folded {
		if o.Kind != op.KindTicketCreate {
			continue
		}
		if o.Project != in.Project {
			ignore(o, "wrong_project")
			continue
		}
		if _, dup := tickets[o.Ticket]; dup {
			ignore(o, "duplicate_ticket_create")
			continue
		}
		status, category := o.Str("status"), ""
		if s, ok := v.StatusByKey(status); ok {
			category = s.Category
		} else {
			status, category = v.Statuses[0].Key, v.Statuses[0].Category
		}
		t := &Ticket{ID: o.Ticket, HandleHash: HandleHash(o.Ticket), Title: o.Str("title"), Body: o.Str("body"),
			Type: o.Str("type"), Priority: o.Str("priority"), Status: status, Category: category,
			CreatedMs: o.HLC.WallMs, CreatedBy: o.Writer, Labels: []string{}, Comments: []Comment{},
			History: []Event{}, Winners: []Winner{}, ClockFlags: []string{}, Pinned: []Pinned{}}
		st := &tstate{t: t, fields: map[string]*fieldWin{}, labels: map[string]*labelState{}}
		k := keyOf(o)
		for _, f := range []string{"title", "body", "type", "priority", "status"} {
			val := o.Str(f)
			if f == "status" {
				val = status
			}
			st.fields[f] = &fieldWin{k, o, val}
		}
		for _, l := range o.Strings("labels") {
			st.labels[op.LabelKey(l)] = &labelState{display: l, present: true, k: k}
		}
		tickets[o.Ticket] = st
		order = append(order, o.Ticket)
	}

	// Pass 2: every folded op in total order.
	for _, o := range folded {
		f := flag(o)
		if f == "clock_behind" {
			v.Flags.Behind++
		}
		if o.Project != in.Project {
			if o.Kind != op.KindTicketCreate {
				ignore(o, "wrong_project")
			}
			continue
		}
		if !op.Known(o.Kind) || o.Kind == op.KindNoop || o.Kind == op.KindProjectCreate {
			continue
		}
		st := tickets[o.Ticket]
		if st == nil {
			ignore(o, "unknown_ticket")
			continue
		}
		t, k := st.t, keyOf(o)
		ev := Event{Op: o.ID, Writer: o.Writer, Actor: actorLabel(o), Kind: o.Kind, WallMs: o.HLC.WallMs,
			Ctr: o.HLC.Ctr, Flag: f}
		applied := true
		switch o.Kind {
		case op.KindTicketCreate:
			if st.fields["title"].op != o {
				continue // duplicate already reported
			}
			ev.To = t.Status
		case op.KindFieldSet, op.KindStatusSet:
			field, val := o.Str("field"), o.Str("value")
			if o.Kind == op.KindStatusSet {
				field, val = "status", o.Str("to")
				if _, ok := v.StatusByKey(val); !ok {
					ignore(o, "unknown_status")
					continue
				}
			}
			cur := st.fields[field]
			ev.Field, ev.From, ev.To = field, cur.value, val
			if !cur.k.less(k) {
				applied = false // ordered before the current winner (e.g. before the create)
				break
			}
			st.fields[field] = &fieldWin{k, o, val}
		case op.KindLabelAdd, op.KindLabelRemove:
			lk := op.LabelKey(o.Str("label"))
			cur := st.labels[lk]
			ev.Field, ev.To = "label", o.Str("label")
			if cur != nil && !cur.k.less(k) {
				applied = false
				break
			}
			display := o.Str("label")
			if cur != nil && cur.present {
				display = cur.display // identity keeps its first display form
			}
			st.labels[lk] = &labelState{display: display, present: o.Kind == op.KindLabelAdd, k: k}
		case op.KindComment:
			t.Comments = append(t.Comments, Comment{ID: o.Str("comment_id"), Op: o.ID, Writer: o.Writer,
				Actor: actorLabel(o), WallMs: o.HLC.WallMs, Body: o.Str("body")})
		}
		if !applied {
			ev.Flag = strings.TrimSpace(ev.Flag + " superseded")
		}
		t.History = append(t.History, ev)
		if o.HLC.WallMs > t.UpdatedMs {
			t.UpdatedMs = o.HLC.WallMs
		}
		if f != "" && !contains(t.ClockFlags, f) {
			t.ClockFlags = append(t.ClockFlags, f)
		}
	}

	for _, id := range order {
		st := tickets[id]
		t := st.t
		t.Title, t.Body = st.fields["title"].value, st.fields["body"].value
		t.Type, t.Priority = st.fields["type"].value, st.fields["priority"].value
		t.Status = st.fields["status"].value
		s, _ := v.StatusByKey(t.Status)
		t.Category = s.Category
		for _, f := range []string{"title", "body", "type", "priority", "status"} {
			w := st.fields[f]
			t.Winners = append(t.Winners, Winner{Field: f, Op: w.op.ID, Writer: w.op.Writer, WallMs: w.op.HLC.WallMs})
		}
		keys := make([]string, 0, len(st.labels))
		for lk, ls := range st.labels {
			if ls.present {
				keys = append(keys, lk)
			}
		}
		sort.Strings(keys)
		for _, lk := range keys {
			t.Labels = append(t.Labels, st.labels[lk].display)
		}
		sort.Strings(t.ClockFlags)
		t.TouchedByUnverified = unverifiedTickets[t.ID]
		v.Tickets = append(v.Tickets, *t)
	}
	assignHandles(v.Tickets)
	return v
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// assignHandles gives each ticket the shortest prefix (>= 8 hex) of its hash that is unique among all
// tickets in the view.
func assignHandles(ts []Ticket) {
	for i := range ts {
		n := 8
		for ; n < 64; n++ {
			unique := true
			for j := range ts {
				if j != i && ts[j].HandleHash[:n] == ts[i].HandleHash[:n] {
					unique = false
					break
				}
			}
			if unique {
				break
			}
		}
		ts[i].Handle = ts[i].HandleHash[:n]
	}
}
