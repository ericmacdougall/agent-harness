package fold

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

const base = int64(1793664000000) // 2026-11-03T00:00:00Z

type builder struct {
	t       *testing.T
	project string
	clocks  map[string]op.HLC
}

func newBuilder(t *testing.T) (*builder, string) {
	b := &builder{t: t, clocks: map[string]op.HLC{}}
	id, _ := op.NewID(op.PrefixOp, base)
	b.project = op.PrefixProject + id[len(op.PrefixOp):]
	return b, id
}

func (b *builder) mk(writer, kind, ticket string, wall int64, payload op.Obj, id string) *op.Op {
	b.t.Helper()
	last := b.clocks[writer]
	h := op.HLC{WallMs: wall}
	if wall == last.WallMs {
		h.Ctr = last.Ctr + 1
	}
	b.clocks[writer] = h
	if id == "" {
		id, _ = op.NewID(op.PrefixOp, wall)
	}
	if ticket == "new" {
		ticket = op.PrefixTicket + id[len(op.PrefixOp):]
	}
	o := &op.Op{V: 1, ID: id, Project: b.project, Writer: writer, HLC: h,
		Actor: op.Actor{Kind: "agent", Label: "test"}, Ticket: ticket, Kind: kind, Payload: payload}
	line, err := o.Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	p, err := op.Parse(line)
	if err != nil {
		b.t.Fatalf("%s: %v", kind, err)
	}
	return p
}

func writer(t *testing.T) string { w, _ := op.NewID(op.PrefixWriter, base); return w }

func encodeView(t *testing.T, v *View) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// scenario builds a self ledger with 50 mixed ops plus an unverified foreign writer.
func scenario(t *testing.T) (Input, string, string) {
	b, rootID := newBuilder(t)
	me, other, foreign := writer(t), writer(t), writer(t)
	ops := map[string][]*op.Op{}
	add := func(w string, o *op.Op) { ops[w] = append(ops[w], o) }
	add(me, b.mk(me, op.KindProjectCreate, "", base, op.ProjectCreate("netwatch", "netwatch", op.DefaultStatuses), rootID))
	var tickets []string
	rng := rand.New(rand.NewSource(35695))
	for i := 0; i < 49; i++ {
		w := me
		if i%3 == 0 {
			w = other
		}
		wall := base + int64(1000*(i+1))
		if len(tickets) < 3 || rng.Intn(4) == 0 {
			o := b.mk(w, op.KindTicketCreate, "new", wall, op.TicketCreate("ticket", "body", "bug", "high", []string{"Dns"}, "todo", "unstarted"), "")
			tickets = append(tickets, o.Ticket)
			add(w, o)
			continue
		}
		tk := tickets[rng.Intn(len(tickets))]
		switch rng.Intn(5) {
		case 0:
			add(w, b.mk(w, op.KindStatusSet, tk, wall, op.StatusSet("todo", "in_progress", "started"), ""))
		case 1:
			add(w, b.mk(w, op.KindFieldSet, tk, wall, op.FieldSet("title", "retitled"), ""))
		case 2:
			add(w, b.mk(w, op.KindLabelAdd, tk, wall, op.Label("IPv6"), ""))
		case 3:
			add(w, b.mk(w, op.KindLabelRemove, tk, wall, op.Label("dns"), ""))
		default:
			cid, _ := op.NewID(op.PrefixComment, wall)
			add(w, b.mk(w, op.KindComment, tk, wall, op.Comment(cid, "comment"), ""))
		}
	}
	// Foreign writer: backdated project.create with a different slug, a ticket, a status move.
	fid, _ := op.NewID(op.PrefixOp, base-1000)
	add(foreign, b.mk(foreign, op.KindProjectCreate, "", base-1000, op.ProjectCreate("hijacked", "x", op.DefaultStatuses), fid))
	ft := b.mk(foreign, op.KindTicketCreate, "new", base+500, op.TicketCreate("evil", "b", "bug", "urgent", nil, "todo", "unstarted"), "")
	add(foreign, ft)
	add(foreign, b.mk(foreign, op.KindStatusSet, tickets[0], base+999999, op.StatusSet("todo", "done", "completed"), ""))
	in := Input{Project: b.project, Classes: map[string]string{me: ClassSelf, other: ClassSelf}}
	for w, os := range ops {
		in.Refs = append(in.Refs, Ref{Writer: w, Ops: os})
	}
	return in, foreign, tickets[0]
}

func TestFoldDeterministicUnderPermutation(t *testing.T) {
	in, _, _ := scenario(t)
	want := encodeView(t, Fold(in))
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		perm := Input{Project: in.Project, Classes: in.Classes}
		for _, j := range rng.Perm(len(in.Refs)) {
			perm.Refs = append(perm.Refs, in.Refs[j])
		}
		if got := encodeView(t, Fold(perm)); !bytes.Equal(got, want) {
			t.Fatalf("seed 1 iteration %d: fold depends on ref order", i)
		}
	}
	v := Fold(in)
	n := 0
	for _, w := range v.Writers {
		if Folded(w.Class) {
			n += w.Ops
		}
	}
	if n != 50 || len(v.Tickets) < 3 {
		t.Fatalf("expected 50 folded ops, got %d (%d tickets)", n, len(v.Tickets))
	}
}

func TestUnverifiedWriterIsExcluded(t *testing.T) {
	in, foreign, first := scenario(t)
	v := Fold(in)
	if v.Slug != "netwatch" {
		t.Fatalf("slug changed to %q", v.Slug)
	}
	for _, tk := range v.Tickets {
		if tk.Title == "evil" {
			t.Fatal("unverified ticket folded")
		}
	}
	if tk := v.FindTicket(first); tk.Status == "done" || !tk.TouchedByUnverified {
		t.Fatalf("unverified status move applied or not flagged: %+v", tk.Status)
	}
	w := v.WriterByID(foreign)
	if w == nil || w.Class != ClassUnverified || w.Ops != 3 || len(v.Pending) != 3 {
		t.Fatalf("foreign writer not listed for review: %+v pending %d", w, len(v.Pending))
	}
	// Control: the same ops trusted are folded, which proves the exclusion is what kept them out.
	in.Classes[foreign] = ClassTrusted
	tv := Fold(in)
	found := false
	for _, tk := range tv.Tickets {
		found = found || tk.Title == "evil"
	}
	if !found || tv.Slug != "netwatch" {
		t.Fatalf("trusted control: found=%v slug=%q", found, tv.Slug)
	}
}

func TestRootRule(t *testing.T) {
	b, rootID := newBuilder(t)
	me := writer(t)
	root := b.mk(me, op.KindProjectCreate, "", base, op.ProjectCreate("first", "first", op.DefaultStatuses), rootID)
	second := b.mk(me, op.KindProjectCreate, "", base+10, op.ProjectCreate("second", "second", op.DefaultStatuses), "")
	in := Input{Project: b.project, Classes: map[string]string{me: ClassSelf}, Refs: []Ref{{Writer: me, Ops: []*op.Op{root, second}}}}
	v := Fold(in)
	if v.Slug != "first" || len(v.Ignored) != 1 || v.Ignored[0].Op != second.ID {
		t.Fatalf("second create must be ignored and reported: slug %q ignored %+v", v.Slug, v.Ignored)
	}
	in.Refs[0].Ops = []*op.Op{second}
	if v := Fold(in); v.Slug != "" {
		t.Fatalf("mismatched create became root: %q", v.Slug)
	}
}

func TestLWWLabelsAndPinned(t *testing.T) {
	b, rootID := newBuilder(t)
	me, other := writer(t), writer(t)
	ops := []*op.Op{b.mk(me, op.KindProjectCreate, "", base, op.ProjectCreate("p", "p", op.DefaultStatuses), rootID)}
	c := b.mk(me, op.KindTicketCreate, "new", base+1000, op.TicketCreate("t0", "", "task", "low", []string{"Caf\u00e9"}, "todo", "unstarted"), "")
	ops = append(ops, c,
		b.mk(me, op.KindFieldSet, c.Ticket, base+2000, op.FieldSet("title", "t1"), ""),
		b.mk(me, op.KindLabelAdd, c.Ticket, base+3000, op.Label(op.LabelDisplay("CAFE\u0301")), ""), // same identity
		b.mk(me, op.KindLabelAdd, c.Ticket, base+3500, op.Label("x"), ""),
		b.mk(me, op.KindLabelRemove, c.Ticket, base+4000, op.Label("X"), ""))
	future := base + 3*24*3600*1000
	fut := b.mk(other, op.KindFieldSet, c.Ticket, future, op.FieldSet("title", "from the future"), "")
	old := b.mk(other, op.KindFieldSet, c.Ticket, 1000, op.FieldSet("priority", "urgent"), "")
	in := Input{Project: b.project, Classes: map[string]string{me: ClassSelf, other: ClassSelf},
		Refs: []Ref{{Writer: me, Ops: ops}, {Writer: other, Ops: []*op.Op{old, fut}}}}
	v := Fold(in)
	tk := v.Tickets[0]
	if tk.Title != "from the future" || len(tk.Labels) != 1 || tk.Labels[0] != "Caf\u00e9" {
		t.Fatalf("lww/labels: %q %v", tk.Title, tk.Labels)
	}
	if tk.Priority != "low" { // 1970 op is ordered before the create, so it does not win
		t.Fatalf("clock_behind op won: %q", tk.Priority)
	}
	if v.Flags.Behind != 1 || len(tk.Pinned) != 0 {
		t.Fatalf("fold must not depend on time: behind=%d pinned=%v", v.Flags.Behind, tk.Pinned)
	}
	now := base + 5000
	a := Annotate(v, now)
	at := a.Tickets[0]
	if len(at.Pinned) != 1 || at.Pinned[0].Field != "title" || at.Pinned[0].Writer != other || a.Flags.Ahead != 1 {
		t.Fatalf("pinned: %+v ahead=%d", at.Pinned, a.Flags.Ahead)
	}
	// Witness: the far-future op is not witnessed; the writer's best in-bound clock is.
	if w := v.Witness(me, now); w.WallMs != 1000 {
		t.Fatalf("witness %v", w)
	}
	if w := v.Witness(me, future); w.WallMs != future {
		t.Fatalf("witness at the future time %v", w)
	}
}

func TestHandlesUniqueAndAtLeast8(t *testing.T) {
	ts := []Ticket{{HandleHash: "abcdef0123456789"}, {HandleHash: "abcdef0199999999"}, {HandleHash: "11112222aaaa"}}
	assignHandles(ts)
	if ts[0].Handle != "abcdef012" || ts[1].Handle != "abcdef019" || ts[2].Handle != "11112222" {
		t.Fatalf("%+v", ts)
	}
}

// Labels come out in identity order whatever the map iteration order: a ticket with many labels folds to
// the same bytes on every run (Go randomizes map order, so 50 folds of 12 labels expose any reliance on it).
func TestLabelsSortedDeterministically(t *testing.T) {
	b, rootID := newBuilder(t)
	me := writer(t)
	ops := []*op.Op{b.mk(me, op.KindProjectCreate, "", base, op.ProjectCreate("p", "p", op.DefaultStatuses), rootID)}
	c := b.mk(me, op.KindTicketCreate, "new", base+1000, op.TicketCreate("t", "", "task", "low", nil, "todo", "unstarted"), "")
	ops = append(ops, c)
	names := []string{"lima", "alpha", "kilo", "delta", "juliet", "bravo", "india", "echo", "hotel", "charlie", "golf", "foxtrot"}
	for i, n := range names {
		ops = append(ops, b.mk(me, op.KindLabelAdd, c.Ticket, base+2000+int64(i), op.Label(n), ""))
	}
	in := Input{Project: b.project, Classes: map[string]string{me: ClassSelf}, Refs: []Ref{{Writer: me, Ops: ops}}}
	want := `["alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel","india","juliet","kilo","lima"]`
	for i := 0; i < 50; i++ {
		got, _ := json.Marshal(Fold(in).Tickets[0].Labels)
		if string(got) != want {
			t.Fatalf("run %d: labels %s", i, got)
		}
	}
}
