package ledger

// The GoodQA import document (goodqa-ledger-import/v1). It is a pure function of one snapshot Input and a
// frontier range, so the digest names exactly that snapshot: no clock, no generation time, no commit ids,
// and nothing from writers that are not folded (their counts sit outside the digest).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
	"github.com/ericmacdougall/agent-harness/internal/ledger/scan"
)

// ImportFormat and ReceiptFormat name the two documents.
const (
	ImportFormat  = "goodqa-ledger-import/v1"
	ReceiptFormat = "goodqa-ledger-receipt/v1"
)

// ImportDoc is a built import document.
type ImportDoc struct {
	Body    []byte // the full JSON document, newline terminated
	Digest  string
	Ops     int // ops in the range
	Tickets int
}

// SecretError reports secret-shaped text found while building a document: fields and offsets only.
type SecretError struct{ Findings []scan.Finding }

func (e *SecretError) Error() string {
	parts := make([]string, 0, len(e.Findings))
	for i, f := range e.Findings {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("and %d more", len(e.Findings)-5))
			break
		}
		parts = append(parts, f.String())
	}
	return "secret-shaped text in the ledger (" + strings.Join(parts, "; ") + "); fix is `export --redact-secrets`"
}

func frontierObjs(f []Frontier) []op.Obj {
	out := []op.Obj{}
	for _, x := range f {
		out = append(out, op.Obj{{K: "writer", V: x.Writer}, {K: "ops", V: x.Ops}, {K: "wall_ms", V: x.WallMs},
			{K: "ctr", V: x.Ctr}, {K: "last_op", V: x.LastOp}})
	}
	return out
}

// Truncate returns an Input holding only the folded writers' first ops (per to), failing when to is not a
// prefix of the current folded frontier. Unfolded refs are dropped: they cannot influence the result.
func Truncate(in fold.Input, to []Frontier) (fold.Input, error) {
	want := map[string]Frontier{}
	for _, f := range to {
		want[f.Writer] = f
	}
	out := fold.Input{Project: in.Project, Classes: map[string]string{}}
	seen := 0
	for _, r := range in.Refs {
		if r.Rejected != "" || !fold.Folded(in.Class(r.Writer)) {
			continue
		}
		f, ok := want[r.Writer]
		if !ok {
			continue
		}
		if f.Ops <= 0 || len(r.Ops) < f.Ops || r.Ops[f.Ops-1].ID != f.LastOp {
			return out, fmt.Errorf("frontier for %s is not a prefix of this ledger", r.Writer)
		}
		out.Refs = append(out.Refs, fold.Ref{Writer: r.Writer, Ops: r.Ops[:f.Ops]})
		out.Classes[r.Writer] = in.Class(r.Writer)
		seen++
	}
	if seen != len(want) {
		return out, fmt.Errorf("frontier names a writer this ledger does not fold")
	}
	return out, nil
}

// Within reports whether frontier a is covered by b (per writer, a.Ops <= b.Ops).
func Within(a, b []Frontier) bool {
	have := map[string]int{}
	for _, f := range b {
		have[f.Writer] = f.Ops
	}
	for _, f := range a {
		if f.Ops > have[f.Writer] {
			return false
		}
	}
	return true
}

type textField struct {
	name string
	p    *string
}

// BuildImport builds the document for the ops in (from, to]: the state of the ledger at to, the ops added
// since from, and the full history of every ticket those ops touch. from nil means the whole ledger.
func BuildImport(in fold.Input, from, to []Frontier, baseDigest string, redact bool) (*ImportDoc, error) {
	cut, err := Truncate(in, to)
	if err != nil {
		return nil, err
	}
	if !Within(from, to) {
		return nil, fmt.Errorf("the base frontier is not covered by the target frontier")
	}
	v := fold.Fold(cut)
	if v.Slug == "" {
		return nil, fmt.Errorf("project root op missing")
	}
	fromOps := map[string]int{}
	for _, f := range from {
		fromOps[f.Writer] = f.Ops
	}
	var rng []*op.Op
	touched := map[string]bool{}
	for _, r := range cut.Refs {
		n := fromOps[r.Writer]
		if n < 0 || n > len(r.Ops) {
			return nil, fmt.Errorf("base frontier for %s is outside the target frontier", r.Writer)
		}
		rng = append(rng, r.Ops[n:]...)
	}
	fold.SortOps(rng)
	for _, o := range rng {
		if o.Ticket != "" {
			touched[o.Ticket] = true
		}
	}

	var picked []*fold.Ticket
	for i := range v.Tickets {
		if len(from) == 0 || touched[v.Tickets[i].ID] {
			picked = append(picked, &v.Tickets[i])
		}
	}

	// Gather every emitted text so one pass scans or masks all of it.
	var fields []textField
	name := v.Name
	fields = append(fields, textField{"project name", &name})
	statusNames := make([]fold.Status, len(v.Statuses))
	copy(statusNames, v.Statuses)
	for i := range statusNames {
		fields = append(fields, textField{fmt.Sprintf("status %d name", i), &statusNames[i].Name})
	}
	copies := make([]fold.Ticket, len(picked))
	for i, t := range picked {
		c := *t
		c.Labels = append([]string(nil), t.Labels...)
		c.Comments = append([]fold.Comment(nil), t.Comments...)
		c.History = append([]fold.Event(nil), t.History...)
		copies[i] = c
		h := c.Handle
		fields = append(fields, textField{"ticket " + h + " created_by", &copies[i].CreatedBy})
		fields = append(fields, textField{"ticket " + h + " title", &copies[i].Title}, textField{"ticket " + h + " body", &copies[i].Body})
		for j := range copies[i].Labels {
			fields = append(fields, textField{fmt.Sprintf("ticket %s label %d", h, j), &copies[i].Labels[j]})
		}
		for j := range copies[i].Comments {
			fields = append(fields, textField{fmt.Sprintf("ticket %s comment %d actor", h, j), &copies[i].Comments[j].Actor})
			fields = append(fields, textField{fmt.Sprintf("ticket %s comment %d", h, j), &copies[i].Comments[j].Body})
		}
		for j := range copies[i].History {
			fields = append(fields, textField{fmt.Sprintf("ticket %s event %d actor", h, j), &copies[i].History[j].Actor},
				textField{fmt.Sprintf("ticket %s event %d from", h, j), &copies[i].History[j].From},
				textField{fmt.Sprintf("ticket %s event %d to", h, j), &copies[i].History[j].To})
		}
	}
	if redact {
		for _, f := range fields {
			*f.p = scan.Mask(*f.p)
		}
	} else {
		var pairs [][2]string
		for _, f := range fields {
			pairs = append(pairs, [2]string{f.name, *f.p})
		}
		if found := scan.Scan(pairs); len(found) > 0 {
			return nil, &SecretError{Findings: found}
		}
		// The raw op lines carry the same text; a secret that only an ignored or non-displayed op holds is
		// still caught here.
		var rawPairs [][2]string
		for _, o := range rng {
			rawPairs = append(rawPairs, [2]string{"op " + o.ID, string(o.Raw)})
		}
		if found := scan.Scan(rawPairs); len(found) > 0 {
			return nil, &SecretError{Findings: found}
		}
	}

	statuses := []op.Obj{}
	for i, s := range v.Statuses {
		statuses = append(statuses, op.Obj{{K: "key", V: s.Key}, {K: "name", V: statusNames[i].Name}, {K: "category", V: s.Category}})
	}
	tickets := []op.Obj{}
	for i := range copies {
		t := &copies[i]
		comments := []op.Obj{}
		for _, c := range t.Comments {
			comments = append(comments, op.Obj{{K: "id", V: c.ID}, {K: "op", V: c.Op}, {K: "writer", V: c.Writer},
				{K: "claimed_actor", V: c.Actor}, {K: "created_ms", V: c.WallMs}, {K: "body", V: c.Body}})
		}
		hist := []op.Obj{}
		for _, e := range t.History {
			cat := ""
			if e.Kind == op.KindStatusSet {
				if st, ok := v.StatusByKey(e.To); ok {
					cat = st.Category
				}
			}
			hist = append(hist, op.Obj{{K: "op", V: e.Op}, {K: "writer", V: e.Writer}, {K: "claimed_actor", V: e.Actor},
				{K: "kind", V: e.Kind}, {K: "wall_ms", V: e.WallMs}, {K: "ctr", V: e.Ctr}, {K: "field", V: e.Field},
				{K: "from", V: e.From}, {K: "to", V: e.To}, {K: "to_category", V: cat}})
		}
		labels := t.Labels
		if labels == nil {
			labels = []string{}
		}
		tickets = append(tickets, op.Obj{{K: "id", V: t.ID}, {K: "handle", V: t.Handle}, {K: "title", V: t.Title},
			{K: "body", V: t.Body}, {K: "type", V: t.Type}, {K: "priority", V: t.Priority}, {K: "status", V: t.Status},
			{K: "category", V: t.Category}, {K: "labels", V: labels}, {K: "created_ms", V: t.CreatedMs},
			{K: "updated_ms", V: t.UpdatedMs}, {K: "created_by", V: t.CreatedBy}, {K: "comments", V: comments},
			{K: "history", V: hist}})
	}

	body := op.Obj{
		{K: "format", V: ImportFormat},
		{K: "project", V: op.Obj{{K: "id", V: v.Project}, {K: "slug", V: v.Slug}, {K: "name", V: name}, {K: "statuses", V: statuses}}},
		{K: "frontier", V: frontierObjs(to)},
		{K: "base_digest", V: baseDigest},
		{K: "redacted", V: redact},
		{K: "tickets", V: tickets},
	}
	if redact {
		body = append(body, op.Field{K: "ops_omitted", V: "redacted"})
	} else {
		lines := []string{}
		for _, o := range rng {
			lines = append(lines, string(o.Raw))
		}
		body = append(body, op.Field{K: "ops", V: lines})
	}
	enc, err := op.Encode(body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(enc)
	digest := hex.EncodeToString(sum[:])

	un, unw, blw, rej, held := 0, map[string]bool{}, map[string]bool{}, 0, 0
	for _, n := range in.Held {
		held += n
	}
	for _, r := range in.Refs {
		switch {
		case r.Rejected != "":
			rej++
		case in.Class(r.Writer) == fold.ClassUnverified:
			un += len(r.Ops)
			unw[r.Writer] = true
		case in.Class(r.Writer) == fold.ClassBlocked:
			blw[r.Writer] = true
		}
	}
	full := append(body, op.Field{K: "digest", V: digest}, op.Field{K: "excluded", V: op.Obj{
		{K: "unverified_ops", V: un}, {K: "unverified_writers", V: len(unw)}, {K: "blocked_writers", V: len(blw)},
		{K: "rejected_refs", V: rej}, {K: "ignored_ops", V: len(v.Ignored)}, {K: "held_ops", V: held}}})
	out, err := op.Encode(full)
	if err != nil {
		return nil, err
	}
	return &ImportDoc{Body: append(out, '\n'), Digest: digest, Ops: len(rng), Tickets: len(tickets)}, nil
}
