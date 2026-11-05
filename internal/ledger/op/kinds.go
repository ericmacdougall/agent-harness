package op

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Status is one workflow status of a project.
type Status struct{ Key, Name, Category string }

// Categories a status can belong to.
var Categories = map[string]bool{"backlog": true, "unstarted": true, "started": true, "completed": true, "canceled": true}

// DefaultStatuses is the 0a workflow written by init.
var DefaultStatuses = []Status{
	{"backlog", "Backlog", "backlog"}, {"todo", "Todo", "unstarted"}, {"in_progress", "In progress", "started"},
	{"in_review", "In review", "started"}, {"done", "Done", "completed"}, {"cancelled", "Cancelled", "canceled"},
}

// Ticket field vocabularies.
var (
	Types      = map[string]bool{"task": true, "bug": true, "feature": true, "chore": true}
	Priorities = map[string]bool{"none": true, "low": true, "medium": true, "high": true, "urgent": true}
	Fields     = map[string]bool{"title": true, "body": true, "priority": true, "type": true}
	statusKey  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// ProjectCreate builds a project.create payload.
func ProjectCreate(slug, name string, statuses []Status) Obj {
	ss := make([]Obj, len(statuses))
	for i, s := range statuses {
		ss[i] = Obj{{"key", s.Key}, {"name", s.Name}, {"category", s.Category}}
	}
	return Obj{{"slug", slug}, {"name", name}, {"statuses", ss}}
}

// TicketCreate builds a ticket.create payload. Labels must already be LabelDisplay-normalized.
func TicketCreate(title, body, typ, priority string, labels []string, status, category string) Obj {
	if labels == nil {
		labels = []string{}
	}
	return Obj{{"title", title}, {"body", body}, {"type", typ}, {"priority", priority}, {"labels", labels},
		{"status", status}, {"category", category}}
}

// FieldSet builds a ticket.field_set payload.
func FieldSet(field, value string) Obj { return Obj{{"field", field}, {"value", value}} }

// StatusSet builds a ticket.status_set payload.
func StatusSet(from, to, category string) Obj {
	return Obj{{"from", from}, {"to", to}, {"category", category}}
}

// Label builds a ticket.label_add/remove payload.
func Label(label string) Obj { return Obj{{"label", label}} }

// Comment builds a ticket.comment payload.
func Comment(commentID, body string) Obj { return Obj{{"comment_id", commentID}, {"body", body}} }

func keysAre(o Obj, keys ...string) bool {
	if len(o) != len(keys) {
		return false
	}
	for i, k := range keys {
		if o[i].K != k {
			return false
		}
	}
	return true
}

// ValidLabel checks a display label: non-empty after normalization, bounded, no control characters.
func ValidLabel(s string) bool {
	if s == "" || s != LabelDisplay(s) || len([]rune(s)) > MaxLabelRunes {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || r == ',' {
			return false
		}
	}
	return true
}

// ValidTitle checks a ticket title: non-empty, single line, bounded.
func ValidTitle(s string) bool {
	return strings.TrimSpace(s) != "" && boundedText(s, MaxTitleBytes) && !strings.ContainsAny(s, "\r\n")
}

func validatePayload(o *Op) error {
	p := o.Payload
	needTicket := strings.HasPrefix(o.Kind, "ticket.")
	if needTicket != (o.Ticket != "") {
		return invalid("%s: ticket presence mismatch", o.Kind)
	}
	switch o.Kind {
	case KindProjectCreate:
		if !keysAre(p, "slug", "name", "statuses") || !ValidSlug(o.Str("slug")) || !boundedText(o.Str("name"), 128) {
			return invalid("project.create payload")
		}
		sv, _ := p.Get("statuses")
		arr, ok := sv.([]any)
		if !ok || len(arr) == 0 || len(arr) > 32 {
			return invalid("project.create statuses")
		}
		seen := map[string]bool{}
		for _, x := range arr {
			s, ok := x.(Obj)
			if !ok || !keysAre(s, "key", "name", "category") {
				return invalid("project.create status")
			}
			k, _ := str(s, "key")
			n, _ := str(s, "name")
			c, _ := str(s, "category")
			if !statusKey.MatchString(k) || seen[k] || !boundedText(n, 64) || !Categories[c] {
				return invalid("project.create status")
			}
			seen[k] = true
		}
		if o.ID[len(PrefixOp):] != o.Project[len(PrefixProject):] {
			// Still a well-formed op; the fold ignores it (root rule). Kept valid so it can be reported.
			return nil
		}
	case KindTicketCreate:
		if !keysAre(p, "title", "body", "type", "priority", "labels", "status", "category") ||
			!ValidTitle(o.Str("title")) || !boundedText(o.Str("body"), MaxBodyBytes) || !Types[o.Str("type")] ||
			!Priorities[o.Str("priority")] || !statusKey.MatchString(o.Str("status")) || !Categories[o.Str("category")] {
			return invalid("ticket.create payload")
		}
		if o.Ticket[len(PrefixTicket):] != o.ID[len(PrefixOp):] {
			return invalid("ticket.create: ticket id must equal the op ULID")
		}
		lv, _ := p.Get("labels")
		arr, ok := lv.([]any)
		if !ok || len(arr) > MaxLabels {
			return invalid("ticket.create labels")
		}
		for _, x := range arr {
			if s, ok := x.(string); !ok || !ValidLabel(s) {
				return invalid("ticket.create label")
			}
		}
	case KindFieldSet:
		f := o.Str("field")
		if !keysAre(p, "field", "value") || !Fields[f] {
			return invalid("field_set payload")
		}
		v := o.Str("value")
		ok := map[string]bool{"title": ValidTitle(v), "body": boundedText(v, MaxBodyBytes), "type": Types[v],
			"priority": Priorities[v]}[f]
		if !ok {
			return invalid("field_set value")
		}
	case KindStatusSet:
		if !keysAre(p, "from", "to", "category") || !statusKey.MatchString(o.Str("from")) ||
			!statusKey.MatchString(o.Str("to")) || !Categories[o.Str("category")] {
			return invalid("status_set payload")
		}
	case KindLabelAdd, KindLabelRemove:
		if !keysAre(p, "label") || !ValidLabel(o.Str("label")) {
			return invalid("label payload")
		}
	case KindComment:
		if !keysAre(p, "comment_id", "body") || !ValidID(o.Str("comment_id"), PrefixComment) ||
			strings.TrimSpace(o.Str("body")) == "" || !boundedText(o.Str("body"), MaxBodyBytes) {
			return invalid("comment payload")
		}
	case KindNoop:
		if len(p) != 0 {
			return invalid("noop payload")
		}
	}
	for _, f := range p {
		if _, isNum := f.V.(json.Number); isNum {
			return invalid("payload numbers are not used in v1")
		}
	}
	return nil
}
