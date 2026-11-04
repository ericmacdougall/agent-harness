// Package op defines the ledger op envelope v1: ordered JSON bytes, ULID ids, HLC clocks, validation and
// the 0a op kinds. Op bytes are produced once by Encode and never re-encoded; Parse accepts a line only if
// re-encoding it reproduces the same bytes, so every reader sees exactly one meaning.
package op

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// Limits (DESIGN section 4.1).
const (
	MaxOpBytes    = 64 * 1024
	MaxBodyBytes  = 32 * 1024
	MaxPackBytes  = 4 * 1024 * 1024
	MaxTitleBytes = 1024
	MaxLabelRunes = 64
	MaxLabels     = 64
	MaxActorLabel = 64
)

// Kinds.
const (
	KindProjectCreate = "project.create"
	KindTicketCreate  = "ticket.create"
	KindFieldSet      = "ticket.field_set"
	KindStatusSet     = "ticket.status_set"
	KindLabelAdd      = "ticket.label_add"
	KindLabelRemove   = "ticket.label_remove"
	KindComment       = "ticket.comment"
	KindNoop          = "noop"
)

var knownKinds = map[string]bool{KindProjectCreate: true, KindTicketCreate: true, KindFieldSet: true,
	KindStatusSet: true, KindLabelAdd: true, KindLabelRemove: true, KindComment: true, KindNoop: true}

// Known reports whether kind is interpreted by this version. Unknown kinds are stored and ignored.
func Known(kind string) bool { return knownKinds[kind] }

var (
	slugRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	actorLabelRe = regexp.MustCompile(`^[A-Za-z0-9 ._/@:+-]{1,64}$`)
	kindRe       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){0,3}$`)
	keyRe        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// ValidSlug reports whether s is a project slug ([a-z0-9][a-z0-9-]{0,62}).
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// ValidActorLabel enforces the actor.label charset and length.
func ValidActorLabel(s string) bool { return actorLabelRe.MatchString(s) }

// Actor is claimed metadata about who wrote an op. It is never trusted.
type Actor struct {
	Kind  string // human | agent | system
	Label string
	Human string // only when attribution.human is configured (not in 0a)
}

// Op is a parsed op. Raw holds its exact stored bytes.
type Op struct {
	V       int
	ID      string
	Project string
	Writer  string
	HLC     HLC
	Actor   Actor
	Ticket  string
	Kind    string
	Payload Obj
	Deps    []string
	Ref     Obj
	Raw     []byte
}

// Draft is an op before its clock and id are assigned under the writer lock.
type Draft struct {
	Actor   Actor
	Ticket  string
	Kind    string
	Payload Obj
}

// Encode builds the canonical bytes of o (v, id, project, writer, hlc, actor, ticket?, kind, payload,
// deps?, ref?).
func (o *Op) Encode() ([]byte, error) {
	actor := Obj{{"kind", o.Actor.Kind}, {"label", o.Actor.Label}}
	if o.Actor.Human != "" {
		actor = append(actor, Field{"human", o.Actor.Human})
	}
	env := Obj{{"v", o.V}, {"id", o.ID}, {"project", o.Project}, {"writer", o.Writer},
		{"hlc", Obj{{"wall_ms", o.HLC.WallMs}, {"ctr", o.HLC.Ctr}}}, {"actor", actor}}
	if o.Ticket != "" {
		env = append(env, Field{"ticket", o.Ticket})
	}
	payload := o.Payload
	if payload == nil {
		payload = Obj{}
	}
	env = append(env, Field{"kind", o.Kind}, Field{"payload", payload})
	if len(o.Deps) > 0 {
		env = append(env, Field{"deps", o.Deps})
	}
	if len(o.Ref) > 0 {
		env = append(env, Field{"ref", o.Ref})
	}
	return Encode(env)
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid op")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Parse validates one ops.jsonl line and returns the op. The line must be canonical: re-encoding the
// parsed op must reproduce it byte for byte.
func Parse(line []byte) (*Op, error) {
	if len(line) > MaxOpBytes {
		return nil, invalid("op exceeds %d bytes", MaxOpBytes)
	}
	v, err := DecodeStrict(line)
	if err != nil {
		return nil, invalid("%v", err)
	}
	env, ok := v.(Obj)
	if !ok {
		return nil, invalid("op is not an object")
	}
	allowed := map[string]bool{"v": true, "id": true, "project": true, "writer": true, "hlc": true, "actor": true,
		"ticket": true, "kind": true, "payload": true, "deps": true, "ref": true}
	for _, k := range env.Keys() {
		if !allowed[k] {
			return nil, invalid("unknown field %q", k)
		}
	}
	o := &Op{Raw: append([]byte(nil), line...)}
	if n, ok := num(env, "v"); !ok || n != 1 {
		return nil, invalid("v must be 1")
	}
	o.V = 1
	o.ID, _ = str(env, "id")
	o.Project, _ = str(env, "project")
	o.Writer, _ = str(env, "writer")
	if !ValidID(o.ID, PrefixOp) || !ValidID(o.Project, PrefixProject) || !ValidID(o.Writer, PrefixWriter) {
		return nil, invalid("bad id, project or writer")
	}
	hv, _ := env.Get("hlc")
	h, ok := hv.(Obj)
	if !ok || len(h) != 2 {
		return nil, invalid("bad hlc")
	}
	wall, ok1 := num(h, "wall_ms")
	ctr, ok2 := num(h, "ctr")
	if !ok1 || !ok2 || wall < 0 || wall >= 1<<48 || ctr < 0 || ctr >= maxCtr {
		return nil, invalid("bad hlc")
	}
	o.HLC = HLC{wall, ctr}
	if ULIDTime(o.ID[len(PrefixOp):]) != wall {
		return nil, invalid("op id time differs from hlc.wall_ms")
	}
	av, _ := env.Get("actor")
	a, ok := av.(Obj)
	if !ok {
		return nil, invalid("bad actor")
	}
	o.Actor.Kind, _ = str(a, "kind")
	o.Actor.Label, _ = str(a, "label")
	o.Actor.Human, _ = str(a, "human")
	if o.Actor.Kind != "human" && o.Actor.Kind != "agent" && o.Actor.Kind != "system" {
		return nil, invalid("bad actor.kind")
	}
	if !ValidActorLabel(o.Actor.Label) || (o.Actor.Human != "" && !ValidActorLabel(o.Actor.Human)) {
		return nil, invalid("bad actor.label")
	}
	if tv, ok := env.Get("ticket"); ok {
		s, _ := tv.(string)
		if !ValidID(s, PrefixTicket) {
			return nil, invalid("bad ticket id")
		}
		o.Ticket = s
	}
	o.Kind, _ = str(env, "kind")
	if !kindRe.MatchString(o.Kind) {
		return nil, invalid("bad kind")
	}
	pv, _ := env.Get("payload")
	if o.Payload, ok = pv.(Obj); !ok {
		return nil, invalid("payload must be an object")
	}
	if dv, ok := env.Get("deps"); ok {
		arr, ok := dv.([]any)
		if !ok || len(arr) == 0 || len(arr) > 16 {
			return nil, invalid("bad deps")
		}
		for _, d := range arr {
			s, _ := d.(string)
			if !ValidID(s, PrefixOp) {
				return nil, invalid("bad deps")
			}
			o.Deps = append(o.Deps, s)
		}
	}
	if rv, ok := env.Get("ref"); ok {
		r, ok := rv.(Obj)
		if !ok || len(r) == 0 {
			return nil, invalid("bad ref")
		}
		for _, f := range r {
			s, ok := f.V.(string)
			if !keyRe.MatchString(f.K) || !ok || len(s) > 256 {
				return nil, invalid("bad ref")
			}
		}
		o.Ref = r
	}
	if Known(o.Kind) {
		if err := validatePayload(o); err != nil {
			return nil, err
		}
	}
	again, err := o.Encode()
	if err != nil || !bytes.Equal(again, line) {
		return nil, invalid("op bytes are not canonical")
	}
	return o, nil
}

func str(o Obj, k string) (string, bool) {
	v, ok := o.Get(k)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func num(o Obj, k string) (int64, bool) {
	v, ok := o.Get(k)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil && string(n) == strconv.FormatInt(i, 10)
}

// Str returns a string payload member ("" if absent or not a string).
func (o *Op) Str(k string) string {
	s, _ := str(o.Payload, k)
	return s
}

// Strings returns a []string payload member.
func (o *Op) Strings(k string) []string {
	v, _ := o.Payload.Get(k)
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func boundedText(s string, maxBytes int) bool { return utf8.ValidString(s) && len(s) <= maxBytes }
