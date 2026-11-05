package cli

import (
	"regexp"
	"strings"

	"github.com/ericmacdougall/agent-harness/internal/ledger"
	"github.com/ericmacdougall/agent-harness/internal/ledger/fold"
	"github.com/ericmacdougall/agent-harness/internal/ledger/op"
)

var (
	hexHandle  = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	slugHandle = regexp.MustCompile(`^(?i:ledger\s+)?([a-z0-9][a-z0-9-]{0,62})#([0-9a-fA-F]+)$`)
)

// Resolve finds the ticket a handle names. A handle is a ticket id (tk_<ULID>), 8-64 hex of
// sha256(ticket id), or <slug>#<hex> / "Ledger <slug>#<hex>". Only tickets created before asOf (ms; 0 =
// no bound) are candidates, so a later ticket can never make an earlier reference ambiguous.
func Resolve(v *fold.View, handle string, asOf int64) (*fold.Ticket, error) {
	h := strings.TrimSpace(handle)
	if op.ValidID(h, op.PrefixTicket) {
		t := v.FindTicket(h)
		if t == nil || (asOf > 0 && t.CreatedMs >= asOf) {
			return nil, wrapNF("no ticket %s", h)
		}
		return t, nil
	}
	if m := slugHandle.FindStringSubmatch(h); m != nil {
		if m[1] != v.Slug {
			return nil, wrapNF("handle is for project %q, this ledger is %q", m[1], v.Slug)
		}
		h = m[2]
	}
	h = strings.ToLower(h)
	if !hexHandle.MatchString(h) {
		return nil, usagef("a handle needs at least 8 hex digits (or a tk_ id), got %q", handle)
	}
	var hits []*fold.Ticket
	for i := range v.Tickets {
		t := &v.Tickets[i]
		if asOf > 0 && t.CreatedMs >= asOf {
			continue
		}
		if strings.HasPrefix(t.HandleHash, h) {
			hits = append(hits, t)
		}
	}
	switch len(hits) {
	case 0:
		return nil, wrapNF("no ticket matches %s", h)
	case 1:
		return hits[0], nil
	}
	return nil, &codedErr{kind: ledger.ErrAmbiguous, msg: "handle " + h + " matches several tickets; use more hex digits"}
}

func wrapNF(format string, a ...any) error {
	return &codedErr{kind: ledger.ErrNotFound, msg: sprintf(format, a...)}
}

var errRefusedKind = ledger.ErrRefused
