package op

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// HLC is a hybrid logical clock value. Total op order is (WallMs, Ctr, writer, id).
type HLC struct {
	WallMs int64
	Ctr    int64
}

const (
	// WitnessBound: another writer's clock is witnessed only if it is at most this far ahead of now.
	WitnessBound int64 = 5 * 60 * 1000
	// BehindSlack: ops older than project.create minus this are flagged clock_behind.
	BehindSlack int64 = 24 * 60 * 60 * 1000
	// Epoch: ops before 2026-01-01T00:00:00Z are flagged clock_behind.
	Epoch  int64 = 1767225600000
	maxCtr       = 1 << 31
)

// Less is the HLC order (without the writer/id tie-breakers).
func (h HLC) Less(o HLC) bool {
	if h.WallMs != o.WallMs {
		return h.WallMs < o.WallMs
	}
	return h.Ctr < o.Ctr
}

// Name is the pack tree entry name for h: hlc-<wall_ms>-<ctr>.
func (h HLC) Name() string { return fmt.Sprintf("hlc-%d-%d", h.WallMs, h.Ctr) }

// ParseHLCName parses hlc-<wall_ms>-<ctr> in canonical decimal (no sign, no leading zeros).
func ParseHLCName(s string) (HLC, error) {
	rest, ok := strings.CutPrefix(s, "hlc-")
	if !ok {
		return HLC{}, errors.New("hlc: bad entry name")
	}
	w, c, ok := strings.Cut(rest, "-")
	if !ok {
		return HLC{}, errors.New("hlc: bad entry name")
	}
	wall, err1 := canonInt(w)
	ctr, err2 := canonInt(c)
	if err1 != nil || err2 != nil || ctr >= maxCtr {
		return HLC{}, errors.New("hlc: bad entry name")
	}
	return HLC{wall, ctr}, nil
}

func canonInt(s string) (int64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || len(s) > 16 {
		return 0, errors.New("not canonical")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not canonical")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

// Tick returns the next clock value for a local event. last is the writer's own last HLC (read from its
// ref tip, the authoritative source). witness is the highest foreign clock the caller already filtered
// with Witnessable. The result is strictly greater than last and not less than witness.
func Tick(last HLC, now int64, witness HLC) (HLC, error) {
	wall := max(now, last.WallMs, witness.WallMs)
	var ctr int64
	switch {
	case wall == last.WallMs && wall == witness.WallMs:
		ctr = max(last.Ctr, witness.Ctr) + 1
	case wall == last.WallMs:
		ctr = last.Ctr + 1
	case wall == witness.WallMs:
		ctr = witness.Ctr + 1
	}
	if ctr >= maxCtr {
		return HLC{}, errors.New("hlc: counter overflow")
	}
	if wall >= 1<<48 {
		return HLC{}, errors.New("hlc: wall clock out of range")
	}
	return HLC{wall, ctr}, nil
}

// Witnessable reports whether a foreign clock may be witnessed at now (at most WitnessBound ahead).
func Witnessable(h HLC, now int64) bool { return h.WallMs <= now+WitnessBound }
