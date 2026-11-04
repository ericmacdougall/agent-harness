// Package legacyimport reads a 0.1.0 console data directory and imports it, one way,
// into the event log. It follows plans/CONSOLE-KERNEL-K3.md. Nothing calls it until
// K10 wires import.
package legacyimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Limits that 6172744 applies when it reads its journal (journal.go:16, :23).
const (
	MaxJournalBytes = 8 << 20
	maxLineBytes    = 65536
)

// ErrRefused marks every refusal before commit. The directory is left as it was.
var ErrRefused = errors.New("legacy import refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// record is 6172744's journalRecord, decoded leniently as 0.1.0 does: unknown fields
// are ignored and a null line is a zero record.
type record struct {
	At                  string          `json:"at"`
	SessionID           string          `json:"sessionId"`
	Provider            string          `json:"provider"`
	ProviderID          string          `json:"providerId"`
	ProfileID           string          `json:"profileId,omitempty"`
	CWD                 string          `json:"cwd"`
	RequestID           string          `json:"requestId,omitempty"`
	State               string          `json:"state"`
	TaskID              string          `json:"taskId,omitempty"`
	TaskGeneration      uint64          `json:"taskGeneration,omitempty"`
	Checkpoint          *Checkpoint     `json:"checkpoint,omitempty"`
	ReviewParent        string          `json:"reviewParent,omitempty"`
	ReviewTaskID        string          `json:"reviewTaskId,omitempty"`
	ReviewGeneration    uint64          `json:"reviewGeneration,omitempty"`
	ReviewStage         string          `json:"reviewStage,omitempty"`
	Cascade             json.RawMessage `json:"cascade,omitempty"`
	ReviewInputRevision uint64          `json:"reviewInputRevision,omitempty"`
}

// Checkpoint is the part of 6172744's checkpointRecord the import carries. Subject,
// attempts and bursts are task state for K1d and are not read here.
type Checkpoint struct {
	InputRevision uint64            `json:"inputRevision"`
	ObjectiveHash string            `json:"objectiveHash"`
	ID            string            `json:"id"`
	Generation    uint64            `json:"generation"`
	State         string            `json:"state"`
	Stage         string            `json:"stage"`
	Passes        map[string]string `json:"passes"`
}

// States 6172744's record() can write. Any other state refuses the import.
var knownStates = map[string]bool{
	"created": true, "intent": true, "accepted": true, "rejected": true, "unknown": true,
	"paused": true, "final": true, "review_unknown": true, "cwd": true, "closed": true,
	"admission_failed": true,
}

// receiptStates carry the request a receipt is about.
var receiptStates = map[string]bool{
	"intent": true, "accepted": true, "rejected": true, "unknown": true, "paused": true,
	"final": true, "review_unknown": true,
}

// Session is one session 0.1.0 would restore, before its 24-session window.
type Session struct {
	ID, Provider, ProviderID, ProfileID, CWD string
	// LastState is the state of the session's last record, which decides only closed.
	LastState string
	// RequestID and RequestState come from the last record that carries a request.
	RequestID, RequestState string
	// Checkpoint is the latest task record for the session, as restoreCheckpoint reads it.
	Checkpoint *Checkpoint
	TaskID     string
	TaskGen    uint64
}

// Review is one review record, restored by 0.1.0 whatever its state.
type Review struct {
	SessionID, Parent, State string
}

// Journal is a decoded sessions.jsonl.
type Journal struct {
	Sessions []Session
	Reviews  []Review
	// Digest is SHA-256 over every byte except a torn tail.
	Digest string
	// Torn is a final line with no newline that does not parse, never acknowledged.
	Torn []byte
	// Present is false when there was no journal file.
	Present bool
}

// Acknowledged returns data without its torn tail, if any. A final line with no
// newline that parses is a complete record: 0.1.0 reads it, so it is kept.
func Acknowledged(data []byte) (kept, torn []byte) {
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return data, nil
	}
	start := bytes.LastIndexByte(data, '\n') + 1
	last := data[start:]
	var probe any
	if len(last) < maxLineBytes && json.Unmarshal(last, &probe) == nil {
		return data, nil
	}
	return data[:start], last
}

// JournalDigest is the digest the import records and recovery compares.
func JournalDigest(data []byte) string {
	kept, _ := Acknowledged(data)
	sum := sha256.Sum256(kept)
	return hex.EncodeToString(sum[:])
}

// DecodeJournal reads journal bytes the way 6172744's restore() does, except that it
// keeps every session that is not closed instead of the last 24, and it refuses a
// state outside knownStates. A torn tail is reported, not refused.
func DecodeJournal(data []byte, present bool) (Journal, error) {
	out := Journal{Present: present, Digest: JournalDigest(data)}
	if len(data) > MaxJournalBytes {
		return out, refuse("journal is larger than 0.1.0 can read")
	}
	kept, torn := Acknowledged(data)
	out.Torn = torn
	records := map[string]record{}
	lastRequest := map[string]record{}
	checkpoints := map[string]record{}
	reviews := map[string]record{}
	var order, reviewOrder []string
	lines := strings.Split(string(kept), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, line := range lines {
		if len(line) >= maxLineBytes {
			return out, refuse("journal line %d is longer than 0.1.0 can read", i+1)
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return out, refuse("journal line %d is not a complete record", i+1)
		}
		if r.SessionID != "" && !knownStates[r.State] && !strings.HasPrefix(r.State, "checkpoint:") {
			return out, refuse("journal line %d has a state this importer does not know", i+1)
		}
		if r.ReviewParent != "" {
			if _, seen := reviews[r.SessionID]; !seen {
				reviewOrder = append(reviewOrder, r.SessionID)
			}
			reviews[r.SessionID] = r
			continue
		}
		// Additive, as in restore(): a task record is also a session record.
		if r.TaskID != "" || r.Checkpoint != nil {
			checkpoints[r.SessionID] = r
		}
		if strings.HasPrefix(r.State, "checkpoint:") || r.SessionID == "" || r.ProviderID == "" {
			continue
		}
		if _, seen := records[r.SessionID]; !seen {
			order = append(order, r.SessionID)
		}
		records[r.SessionID] = r
		if r.RequestID != "" && receiptStates[r.State] {
			lastRequest[r.SessionID] = r
		}
	}
	for _, id := range order {
		r := records[id]
		if r.State == "closed" {
			continue
		}
		s := Session{ID: id, Provider: r.Provider, ProviderID: r.ProviderID, ProfileID: r.ProfileID, CWD: r.CWD, LastState: r.State}
		if req, ok := lastRequest[id]; ok {
			s.RequestID, s.RequestState = req.RequestID, req.State
		}
		if cp, ok := checkpoints[id]; ok {
			s.Checkpoint, s.TaskID, s.TaskGen = cp.Checkpoint, cp.TaskID, cp.TaskGeneration
		}
		out.Sessions = append(out.Sessions, s)
	}
	for _, id := range reviewOrder {
		r := reviews[id]
		out.Reviews = append(out.Reviews, Review{SessionID: id, Parent: r.ReviewParent, State: r.State})
	}
	return out, nil
}
