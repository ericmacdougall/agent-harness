// Package kernel is the console's state machine: closed enums, append-only facts,
// a pure Decide, and a pure Reduce that is the sole writer of authority. It does
// no I/O and reads no clock, so live state and restart are one fold over one log.
package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion = 1
	maxFactBytes  = 64 << 10
	maxJSONDepth  = 8
	maxJSONMember = 64
	// MaxReasonBytes bounds the one user-written field the log holds.
	MaxReasonBytes = 500
)

type FactKind string

const (
	FactProcessRestarted          FactKind = "ProcessRestarted"
	FactLegacyImportCompleted     FactKind = "LegacyImportCompleted"
	FactSessionCreated            FactKind = "SessionCreated"
	FactConversationBound         FactKind = "ConversationBound"
	FactProviderConnected         FactKind = "ProviderConnected"
	FactProviderDisconnected      FactKind = "ProviderDisconnected"
	FactRuntimeIdentityBound      FactKind = "RuntimeIdentityBound"
	FactAuthBoundaryCrossed       FactKind = "AuthBoundaryCrossed"
	FactCwdChanged                FactKind = "CwdChanged"
	FactSessionClosed             FactKind = "SessionClosed"
	FactAbandoned                 FactKind = "Abandoned"
	FactSessionQuarantined        FactKind = "SessionQuarantined"
	FactSupervisionChanged        FactKind = "SupervisionChanged"
	FactCascadeSelected           FactKind = "CascadeSelected"
	FactPolicyBound               FactKind = "PolicyBound"
	FactContinuationBudgetChanged FactKind = "ContinuationBudgetChanged"
	FactRequestIntended           FactKind = "RequestIntended"
	FactProviderAccepted          FactKind = "ProviderAccepted"
	FactProviderRefused           FactKind = "ProviderRefused"
	FactProviderCompleted         FactKind = "ProviderCompleted"
	FactOutcomeUnknown            FactKind = "OutcomeUnknown"
	FactTurnBound                 FactKind = "TurnBound"
	FactLateFrameObserved         FactKind = "LateFrameObserved"
	FactAdmissionRefused          FactKind = "AdmissionRefused"
	FactControlRequested          FactKind = "ControlRequested"
	FactControlOutcome            FactKind = "ControlOutcome"
	FactQuestionOpened            FactKind = "QuestionOpened"
	FactQuestionAnswered          FactKind = "QuestionAnswered"
	FactQuestionRevoked           FactKind = "QuestionRevoked"
	FactChildObserved             FactKind = "ChildObserved"
	FactChildControlOutcome       FactKind = "ChildControlOutcome"
	FactChildQuarantined          FactKind = "ChildQuarantined"
	FactInputQueued               FactKind = "InputQueued"
	FactInputDispatchPrepared     FactKind = "InputDispatchPrepared"
	FactInputOutcome              FactKind = "InputOutcome"
	FactInputDiscarded            FactKind = "InputDiscarded"
	FactPayloadReleased           FactKind = "PayloadReleased"
	FactReviewStarted             FactKind = "ReviewStarted"
	FactReviewCancelled           FactKind = "ReviewCancelled"
	FactReviewOutcome             FactKind = "ReviewOutcome"
	FactReviewResultPending       FactKind = "ReviewResultPending"
	FactCheckpointRecorded        FactKind = "CheckpointRecorded"
	FactLegacyImported            FactKind = "LegacyImported"
	FactLegacyInputHeld           FactKind = "LegacyInputHeld"
)

// knownFacts is closed: an unknown kind refuses the log rather than being skipped.
var knownFacts = map[FactKind]bool{
	FactProcessRestarted: true, FactLegacyImportCompleted: true, FactSessionCreated: true, FactConversationBound: true,
	FactProviderConnected: true, FactProviderDisconnected: true, FactRuntimeIdentityBound: true, FactAuthBoundaryCrossed: true,
	FactCwdChanged: true, FactSessionClosed: true, FactAbandoned: true, FactSessionQuarantined: true, FactSupervisionChanged: true,
	FactCascadeSelected: true, FactPolicyBound: true, FactContinuationBudgetChanged: true, FactRequestIntended: true,
	FactProviderAccepted: true, FactProviderRefused: true, FactProviderCompleted: true, FactOutcomeUnknown: true, FactTurnBound: true,
	FactLateFrameObserved: true, FactAdmissionRefused: true, FactControlRequested: true, FactControlOutcome: true,
	FactQuestionOpened: true, FactQuestionAnswered: true, FactQuestionRevoked: true, FactChildObserved: true,
	FactChildControlOutcome: true, FactChildQuarantined: true, FactInputQueued: true, FactInputDispatchPrepared: true,
	FactInputOutcome: true, FactInputDiscarded: true, FactPayloadReleased: true, FactReviewStarted: true, FactReviewCancelled: true,
	FactReviewOutcome: true, FactReviewResultPending: true, FactCheckpointRecorded: true, FactLegacyImported: true, FactLegacyInputHeld: true,
}

func globalFact(kind FactKind) bool {
	return kind == FactProcessRestarted || kind == FactLegacyImportCompleted
}

// Fact is one committed event. It holds identity, enums and digests only: prompts,
// question text, attachment bytes and secrets never appear here. Reason is the sole
// user-written field, bounded here and redacted through RedactedReason.
type Fact struct {
	Seq             uint64            `json:"seq"`
	SchemaVersion   int               `json:"schemaVersion"`
	At              string            `json:"at"`
	Kind            FactKind          `json:"kind"`
	SessionID       string            `json:"sessionId,omitempty"`
	SessionRevision uint64            `json:"sessionRevision,omitempty"`
	Provider        string            `json:"provider,omitempty"`
	ProviderID      string            `json:"providerId,omitempty"`
	ProfileID       string            `json:"profileId,omitempty"`
	CWD             string            `json:"cwd,omitempty"`
	RequestID       string            `json:"requestId,omitempty"`
	TurnID          string            `json:"turnId,omitempty"`
	ID              string            `json:"id,omitempty"`
	Role            string            `json:"role,omitempty"`
	Status          string            `json:"status,omitempty"`
	ReasonCode      string            `json:"reasonCode,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Control         string            `json:"control,omitempty"`
	Outcome         string            `json:"outcome,omitempty"`
	LateKind        string            `json:"lateKind,omitempty"`
	Digest          string            `json:"digest,omitempty"`
	ExpiresAt       string            `json:"expiresAt,omitempty"`
	TaskID          string            `json:"taskId,omitempty"`
	Generation      uint64            `json:"generation,omitempty"`
	InputRevision   uint64            `json:"inputRevision,omitempty"`
	ObjectiveHash   string            `json:"objectiveHash,omitempty"`
	PayloadHash     string            `json:"payloadHash,omitempty"`
	Attachments     []string          `json:"attachments,omitempty"`
	Stage           string            `json:"stage,omitempty"`
	Verdict         string            `json:"verdict,omitempty"`
	State           string            `json:"state,omitempty"`
	RuntimeIdentity string            `json:"runtimeIdentity,omitempty"`
	PolicyRevision  string            `json:"policyRevision,omitempty"`
	Cascade         string            `json:"cascade,omitempty"`
	RemainingBursts int64             `json:"remainingBursts,omitempty"`
	Progress        int64             `json:"progress,omitempty"`
	Receipt         Receipt           `json:"receipt,omitempty"`
	Passes          map[string]string `json:"passes,omitempty"`
}

var factFields = func() map[string]bool {
	fields := map[string]bool{}
	kind := reflect.TypeOf(Fact{})
	for i := 0; i < kind.NumField(); i++ {
		fields[strings.Split(kind.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	return fields
}()

var (
	ErrMalformedFact = errors.New("malformed fact")
	// ErrUnreadableLog means the log cannot be interpreted at all. It refuses.
	ErrUnreadableLog = errors.New("unreadable log")
	// ErrIllegalFact is an invalid transition in a readable log. During replay it
	// quarantines the session; the rest of the console keeps running.
	ErrIllegalFact = errors.New("illegal fact")
)

// EncodeFact is the only way a fact reaches storage. encoding/json orders struct
// fields by declaration and map keys by sort, so the bytes are canonical.
func EncodeFact(f Fact) ([]byte, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFactBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrMalformedFact, maxFactBytes)
	}
	return data, nil
}

// DecodeFact is strict. encoding/json folds field names, including Unicode aliases
// such as U+017F for s, so names are checked exactly before semantic decoding.
func DecodeFact(data []byte) (Fact, error) {
	var f Fact
	if len(data) == 0 || len(data) > maxFactBytes || !utf8.Valid(data) {
		return f, fmt.Errorf("%w: size or encoding", ErrMalformedFact)
	}
	if err := checkJSONKeys(data, factFields); err != nil {
		return f, fmt.Errorf("%w: %v", ErrMalformedFact, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return Fact{}, fmt.Errorf("%w: %v", ErrMalformedFact, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Fact{}, fmt.Errorf("%w: trailing content", ErrMalformedFact)
	}
	return f, nil
}

// checkJSONKeys requires an object whose top-level keys match allowed exactly, with
// no duplicates at any depth. Nested keys are data, such as stage names in passes.
func checkJSONKeys(data []byte, allowed map[string]bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("not an object")
	}
	return walkJSONObject(decoder, allowed, 1)
}

func walkJSONObject(decoder *json.Decoder, allowed map[string]bool, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("nesting too deep")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("non-string key")
		}
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		if len(seen) > maxJSONMember {
			return errors.New("too many members")
		}
		if allowed != nil && !allowed[key] {
			return fmt.Errorf("unknown key %q", key)
		}
		if err = walkJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		return walkJSONObject(decoder, nil, depth)
	case json.Delim('['):
		if depth > maxJSONDepth {
			return errors.New("nesting too deep")
		}
		for decoder.More() {
			if err = walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return nil
}
