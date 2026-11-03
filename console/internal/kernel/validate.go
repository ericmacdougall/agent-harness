package kernel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Facts hold identity, closed enums, digests and one redacted reason. This is the
// backstop for INV6 and for closed states: free text from a provider cannot reach
// the log, and no value outside an enum can reach a reducer rule.
var (
	identityPattern = regexp.MustCompile(`^[A-Za-z0-9._:/@+=-]{1,128}$`)
	digestPattern   = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
	codePattern     = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	timePattern     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$`)
)

// errBadValue marks a malformed value, which Decide reports as a refusal.
var errBadValue = errors.New("value outside its enum or shape")

func oneOfValues(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

var finalStatuses = []string{"completed", "failed", "interrupted"}
var inputOutcomes = []string{InputRetained, InputUnknown, InputHeld}
var heldStatuses = []string{InputHeld, InputUnknown, InputRetained, InputCleanup}
var verdicts = []string{"pass", "block", "failed", "unknown"}
var checkpointStates = []string{TaskActive, TaskBlocked, TaskHandoff, TaskNeedsReview, TaskComplete}
var childStatuses = []string{ChildRunning, "completed", "failed", "interrupted", ChildUnknown}
var supervisionStates = []string{SupervisionActive, SupervisionWaiting, SupervisionPaused, SupervisionBlocked}
var lateKinds = []string{"accepted", "refused", "write_unknown", "turn_bound", "final", "question", "review", "conversation", "connected", "disconnected", "child"}

func validateFact(f Fact) error {
	fail := func(field string) error {
		return fmt.Errorf("%w: %s on %s", errBadValue, field, f.Kind)
	}
	if !timePattern.MatchString(f.At) {
		return fail("at")
	}
	if f.ExpiresAt != "" && !timePattern.MatchString(f.ExpiresAt) {
		return fail("expiresAt")
	}
	for name, value := range map[string]string{"sessionId": f.SessionID, "providerId": f.ProviderID, "profileId": f.ProfileID, "requestId": f.RequestID, "turnId": f.TurnID, "id": f.ID, "role": f.Role, "taskId": f.TaskID, "stage": f.Stage, "policyRevision": f.PolicyRevision, "cascade": f.Cascade} {
		if value != "" && !identityPattern.MatchString(value) {
			return fail(name)
		}
	}
	for name, value := range map[string]string{"digest": f.Digest, "objectiveHash": f.ObjectiveHash, "payloadHash": f.PayloadHash, "runtimeIdentity": f.RuntimeIdentity} {
		if value != "" && !digestPattern.MatchString(value) {
			return fail(name)
		}
	}
	if f.ReasonCode != "" && !codePattern.MatchString(f.ReasonCode) {
		return fail("reasonCode")
	}
	if f.Provider != "" && !oneOfValues(f.Provider, ProviderCodex, ProviderClaude) {
		return fail("provider")
	}
	if len(f.CWD) > 4096 || strings.ContainsAny(f.CWD, "\x00\n\r") {
		return fail("cwd")
	}
	if len(f.Attachments) > 16 {
		return fail("attachments")
	}
	for _, path := range f.Attachments {
		if path == "" || len(path) > 4096 || strings.ContainsAny(path, "\x00\n\r") {
			return fail("attachments")
		}
	}
	if f.Reason != "" && (f.Kind != FactAbandoned && f.Kind != FactLegacyImported || len(f.Reason) > MaxReasonBytes) {
		return fail("reason")
	}
	valid := true
	switch f.Kind {
	case FactSessionCreated:
		valid = oneOfValues(f.Provider, ProviderCodex, ProviderClaude) && oneOfValues(f.Status, "", "connected")
	case FactRequestIntended:
		valid = f.RequestID != "" && oneOfValues(f.Status, "", "new_objective")
	case FactProviderCompleted:
		valid = oneOfValues(f.Status, finalStatuses...)
	case FactTurnBound:
		valid = f.TurnID != ""
	case FactLateFrameObserved:
		valid = oneOfValues(f.LateKind, lateKinds...) && (f.Status == "" || codePattern.MatchString(f.Status))
	case FactControlRequested:
		valid = oneOfValues(f.Control, "pause", "stop", "resume")
	case FactControlOutcome:
		valid = oneOfValues(f.Outcome, "confirmed", "rejected", "unconfirmed")
	case FactQuestionOpened:
		valid = f.ID != "" && f.ExpiresAt != "" && (f.Status == "" || codePattern.MatchString(f.Status))
	case FactQuestionAnswered, FactQuestionRevoked:
		valid = f.ID != ""
	case FactChildObserved, FactChildControlOutcome:
		valid = f.ID != "" && oneOfValues(f.Status, childStatuses...)
	case FactChildQuarantined:
		valid = f.ID != ""
	case FactInputQueued:
		valid = f.RequestID != "" && f.PayloadHash != ""
	case FactInputDispatchPrepared:
		valid = f.RequestID != "" && f.TaskID != "" && f.InputRevision > 0
	case FactInputOutcome:
		valid = f.RequestID != "" && oneOfValues(f.Status, inputOutcomes...)
	case FactLegacyInputHeld:
		valid = f.RequestID != "" && f.PayloadHash != "" && oneOfValues(f.Status, heldStatuses...)
	case FactReviewStarted:
		valid = f.ID != "" && f.Stage != "" && f.Digest != ""
	case FactReviewOutcome:
		valid = f.ID != "" && oneOfValues(f.Verdict, verdicts...)
	case FactReviewResultPending:
		valid = oneOfValues(f.Status, "pending", "clear")
	case FactCheckpointRecorded:
		valid = f.TaskID != "" && oneOfValues(f.State, checkpointStates...)
	case FactSupervisionChanged:
		valid = oneOfValues(f.State, supervisionStates...)
	case FactRuntimeIdentityBound:
		valid = f.RuntimeIdentity != ""
	case FactLegacyImported:
		valid = f.State == "" || oneOfValues(f.State, append([]string{TaskIdle}, checkpointStates...)...)
	}
	if !valid {
		return fail("value")
	}
	return nil
}

// RedactedReason makes the redaction boundary a type: a reason cannot reach Decide
// without passing through a redactor, and K1 itself holds no secret list.
type RedactedReason struct{ text string }

// Redact applies the console's secret redactor to user-written text.
func Redact(text string, redactor func(string) string) RedactedReason {
	return RedactedReason{text: strings.TrimSpace(redactor(text))}
}

func (r RedactedReason) String() string { return r.text }
