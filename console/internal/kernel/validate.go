package kernel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Facts hold identity, closed enums, digests and one redacted reason. This is the
// backstop for INV6 and for closed states: free text from a provider cannot reach
// the log, and no value outside an enum can reach a reducer rule.
var (
	identityPattern    = regexp.MustCompile(`^[A-Za-z0-9._:/@+=-]{1,128}$`)
	digestPattern      = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
	codePattern        = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	frameDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	timePattern        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$`)
)

// validTime requires the fixed width that makes times compare as strings, and a real
// calendar date. Parsing reads no clock.
func validTime(at string) bool {
	if !timePattern.MatchString(at) {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05.000000000Z", at)
	return err == nil
}

// ValidateFact checks a fact's values against their closed sets and shapes, the same
// check Reduce applies. The event log calls it so nothing out of shape is stored.
func ValidateFact(f Fact) error { return validateFact(f) }

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
var lateKinds = []string{"accepted", "refused", "write_unknown", "turn_bound", "final", "conversation", "connected", "disconnected", "control_outcome"}

// closedStatus is the rule that no enum-bearing string is free on any kind: each kind
// names the exact values Status, Control, Outcome, LateKind and State may hold.
func closedFields(f Fact) bool {
	status, control, outcome, late := []string{""}, []string{""}, []string{""}, []string{""}
	switch f.Kind {
	case FactProviderCompleted:
		status = finalStatuses
	case FactLateFrameObserved:
		if f.Status != "" && !codePattern.MatchString(f.Status) || f.Digest != "" && !frameDigestPattern.MatchString(f.Digest) {
			return false
		}
		status, late = []string{f.Status}, lateKinds
	case FactControlRequested:
		control = []string{"pause", "stop"}
	case FactControlOutcome:
		control, outcome = []string{"pause", "stop"}, []string{"confirmed", "rejected", "unconfirmed"}
	}
	return oneOfValues(f.Status, status...) && oneOfValues(f.Control, control...) && oneOfValues(f.Outcome, outcome...) && oneOfValues(f.LateKind, late...) && (f.State == "" || f.Kind == FactLegacyImported && codePattern.MatchString(f.State))
}

func validateFact(f Fact) error {
	fail := func(field string) error {
		return fmt.Errorf("%w: %s on %s", errBadValue, field, f.Kind)
	}
	if !validTime(f.At) {
		return fail("at")
	}
	for name, value := range map[string]string{"sessionId": f.SessionID, "providerId": f.ProviderID, "profileId": f.ProfileID, "requestId": f.RequestID, "turnId": f.TurnID, "taskId": f.TaskID} {
		if value != "" && !identityPattern.MatchString(value) {
			return fail(name)
		}
	}
	for name, value := range map[string]string{"digest": f.Digest, "objectiveHash": f.ObjectiveHash, "runtimeIdentity": f.RuntimeIdentity} {
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
	if len(f.CWD) > 4096 || !utf8.ValidString(f.CWD) || strings.IndexFunc(f.CWD, unicode.IsControl) >= 0 {
		return fail("cwd")
	}
	if f.Reason != "" && (f.Kind != FactAbandoned && f.Kind != FactLegacyImported || len(f.Reason) > MaxReasonBytes || !utf8.ValidString(f.Reason)) {
		return fail("reason")
	}
	if !oneOfValues(string(f.Receipt), "", string(ReceiptIntent), string(ReceiptAccepted), string(ReceiptFinal), string(ReceiptUnknown), string(ReceiptRejected), string(ReceiptAbandoned)) {
		return fail("receipt")
	}
	if !closedFields(f) {
		return fail("closed value")
	}
	valid := true
	switch f.Kind {
	case FactSessionCreated:
		valid = oneOfValues(f.Provider, ProviderCodex, ProviderClaude)
	case FactRequestIntended:
		valid = f.RequestID != ""
	case FactTurnBound:
		valid = f.TurnID != ""
	case FactRuntimeIdentityBound:
		valid = f.RuntimeIdentity != ""
	case FactCwdChanged:
		valid = f.CWD != ""
	case FactAbandoned:
		valid = f.Reason != ""
	case FactSessionQuarantined:
		valid = f.ReasonCode != ""
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
	if redactor == nil {
		return RedactedReason{}
	}
	return RedactedReason{text: strings.TrimSpace(redactor(text))}
}

func (r RedactedReason) String() string { return r.text }
