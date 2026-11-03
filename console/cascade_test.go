package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCascadeConsumesOrderedExplicitStagesBeforeFreshDispatch(t *testing.T) {
	a, _, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	attempted := []string{}
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		policy, _ := defaultPolicy(provider, profile, stage)
		policy.Cascade = []policyStep{{Provider: "claude", ProfileID: "second", Model: "second-model"}, {Provider: "codex", ProfileID: "third", Model: "stage-model", Effort: "low"}}
		return policy, nil
	}
	a.runtime = func(provider, profile string) (string, []string, error) {
		attempted = append(attempted, profile)
		if profile != "third" {
			return "", nil, &exec.Error{Name: provider, Err: exec.ErrNotFound}
		}
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil
	}
	current, err := a.createSession("claude", a.sessions[0].CWD, "first")
	if err != nil {
		t.Fatal("configured cascade was not dispatched", err)
	}
	if current.Provider != "codex" || current.ProfileID != "third" || current.Model != "stage-model" || current.Effort != "low" || current.Cascade == nil || current.Cascade.Stage != 2 {
		t.Fatal("actual selected stage/params mismatch", current.Provider, current.ProfileID, current.Model, current.Cascade)
	}
	if len(attempted) < 3 || attempted[0] != "first" || attempted[1] != "second" || attempted[2] != "third" {
		t.Fatal("configured stage order ignored", attempted)
	}
}
func TestCascadeSelectedStageControlsNativeParamsAndDedup(t *testing.T) {
	a, _, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	audit := filepath.Join(t.TempDir(), "rpc.jsonl")
	calls := 0
	steps := []policyStep{{Provider: "codex", ProfileID: "fallback", Model: "selected-model", Effort: "low"}}
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		p, _ := defaultPolicy(provider, profile, stage)
		p.Cascade = steps
		return p, nil
	}
	a.runtime = func(provider, profile string) (string, []string, error) {
		calls++
		if provider == "claude" {
			return "", nil, &exec.Error{Name: provider, Err: exec.ErrNotFound}
		}
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1", "HARNESS_CONSOLE_RPC_AUDIT="+audit), nil
	}
	s, err := a.createSession("claude", a.sessions[0].CWD, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.send(s.ID, "request-one", "bounded synthetic request", nil, false); err != nil {
		t.Fatal(err)
	}
	before := calls
	if err = a.send(s.ID, "request-one", "bounded synthetic request", nil, false); err != nil || calls != before {
		t.Fatal("duplicate input re-admitted cascade", err)
	}
	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	turns := 0
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var packet rpcPacket
		_ = json.Unmarshal(scan.Bytes(), &packet)
		if packet.Method == "turn/start" {
			turns++
			params := object(packet.Params)
			if textField(params, "model") != "selected-model" || textField(params, "effort") != "low" || textField(params, "clientUserMessageId") != "request-one" {
				t.Fatal("selected runtime not dispatched", params)
			}
		}
	}
	if turns != 1 || s.Cascade.RequestID != "request-one" || s.Cascade.Revision != "builtin-v1" {
		t.Fatal("stage trace not bound to one request", turns, s.Cascade)
	}
}
func TestCascadeGenericAuthQuotaAndUnknownErrorsNeverAdvance(t *testing.T) {
	for _, reason := range []string{"authentication required", "quota exhausted", "provider request outcome unknown"} {
		t.Run(reason, func(t *testing.T) {
			a, _, _ := checkpointFixture(t)
			calls := 0
			a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
				p, _ := defaultPolicy(provider, profile, stage)
				p.Cascade = []policyStep{{Provider: "codex", ProfileID: "fallback", Model: "other"}}
				return p, nil
			}
			a.runtime = func(string, string) (string, []string, error) { calls++; return "", nil, errors.New(reason) }
			if _, err := a.createSession("claude", a.sessions[0].CWD, "primary"); err == nil || calls != 1 {
				t.Fatal("nonlocal admission error retried", err, calls)
			}
		})
	}
}
func TestCascadeUnknownTurnNeverChangesActiveIdentity(t *testing.T) {
	for _, failure := range []string{"disconnect", "authentication required", "quota exhausted"} {
		t.Run(failure, func(t *testing.T) {
			a, _, _ := checkpointFixture(t)
			binary, _ := os.Executable()
			profiles := []string{}
			a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
				p, _ := defaultPolicy(provider, profile, stage)
				p.Cascade = []policyStep{{Provider: "claude", ProfileID: "other", Model: "fallback"}}
				return p, nil
			}
			a.runtime = func(provider, profile string) (string, []string, error) {
				profiles = append(profiles, profile)
				return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1", "HARNESS_CONSOLE_RPC_FAIL_TURN="+failure), nil
			}
			s, err := a.createSession("codex", a.sessions[0].CWD, "primary")
			if err != nil {
				t.Fatal(err)
			}
			identity := s.ProviderID
			if err = a.send(s.ID, "uncertain", "bounded test", nil, false); err == nil {
				t.Fatal("provider failure accepted")
			}
			a.mu.Lock()
			changed := s.ProviderID != identity || s.ProfileID != "primary" || s.Cascade.Stage != 0
			a.mu.Unlock()
			if changed {
				t.Fatal("active identity switched after provider failure")
			}
			for _, profile := range profiles {
				if profile != "primary" {
					t.Fatal("provider failure dispatched fallback account", profiles)
				}
			}
		})
	}
}
func TestCascadeRecoveryRetainsSelectionAndNeverReplaysAcceptedInput(t *testing.T) {
	a, _, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		p, _ := defaultPolicy(provider, profile, stage)
		p.Cascade = []policyStep{{Provider: "codex", ProfileID: "fallback", Model: "pinned-model", Effort: "low"}}
		return p, nil
	}
	a.runtime = func(provider, profile string) (string, []string, error) {
		if provider == "claude" {
			return "", nil, &exec.Error{Name: provider, Err: exec.ErrNotFound}
		}
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil
	}
	s, err := a.createSession("claude", a.sessions[0].CWD, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.send(s.ID, "accepted-request", "bounded fixture", nil, false); err != nil {
		t.Fatal(err)
	}
	fresh := &app{journal: a.journal}
	if err = fresh.restore(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.sessions) != 1 {
		t.Fatal("accepted session not restored")
	}
	restored := fresh.sessions[0]
	if !restored.Restored || restored.Cascade == nil || restored.Cascade.AdmissionID != s.Cascade.AdmissionID || restored.Cascade.RequestID != "accepted-request" || restored.Cascade.Selected.Model != "pinned-model" {
		t.Fatal("cascade identity lost on restart", restored.Cascade)
	}
	fresh.runtime = func(string, string) (string, []string, error) {
		t.Fatal("restored request re-admitted cascade")
		return "", nil, nil
	}
	if err = fresh.send(restored.ID, "accepted-request", "bounded fixture", nil, false); err == nil {
		t.Fatal("accepted unknown request replayed")
	}
}
func TestCascadePolicyRevisionChangeStopsBeforeAnotherRuntime(t *testing.T) {
	a, _, _ := checkpointFixture(t)
	calls := 0
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		p, _ := defaultPolicy(provider, profile, stage)
		p.Revision = "1"
		if profile == "fallback" {
			p.Revision = "2"
		}
		p.Cascade = []policyStep{{Provider: "codex", ProfileID: "fallback", Model: "other"}}
		return p, nil
	}
	a.runtime = func(string, string) (string, []string, error) {
		calls++
		return "", nil, &exec.Error{Name: "cli", Err: exec.ErrNotFound}
	}
	if _, err := a.createSession("claude", a.sessions[0].CWD, "primary"); err == nil || calls != 1 {
		t.Fatal("changed revision admitted a different runtime", err, calls)
	}
}
