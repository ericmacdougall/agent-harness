package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceCapacityCheckpointWire(t *testing.T) {
	input, err := parseCheckpoint(map[string]any{
		"taskId": "a-task", "generation": 1, "inputRevision": 1, "objectiveHash": "an-objective",
		"state": "wait_workspace_capacity", "minimumAvailableBytes": 8 << 20,
	})
	if err != nil || input.State != "wait_workspace_capacity" {
		t.Fatalf("typed workspace capacity checkpoint was rejected: %v", err)
	}
	on, _ := json.Marshal(checkpointTool(true))
	off, _ := json.Marshal(checkpointTool(false))
	if !strings.Contains(string(on), waitWorkspaceCapacity) || strings.Contains(string(off), "minimumAvailableBytes") {
		t.Fatal("workspace waiting tool surface must be opt-in")
	}
}

func workspaceNativeFixture(t *testing.T, enabled bool) (*app, *session) {
	t.Helper()
	if !workspaceCapacitySupported() {
		t.Skip("local descriptor capacity is unsupported")
	}
	a, s := queueNativeFixture(t)
	a.mu.Lock()
	a.workspaceWakeEnabled = enabled
	s.task.State = "active"
	a.mu.Unlock()
	return a, s
}

func armNativeWorkspaceFixture(t *testing.T, a *app, s *session, turn string, want bool) {
	t.Helper()
	a.mu.Lock()
	input := checkpointInput{
		TaskID: s.task.ID, Generation: s.task.Generation, InputRevision: s.task.InputRevision,
		ObjectiveHash: s.task.ObjectiveHash, State: waitWorkspaceCapacity, MinimumAvailableBytes: 1 << 20,
	}
	a.mu.Unlock()
	data, _ := json.Marshal(map[string]any{
		"threadId": s.ProviderID, "turnId": turn, "tool": "harness_console_checkpoint", "arguments": input,
	})
	a.codexQuestion(s.codex, rpcPacket{ID: json.RawMessage("82"), Method: "item/tool/call", Params: data})
	a.mu.Lock()
	defer a.mu.Unlock()
	if (s.workspaceWake != nil) != want {
		t.Fatalf("native workspace wait admission wrong: %s", s.task.State)
	}
}

func setWorkspaceBytes(a *app, s *session, amount uint64, filesystem string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sample := workspaceCapacitySample{directory: s.cwdInfo, filesystem: filesystem, available: amount}
	a.workspaceProbe = func(string) (workspaceCapacitySample, error) { return sample, nil }
}

func TestWorkspaceCapacityWakeNativeFinalThenBelowAndAbove(t *testing.T) {
	a, s := workspaceNativeFixture(t, true)
	armNativeWorkspaceFixture(t, a, s, "foreign-turn", false)
	armNativeWorkspaceFixture(t, a, s, "fixture-turn", true)
	setWorkspaceBytes(a, s, 0, "volume-A")
	a.pollWorkspaceCapacity()
	a.mu.Lock()
	wake, task := s.workspaceWake, s.task
	probes := wake.probes
	a.mu.Unlock()
	if probes != 0 {
		t.Fatal("sampled before the exact native turn had a durable final receipt")
	}
	finishNativeQueueTurn(a, s)
	setWorkspaceBytes(a, s, 2<<20, "volume-A")
	a.pollWorkspaceCapacity()
	a.mu.Lock()
	alreadyReadySpent := s.lastRequest != "original" || s.Supervision.RemainingBursts != 3 || wake.lastBelowBytes != nil
	a.mu.Unlock()
	if alreadyReadySpent {
		t.Fatal("first already-clear observation spent a wake")
	}
	setWorkspaceBytes(a, s, 0, "volume-A")
	a.pollWorkspaceCapacity()
	setWorkspaceBytes(a, s, 1<<20, "volume-A")
	a.pollWorkspaceCapacity()
	a.pollWorkspaceCapacity()
	a.scheduleInputs(s.ID)

	a.mu.Lock()
	badWake := s.task != task || s.task.InputRevision != wake.inputRevision || s.task.ObjectiveHash != wake.objectiveHash ||
		s.lastRequest != wake.receipt.ID || s.requests[wake.receipt.ID] != "accepted" ||
		s.Supervision.RemainingBursts != 2 || s.task.workspaceWakeReceipt.State != "spent"
	lastRequest, status, reason := s.lastRequest, s.Status, s.Supervision.Reason
	lastMessage := s.Messages[len(s.Messages)-1]
	a.mu.Unlock()
	if badWake {
		t.Fatalf("wake did not preserve objective and spend exactly once: request=%s status=%s reason=%s", lastRequest, status, reason)
	}
	if lastMessage.Text != capacityResumePrompt {
		t.Fatal("provider did not receive the bounded existing-objective continuation")
	}
	journal, err := os.Open(a.journal.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	spent := false
	scan := bufio.NewScanner(journal)
	for scan.Scan() {
		var r journalRecord
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.SessionID != s.ID || r.Checkpoint == nil || r.Checkpoint.WorkspaceWake == nil {
			continue
		}
		receipt := r.Checkpoint.WorkspaceWake
		if r.RequestID == wake.receipt.ID && r.State == "intent" {
			if !spent {
				t.Fatal("native send intent preceded durable wake spend")
			}
			return
		}
		if receipt.ID == wake.receipt.ID && receipt.State == "spent" && r.Checkpoint.Bursts == 2 && r.RequestID == "" {
			spent = receipt.MeasuredBelowBytes != nil && *receipt.MeasuredBelowBytes == 0 &&
				receipt.MeasuredReadyBytes != nil && *receipt.MeasuredReadyBytes == 1<<20
		}
	}
	t.Fatalf("missing wake intent in journal: %v", scan.Err())
}

func TestWorkspaceCapacityWakeDisabledAndUnsuccessfulFinal(t *testing.T) {
	a, s := workspaceNativeFixture(t, false)
	armNativeWorkspaceFixture(t, a, s, "fixture-turn", false)
	for _, finalStatus := range []string{"failed", "interrupted"} {
		t.Run(finalStatus, func(t *testing.T) {
			a, s := workspaceNativeFixture(t, true)
			armNativeWorkspaceFixture(t, a, s, "fixture-turn", true)
			completed, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turn": map[string]any{"id": "fixture-turn", "status": finalStatus}})
			a.codexEvent(s.codex, "turn/completed", completed)
			setWorkspaceBytes(a, s, 0, "volume-A")
			a.pollWorkspaceCapacity()
			setWorkspaceBytes(a, s, 2<<20, "volume-A")
			a.pollWorkspaceCapacity()
			a.mu.Lock()
			defer a.mu.Unlock()
			if s.lastRequest != "original" || s.Supervision.RemainingBursts != 3 {
				t.Fatal("non-successful native final received a workspace wake")
			}
		})
	}
}

func TestWorkspaceCapacityWakePauseDriftExpiryAndDurability(t *testing.T) {
	for _, failure := range []string{"pause", "filesystem", "revision", "expiry", "journal"} {
		t.Run(failure, func(t *testing.T) {
			a, s := workspaceNativeFixture(t, true)
			armNativeWorkspaceFixture(t, a, s, "fixture-turn", true)
			finishNativeQueueTurn(a, s)
			setWorkspaceBytes(a, s, 0, "volume-A")
			a.pollWorkspaceCapacity()
			setWorkspaceBytes(a, s, 2<<20, "volume-A")
			switch failure {
			case "pause":
				if err := a.control(s.ID, "pause", ""); err != nil {
					t.Fatal(err)
				}
			case "filesystem":
				setWorkspaceBytes(a, s, 2<<20, "volume-B")
			case "revision":
				a.mu.Lock()
				s.task.InputRevision++
				a.mu.Unlock()
			case "expiry":
				a.mu.Lock()
				s.workspaceWake.receipt.ExpiresAt = time.Now().Add(-time.Second)
				a.mu.Unlock()
			case "journal":
				a.mu.Lock()
				a.journalSync = func() error { return errors.New("test sync failure") }
				a.mu.Unlock()
			}
			a.pollWorkspaceCapacity()
			a.pollWorkspaceCapacity()
			a.mu.Lock()
			defer a.mu.Unlock()
			if s.lastRequest != "original" || (failure == "journal" && s.task.State != "unknown") {
				t.Fatalf("wake escaped %s: state=%s request=%s", failure, s.task.State, s.lastRequest)
			}
			if failure != "journal" && s.task.workspaceWakeReceipt.State != "revoked" {
				t.Fatalf("invalid watch remained armed after %s", failure)
			}
		})
	}
}

func TestWorkspaceCapacityWakeNeverOvertakesQueuedInput(t *testing.T) {
	a, s := workspaceNativeFixture(t, true)
	armNativeWorkspaceFixture(t, a, s, "fixture-turn", true)
	if _, err := a.enqueueInput(s.ID, "user-follow-up", "Authorized next user input", nil); err != nil {
		t.Fatal(err)
	}
	finishNativeQueueTurn(a, s)
	setWorkspaceBytes(a, s, 2<<20, "volume-A")
	a.pollWorkspaceCapacity()
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.lastRequest != "user-follow-up" || s.task.workspaceWakeReceipt.State != "revoked" || s.Supervision.RemainingBursts != 3 {
		t.Fatal("workspace wait superseded a user follow-up")
	}
}

func TestWorkspaceCapacityWakeRejectsCapacityLossDuringSendAdmission(t *testing.T) {
	a, s := workspaceNativeFixture(t, true)
	armNativeWorkspaceFixture(t, a, s, "fixture-turn", true)
	finishNativeQueueTurn(a, s)
	setWorkspaceBytes(a, s, 0, "volume-A")
	a.pollWorkspaceCapacity()
	a.mu.Lock()
	info := s.cwdInfo
	attempts := 0
	a.workspaceProbe = func(string) (workspaceCapacitySample, error) {
		attempts++
		sample := workspaceCapacitySample{directory: info, filesystem: "volume-A"}
		if attempts == 1 {
			sample.available = 2 << 20
		}
		return sample, nil
	}
	a.mu.Unlock()
	a.pollWorkspaceCapacity()
	a.pollWorkspaceCapacity()
	a.mu.Lock()
	defer a.mu.Unlock()
	if attempts != 2 || s.lastRequest != "original" || s.task.State != "blocked" ||
		s.task.workspaceWakeReceipt.State != "spent" || s.Supervision.RemainingBursts != 2 {
		t.Fatal("capacity change before send was ignored or uncertain one-use claim was retried")
	}
}

func TestWorkspaceCapacityWakeRechecksAuthorityAtNativeWrite(t *testing.T) {
	for _, changed := range []string{"none", "revision", "epoch", "receipt", "queue", "restored", "client"} {
		t.Run(changed, func(t *testing.T) {
			a, s := workspaceNativeFixture(t, true)
			armNativeWorkspaceFixture(t, a, s, "fixture-turn", true)
			finishNativeQueueTurn(a, s)
			setWorkspaceBytes(a, s, 0, "volume-A")
			a.pollWorkspaceCapacity()
			a.mu.Lock()
			s.workspaceWake.readyBytes = 2 << 20
			s.workspaceWake.readyAt = time.Now()
			w, err := a.claimWorkspaceWakeLocked(s)
			if err != nil || w == nil {
				a.mu.Unlock()
				t.Fatalf("valid wake could not claim its burst: %v", err)
			}
			s.scheduled = true
			s.Status = "running"
			s.providerFinal = false // Normal send allocates a new binding.
			s.lastRequest = w.receipt.ID
			s.requests[s.lastRequest] = "intent"
			s.codexTurn = &codexTurnBinding{client: s.codex, requestID: s.lastRequest}
			admit := a.turnAdmissionGuarded(s, w.epoch, s.lastRequest, func(current *session) bool {
				return a.workspaceWakeSendLocked(current, w, w.receipt.ID)
			})
			switch changed {
			case "revision":
				s.task.InputRevision++
			case "epoch":
				s.controlEpoch++
			case "receipt":
				s.requests[w.origin.requestID] = "unknown"
			case "queue":
				s.inputs = append(s.inputs, &queuedInput{Status: "held"})
			case "restored":
				s.Restored = true
			case "client":
				s.codex = &rpcClient{}
			}
			a.mu.Unlock()
			release, err := admit()
			if err == nil {
				release()
			}
			if (err == nil) != (changed == "none") {
				t.Fatalf("write admission wrong after %s: %v", changed, err)
			}
		})
	}
}

func TestWorkspaceCapacityProbeLocalDescriptorAndSymlink(t *testing.T) {
	if !workspaceCapacitySupported() {
		t.Skip("local descriptor capacity is unsupported")
	}
	cwd, info, err := canonicalCWD(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sample, err := probeWorkspaceCapacity(cwd)
	if err != nil || sample.filesystem == "" || !os.SameFile(info, sample.directory) {
		t.Fatalf("statfs did not sample the actual local directory: %v", err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cwd, "link")
	if err := os.Symlink(cwd, link); err != nil {
		t.Fatal(err)
	}
	if _, err := probeWorkspaceCapacity(filepath.Join(link, "child")); err == nil {
		t.Fatal("statfs followed a redirected ancestor")
	}
}
