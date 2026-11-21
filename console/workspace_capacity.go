package main

import (
	"errors"
	"os"
	"time"
)

const (
	waitWorkspaceCapacity = "wait_workspace_capacity"
	waitingForCapacity    = "waiting_capacity"
	workspacePollInterval = 30 * time.Second
	workspaceWaitLimit    = 24 * time.Hour
	maxWorkspaceWaits     = 4
	maxWorkspaceProbes    = int(workspaceWaitLimit / workspacePollInterval)
)

const maxWorkspaceMinimumBytes uint64 = 1<<53 - 1 // Native checkpoint JSON is decoded through float64.
const capacityResumePrompt = "The console observed local workspace free space meet your recorded threshold after being below it. Continue the existing objective from its last authorized checkpoint. Recheck workspace identity and applicable resource, review, and deployment gates before acting."

// Only the native write-admission callback can return this refusal. The input
// writer returns it to the caller without calling Write on the provider stream.
var errWorkspaceWakeQueued = refused("accepted user input superseded the workspace wake before native write")

type workspaceWakeUnwritten struct {
	binding *codexTurnBinding
}

func (*workspaceWakeUnwritten) Error() string { return errWorkspaceWakeQueued.Error() }
func (*workspaceWakeUnwritten) Unwrap() error { return errWorkspaceWakeQueued }

// Durable metadata is for inspection only. A restored session does not regain
// the live provider binding or the ability to poll or spend this receipt.
type workspaceWakeReceipt struct {
	ID                    string     `json:"id"`
	State                 string     `json:"state"`
	OriginRequest         string     `json:"originRequest"`
	OriginTurn            string     `json:"originTurn"`
	MinimumAvailableBytes uint64     `json:"minimumAvailableBytes"`
	ExpiresAt             time.Time  `json:"expiresAt"`
	MeasuredBelowBytes    *uint64    `json:"measuredBelowBytes,omitempty"`
	MeasuredReadyBytes    *uint64    `json:"measuredReadyBytes,omitempty"`
	ReadyAt               *time.Time `json:"readyAt,omitempty"`
}

type workspaceWake struct {
	receipt        *workspaceWakeReceipt
	task           *trackedTask
	origin         *codexTurnBinding
	epoch          uint64
	generation     uint64
	inputRevision  uint64
	objectiveHash  string
	policyHash     string
	providerID     string
	runtimeHash    string
	cwd            string
	cwdInfo        os.FileInfo
	filesystem     string
	lastBelowBytes *uint64
	readyBytes     uint64
	readyAt        time.Time
	probes         int
}

type workspaceCapacitySample struct {
	directory  os.FileInfo
	filesystem string
	available  uint64
}

func workspaceSampleMatches(w *workspaceWake, sample workspaceCapacitySample) bool {
	return sample.directory != nil && os.SameFile(w.cwdInfo, sample.directory) &&
		sample.filesystem != "" && (w.filesystem == "" || w.filesystem == sample.filesystem)
}

func (a *app) armWorkspaceWakeLocked(s *session, minimum uint64, guarded bool) error {
	if !a.workspaceWakeEnabled || !workspaceCapacitySupported() {
		return errors.New("workspace capacity wake is unavailable")
	}
	if minimum == 0 || minimum > maxWorkspaceMinimumBytes {
		return errors.New("workspace capacity wake requires a positive exact JSON byte threshold")
	}
	origin := s.codexTurn
	if !guarded || s.Provider != "codex" || s.codex == nil || s.ProviderID == "" || s.cwdInfo == nil ||
		origin == nil || origin.turnID == "" || origin.client != s.codex || origin.requestID != s.lastRequest ||
		s.requests[origin.requestID] != "accepted" || s.Status != "running" || s.providerFinal ||
		s.task.State != "active" || s.Supervision.State != "active" || s.task.workspaceWakeReceipt != nil ||
		s.Supervision.RemainingBursts <= 0 || activeQueue(s) || s.pendingReviewResult != "" ||
		s.task.reviewing || !oneOf(s.task.ReviewStatus, "", "passed") || inputLifecycleBlocked(s) {
		return errors.New("workspace capacity wake requires an eligible live Codex task and unused wait")
	}
	active := 0
	for _, current := range a.sessions {
		if current.task != nil && current.task.State == waitingForCapacity && current.Supervision.State == waitingForCapacity && current.workspaceWake != nil {
			active++
		}
	}
	if active >= maxWorkspaceWaits {
		return errors.New("workspace capacity wake limit reached")
	}
	record := &workspaceWakeReceipt{
		ID: "capacity-" + freshID(), State: "armed", OriginRequest: origin.requestID, OriginTurn: origin.turnID,
		MinimumAvailableBytes: minimum, ExpiresAt: time.Now().Add(workspaceWaitLimit),
	}
	s.workspaceWake = &workspaceWake{
		receipt: record, task: s.task, origin: origin, epoch: s.controlEpoch, generation: s.task.Generation,
		inputRevision: s.task.InputRevision, objectiveHash: s.task.ObjectiveHash, policyHash: policyHash(s.policy),
		providerID: s.ProviderID, runtimeHash: s.codex.runtimeHash, cwd: s.CWD, cwdInfo: s.cwdInfo,
	}
	s.task.workspaceWakeReceipt = record
	s.task.State = waitingForCapacity
	s.Supervision.State = waitingForCapacity
	s.Supervision.NextCheckpoint = "Waiting for local workspace capacity to recover"
	s.Supervision.Reason = s.Supervision.NextCheckpoint
	err := a.recordCheckpoint(s)
	a.changedLocked()
	return err
}

func (a *app) workspaceWakeIdentityLocked(s *session, w *workspaceWake) bool {
	return a.workspaceWakeEnabled && a.findLocked(s.ID) == s && !inputLifecycleBlocked(s) &&
		s.workspaceWake == w && s.task == w.task && s.task.workspaceWakeReceipt == w.receipt &&
		s.task.Generation == w.generation && s.task.InputRevision == w.inputRevision &&
		s.task.ObjectiveHash == w.objectiveHash && s.controlEpoch == w.epoch &&
		s.Provider == "codex" && s.codex == w.origin.client && !s.codex.disconnected.Load() &&
		s.ProviderID == w.providerID && s.codex.runtimeHash == w.runtimeHash &&
		s.CWD == w.cwd && s.cwdInfo != nil && os.SameFile(w.cwdInfo, s.cwdInfo) &&
		policyHash(s.policy) == w.policyHash &&
		!s.task.reviewing && oneOf(s.task.ReviewStatus, "", "passed") &&
		s.pendingReviewResult == "" && !s.resumeRequested && len(s.PendingQuestions) == 0
}

func (a *app) workspaceWakeOwnerLocked(s *session, w *workspaceWake) bool {
	return a.workspaceWakeIdentityLocked(s, w) && !activeQueue(s)
}

func workspaceOriginCompleted(s *session, w *workspaceWake) bool {
	return s.lastRequest == w.origin.requestID && s.codexTurn == w.origin &&
		s.providerFinal && w.origin.finalStatus == "completed" && s.requests[w.origin.requestID] == "final"
}

func (a *app) workspaceWakeIdleLocked(s *session, w *workspaceWake) bool {
	return a.workspaceWakeOwnerLocked(s, w) && s.Status == "idle" &&
		s.task.State == waitingForCapacity && s.Supervision.State == waitingForCapacity &&
		s.Supervision.RemainingBursts > 0 && workspaceOriginCompleted(s, w) && !s.scheduled
}

func retireWorkspaceWakeLocked(s *session, nextState string) {
	record := *s.workspaceWake.receipt
	record.State = "revoked"
	s.workspaceWake = nil
	s.task.workspaceWakeReceipt = &record
	s.task.State = nextState
	s.Supervision.NextCheckpoint = ""
}

func (a *app) revokeWorkspaceWakeLocked(s *session, reason, nextState string) error {
	if s.task == nil || s.task.State != waitingForCapacity {
		return nil
	}
	if s.workspaceWake == nil {
		return refused("missing live workspace wake authority")
	}
	retireWorkspaceWakeLocked(s, nextState)
	s.Supervision.State = nextState
	s.Supervision.Reason = reason
	err := a.recordCheckpoint(s)
	a.changedLocked()
	return err
}

func (a *app) workspaceWakeFresh(w *workspaceWake, now time.Time) bool {
	return w.lastBelowBytes != nil && w.readyBytes >= w.receipt.MinimumAvailableBytes &&
		!w.readyAt.IsZero() && !now.Before(w.readyAt) && now.Sub(w.readyAt) <= workspacePollInterval &&
		now.Before(w.receipt.ExpiresAt)
}

func (a *app) claimWorkspaceWakeLocked(s *session) (*workspaceWake, error) {
	w := s.workspaceWake
	if w == nil || !a.workspaceWakeIdleLocked(s, w) || !a.workspaceWakeFresh(w, time.Now()) {
		return nil, nil
	}
	record := *w.receipt
	record.State = "spent"
	record.MeasuredBelowBytes = w.lastBelowBytes
	readyBytes, readyAt := w.readyBytes, w.readyAt
	record.MeasuredReadyBytes = &readyBytes
	record.ReadyAt = &readyAt
	w.receipt = &record
	s.task.workspaceWakeReceipt = &record
	s.task.State = "active"
	s.Supervision.State = "active"
	s.Supervision.NextCheckpoint = ""
	s.Supervision.Reason = "Workspace capacity recovered; continuing existing work"
	s.Supervision.RemainingBursts--
	s.Supervision.lastProgress = s.Supervision.progress
	if err := a.recordCheckpoint(s); err != nil {
		a.changedLocked()
		return nil, err
	}
	return w, nil
}

func (a *app) workspaceWakeSendIdentityLocked(s *session, w *workspaceWake, request string) bool {
	return request == w.receipt.ID && w.receipt.State == "spent" &&
		a.workspaceWakeIdentityLocked(s, w) && s.scheduled &&
		s.task.State == "active" && s.Supervision.State == "active" &&
		w.origin.turnID == w.receipt.OriginTurn && w.origin.requestID == w.receipt.OriginRequest &&
		w.origin.finalStatus == "completed" && s.requests[w.origin.requestID] == "final"
}

func (a *app) workspaceWakeSendLocked(s *session, w *workspaceWake, request string) bool {
	return a.workspaceWakeSendIdentityLocked(s, w, request) && !activeQueue(s) && a.workspaceWakeFresh(w, time.Now())
}

func (a *app) admitWorkspaceWakeLocked(s *session, w *workspaceWake, request string) error {
	binding := s.codexTurn
	if !a.workspaceWakeSendIdentityLocked(s, w, request) || !a.workspaceWakeFresh(w, time.Now()) ||
		binding == nil || binding.client != w.origin.client || binding.requestID != request || binding.turnID != "" ||
		s.requests[request] != "intent" {
		return refused("workspace wake authority changed before native write")
	}
	if head := firstPendingInput(s); head != nil && head.Status == "queued" {
		return &workspaceWakeUnwritten{binding: binding}
	}
	if activeQueue(s) {
		return refused("workspace wake cannot supersede retained or held user input")
	}
	return nil
}

// Call only with the exact refusal emitted before the writer called Write.
// Store the rejected wake before making the previous final available again.
func (a *app) settleUnwrittenWorkspaceWake(s *session, w *workspaceWake, request string, binding *codexTurnBinding) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	head := firstPendingInput(s)
	if w == nil || !a.workspaceWakeSendIdentityLocked(s, w, request) || s.Status != "running" ||
		s.lastRequest != request || s.requests[request] != "intent" || s.providerFinal ||
		binding == nil || s.codexTurn != binding || binding.client != w.origin.client || binding.requestID != request || binding.turnID != "" ||
		head == nil || head.Status != "queued" {
		return false
	}
	if err := a.record(s, request, "rejected"); err != nil {
		a.quarantineCodexLocked(s, request, "Could not persist the unwritten workspace wake outcome; no replay")
		return true
	}
	a.transitionRequestLocked(s, request, "rejected")
	s.lastRequest = w.origin.requestID
	s.codexTurn = w.origin
	s.providerFinal = true
	s.Status = "idle"
	if s.Cascade != nil {
		s.Cascade.RequestID = w.origin.requestID
	}
	s.Supervision.Reason = "Accepted user input takes priority over the workspace wake"
	for i, message := range s.Messages {
		if message.ID == request {
			s.Messages = append(s.Messages[:i], s.Messages[i+1:]...)
			break
		}
	}
	a.changedLocked()
	return true
}

// One serial worker owns all probes. Filesystem calls have no portable context
// deadline; a stalled mount cannot retain the application or dispatch lock or
// spawn additional workers. Closing the app revokes any in-flight result.
func (a *app) watchWorkspaceCapacity(done <-chan struct{}) {
	ticker := time.NewTicker(workspacePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			a.pollWorkspaceCapacity()
		}
	}
}

func (a *app) pollWorkspaceCapacity() {
	type target struct {
		s *session
		w *workspaceWake
	}
	a.mu.Lock()
	if !a.workspaceWakeEnabled {
		a.mu.Unlock()
		return
	}
	var selected []target
	for _, s := range a.sessions {
		w := s.workspaceWake
		if w == nil || s.task != w.task || s.task.State != waitingForCapacity {
			continue
		}
		if !time.Now().Before(w.receipt.ExpiresAt) || w.probes >= maxWorkspaceProbes {
			if s.Supervision.State == waitingForCapacity {
				_ = a.revokeWorkspaceWakeLocked(s, "Workspace wake reached its polling limit", "blocked")
			}
			continue
		}
		if activeQueue(s) {
			continue // Existing FIFO scheduler owns this case.
		}
		if !a.workspaceWakeOwnerLocked(s, w) {
			if s.Supervision.State == waitingForCapacity {
				_ = a.revokeWorkspaceWakeLocked(s, "Workspace wake expired or lost its admission", "blocked")
			}
			continue
		}
		if a.workspaceWakeIdleLocked(s, w) {
			w.probes++
			selected = append(selected, target{s, w})
		}
	}
	probe := a.workspaceProbe
	a.mu.Unlock()
	if probe == nil {
		probe = probeWorkspaceCapacity
	}
	for _, target := range selected {
		s, w := target.s, target.w
		sample, err := probe(w.cwd)
		now := time.Now()
		a.mu.Lock()
		if !a.workspaceWakeIdleLocked(s, w) {
			a.mu.Unlock()
			continue
		}
		if err != nil || !workspaceSampleMatches(w, sample) || !now.Before(w.receipt.ExpiresAt) {
			_ = a.revokeWorkspaceWakeLocked(s, "Workspace capacity probe could not verify the admitted local filesystem", "blocked")
			a.mu.Unlock()
			continue
		}
		w.filesystem = sample.filesystem
		ready := w.lastBelowBytes != nil && sample.available >= w.receipt.MinimumAvailableBytes
		if sample.available < w.receipt.MinimumAvailableBytes {
			w.lastBelowBytes = &sample.available
			w.readyAt = time.Time{}
		} else if ready {
			w.readyBytes = sample.available
			w.readyAt = now
		}
		a.mu.Unlock()
		if ready {
			a.scheduleInputs(s.ID)
		}
	}
}
