package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
)

type queuedInput struct {
	RequestHash            string                        `json:"requestHash"`
	RequestID              string                        `json:"requestId"`
	Status                 string                        `json:"status"`
	CreatedAt              string                        `json:"createdAt"`
	Reason                 string                        `json:"reason"`
	TaskID                 string                        `json:"taskId"`
	Generation             uint64                        `json:"generation"`
	QueuedAtInputRevision  uint64                        `json:"queuedAtInputRevision"`
	DeliveredInputRevision uint64                        `json:"deliveredInputRevision"`
	CWD                    string                        `json:"cwd"`
	PolicyRevision         string                        `json:"policyRevision"`
	Text                   string                        `json:"text"` // Private disk only; state is projected explicitly.
	PayloadHash            string                        `json:"payloadHash"`
	PolicyHash             string                        `json:"policyHash"`
	RuntimeHash            string                        `json:"runtimeHash"`
	Snapshots              map[string]attachmentSnapshot `json:"snapshots"`
	cwdInfo                os.FileInfo
}

func objectiveHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
func ensureTaskAuthority(task *trackedTask) {
	if task.InputRevision == 0 {
		task.InputRevision = 1
		task.ObjectiveHash = objectiveHash(task.objective)
	}
}
func policyHash(policy resolvedPolicy) string {
	data, _ := json.Marshal(policy)
	return objectiveHash(string(data))
}
func pendingInput(entry *queuedInput) bool {
	return entry.Status == "queued" || entry.Status == "held" || entry.Status == "dispatching" || entry.Status == "unknown"
}
func (a *app) inputStateLocked(s *session) []map[string]any {
	out := []map[string]any{}
	for _, entry := range s.inputs {
		if entry.Status == "discarded" {
			continue
		}
		preview := a.clean(entry.Text)
		if len(preview) > 240 {
			preview = preview[:240] + "…"
		}
		out = append(out, map[string]any{"requestId": entry.RequestID, "status": entry.Status, "preview": preview, "createdAt": entry.CreatedAt, "reason": entry.Reason, "taskId": entry.TaskID, "generation": entry.Generation, "queuedAtInputRevision": entry.QueuedAtInputRevision, "deliveredInputRevision": entry.DeliveredInputRevision, "cwd": entry.CWD, "policyRevision": entry.PolicyRevision, "attachmentCount": len(entry.Snapshots)})
	}
	return out
}
func queueEntry(s *session, id string) *queuedInput {
	for _, entry := range s.inputs {
		if entry.RequestID == id {
			return entry
		}
	}
	return nil
}
func activeQueue(s *session) bool {
	for _, entry := range s.inputs {
		if entry.Status != "discarded" {
			return true
		}
	}
	return false
}
func (a *app) enqueueInput(id, request, text string, paths []string) (*queuedInput, error) {
	if request == "" || len(request) > 128 || strings.TrimSpace(text) == "" || len(text) > 128<<10 {
		return nil, errors.New("bounded requestId and nonempty message up to 128 KiB required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.findLocked(id)
	if s == nil {
		return nil, errors.New("session not found")
	}
	// Hash request contents before status checks: a lost acceptance response remains queryable.
	requestedHash := objectiveHash(text + "\x00" + strings.Join(paths, "\x00"))
	if prior := queueEntry(s, request); prior != nil {
		if prior.RequestHash != requestedHash {
			return nil, errors.New("requestId already identifies different queued input")
		}
		for _, path := range paths {
			if selected, ok := s.attachmentSnapshots[path]; ok {
				if original, found := prior.Snapshots[path]; !found || selected.Hash != original.Hash {
					return nil, errors.New("requestId attachment bytes changed")
				}
			}
		}
		return prior, nil
	}
	if s.queueUncertain {
		return nil, queueUncertainError()
	}
	if s.Restored || s.task == nil || oneOf(s.Status, "unknown", "disconnected", "error") || oneOf(s.task.State, "complete", "blocked", "handoff") || s.task.ReviewStatus == "unknown" {
		return nil, errors.New("session needs a new interactive context before accepting follow-ups")
	}
	if _, exists := s.requests[request]; exists {
		return nil, errors.New("requestId already belongs to a provider send")
	}
	ensureTaskAuthority(s.task)
	if len(s.inputs) >= queueReceiptLimit {
		return nil, errors.New("queue receipt limit reached; continue in a new context")
	}
	pending := 0
	textBytes := len(text)
	futureObjective := len(s.task.objective) + len(text) + 160
	bytesRetained := int64(0)
	filesRetained := 0
	for _, entry := range s.inputs {
		textBytes += len(entry.Text)
		if pendingInput(entry) {
			pending++
			futureObjective += len(entry.Text) + 160
		}
		for _, saved := range entry.Snapshots {
			bytesRetained += saved.Size
			filesRetained++
		}
	}
	if pending >= 8 || textBytes > queueTextLimit || futureObjective > queueTextLimit {
		return nil, errors.New("queue or task objective is full; preserve this draft and resolve existing inputs")
	}
	if _, err := a.selectedAttachments(s, paths); err != nil {
		return nil, err
	}
	snapshots := map[string]attachmentSnapshot{}
	for _, path := range paths {
		if _, duplicate := snapshots[path]; duplicate {
			return nil, errors.New("duplicate attachment")
		}
		saved := s.attachmentSnapshots[path]
		snapshots[path] = saved
		bytesRetained += saved.Size
		filesRetained++
	}
	if bytesRetained > queueAttachmentLimit || filesRetained > 16 {
		return nil, errors.New("retained attachments reached 16 MiB / 16 files; reconcile or discard retained inputs")
	}
	info, err := os.Stat(s.CWD)
	if err != nil {
		return nil, errors.New("working directory unavailable")
	}
	entry := &queuedInput{RequestID: request, Status: "queued", CreatedAt: now(), TaskID: s.task.ID, Generation: s.task.Generation, QueuedAtInputRevision: s.task.InputRevision, CWD: s.CWD, PolicyRevision: s.PolicyRevision, Text: text, RequestHash: requestedHash, PayloadHash: objectiveHash(requestedHash + policyHash(s.policy) + s.task.ID + objectiveInput(text, snapshots)), PolicyHash: policyHash(s.policy), Snapshots: snapshots, cwdInfo: info}
	if s.codex != nil {
		entry.RuntimeHash = s.codex.runtimeHash
	} else if s.claude != nil {
		entry.RuntimeHash = s.claude.runtimeHash
	}
	if s.Supervision.State == "paused" {
		entry.Status = "held"
		entry.Reason = "User paused; explicit Resume required"
	}
	s.inputs = append(s.inputs, entry)
	if err = a.saveInputsLocked(s); err != nil {
		if s.queueUncertain {
			entry.Status = "unknown"
			entry.Reason = "Local queue replacement durability is unknown; restart to reconcile"
			for _, path := range paths {
				delete(s.attachmentSnapshots, path)
			}
			s.Attachments = []string{}
			a.changedLocked()
		} else {
			s.inputs = s.inputs[:len(s.inputs)-1]
		}
		return nil, err
	}
	// Transfer snapshots; selecting another composer attachment must not unlink queued bytes.
	for _, path := range paths {
		delete(s.attachmentSnapshots, path)
	}
	s.Attachments = []string{}
	a.changedLocked()
	go a.advance(s.ID)
	return entry, nil
}
func (a *app) discardInput(id, request string, explicit bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.findLocked(id)
	if s == nil {
		return errors.New("session not found")
	}
	if s.queueUncertain {
		return queueUncertainError()
	}
	entry := queueEntry(s, request)
	if entry == nil {
		return errors.New("queued input not found")
	}
	if entry.Status == "discarded" {
		return nil
	}
	if !explicit && !oneOf(entry.Status, "queued", "held") {
		return errors.New("delivery may have occurred; explicit local discard required, this will not stop provider work")
	}
	if entry.Status == "dispatching" {
		return errors.New("dispatch is in progress; pause and reconcile before local discard")
	}
	old := *entry
	entry.Status = "discarded"
	entry.Text = ""
	entry.Reason = "Local payload discarded; delivery outcome is unchanged"
	entry.Snapshots = nil
	if err := a.saveInputsLocked(s); err != nil {
		*entry = old
		if s.queueUncertain {
			entry.Status = "unknown"
			entry.Reason = "Local discard durability unknown; snapshot owners retained until restart reconciliation"
			a.changedLocked()
		}
		return err
	}
	for _, saved := range old.Snapshots {
		_ = os.Remove(saved.Path)
	}
	a.changedLocked()
	go a.advance(s.ID)
	return nil
}
func (a *app) registerInputs(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/sessions/{id}/inputs", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			RequestID   string   `json:"requestId"`
			Text        string   `json:"text"`
			Attachments []string `json:"attachments"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		entry, err := a.enqueueInput(r.PathValue("id"), input.RequestID, input.Text, input.Attachments)
		if err != nil {
			a.apiError(w, err)
			return
		}
		a.mu.Lock()
		response := map[string]any{"requestId": entry.RequestID, "status": entry.Status, "queued": true}
		a.mu.Unlock()
		writeJSON(w, 200, response)
	})
	mux.HandleFunc("GET /api/sessions/{id}/inputs/{request}", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		s := a.findLocked(r.PathValue("id"))
		if s == nil {
			a.apiError(w, errors.New("session not found"))
			return
		}
		entry := queueEntry(s, r.PathValue("request"))
		if entry == nil {
			a.apiError(w, errors.New("queued input not found"))
			return
		}
		attachments := []map[string]any{}
		for path, snapshot := range entry.Snapshots {
			attachments = append(attachments, map[string]any{"path": path, "size": snapshot.Size})
		}
		writeJSON(w, 200, map[string]any{"requestId": entry.RequestID, "text": a.clean(entry.Text), "attachments": attachments, "status": entry.Status, "reason": entry.Reason})
	})
	mux.HandleFunc("DELETE /api/sessions/{id}/inputs/{request}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.discardInput(r.PathValue("id"), r.PathValue("request"), false); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"cancelled": true})
	})
	mux.HandleFunc("POST /api/sessions/{id}/inputs/{request}/discard", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Confirm bool `json:"confirm"`
		}
		if err := decodeJSON(w, r, &input); err != nil || !input.Confirm {
			a.apiError(w, errors.New("explicit confirmation required to discard possibly in-use local payload"))
			return
		}
		if err := a.discardInput(r.PathValue("id"), r.PathValue("request"), true); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"discarded": true})
	})
}
