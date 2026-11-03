package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func postReplaceQueueFault(t *testing.T, a *app) {
	t.Helper()
	a.writeInputs = func(path string, data []byte) error {
		if err := settingsAtomicWrite(path, data); err != nil {
			return err
		}
		return errSettingsDurability
	}
}

func cleanupCompletionFault(t *testing.T, a *app) {
	t.Helper()
	writes := 0
	a.writeInputs = func(path string, data []byte) error {
		writes++
		if err := settingsAtomicWrite(path, data); err != nil {
			return err
		}
		if writes == 2 {
			return errSettingsDurability
		}
		return nil
	}
}

func TestQueueRepairInterruptedCleanupCompletionRestarts(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
	for _, tc := range []struct {
		name          string
		retentionOnly bool
		interruptions int
	}{
		{"queued_discard", false, 0},
		{"ordinary_finality", true, 0},
		{"queued_discard_second_interruption", false, 1},
		{"ordinary_finality_second_interruption", true, 1},
		{"queued_discard_repeated_interruptions", false, 3},
		{"ordinary_finality_repeated_interruptions", true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s := queueNativeFixture(t)
			source := filepath.Join(s.CWD, tc.name+".bin")
			if err := os.WriteFile(source, []byte("cleanup completion crash"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.selectAttachments(s.ID, []string{source}); err != nil {
				t.Fatal(err)
			}
			request := "cleanup-queued"
			var entry *queuedInput
			var err error
			if tc.retentionOnly {
				finishNativeQueueTurn(a, s)
				s.Status = "idle"
				s.task.State = "blocked"
				request = "cleanup-ordinary"
				if err = a.send(s.ID, request, "ordinary attachment cleanup", []string{source}, false); err != nil {
					t.Fatal(err)
				}
				entry = queueEntry(s, request)
			} else {
				entry, err = a.enqueueInput(s.ID, request, "queued attachment cleanup", []string{source})
				if err != nil {
					t.Fatal(err)
				}
			}
			snapshot := entry.Snapshots[source].Path
			cleanupCompletionFault(t, a)
			if tc.retentionOnly {
				finishNativeQueueTurn(a, s)
			} else if err = a.discardInput(s.ID, request, false); err == nil {
				t.Fatal("cleanup completion interruption reported success")
			}
			if _, statErr := os.Stat(snapshot); !os.IsNotExist(statErr) {
				t.Fatal("fixture did not interrupt after snapshot unlink", statErr)
			}
			dir := a.dataDir
			path := a.queuePath(s)
			a.close()
			current := readCleanupCandidate(t, path, request)
			previous := readCleanupCandidate(t, path+".previous", request)
			if current.Status != "discarded" || previous.Status != "cleanup_pending" || previous.Snapshots[source].Path != snapshot {
				t.Fatal("first interruption did not preserve the completed-cleanup transition")
			}
			for i := 0; i < tc.interruptions; i++ {
				interruptCleanupPromotion(t, dir)
				current = readCleanupCandidate(t, path, request)
				pending := readCleanupCandidate(t, path+".previous", request)
				if current.Status != "cleanup_pending" || pending.Status != "cleanup_pending" || current.Reason == pending.Reason {
					t.Fatal("promotion interruption did not leave distinct pending candidates")
				}
				if !reflect.DeepEqual(previous, pending) || !reflect.DeepEqual(current.Snapshots, pending.Snapshots) {
					t.Fatal("promotion changed the retained beforeimage or snapshot owners")
				}
			}
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatal("restart could not reconcile completed cleanup", err)
			}
			t.Cleanup(restored.close)
			recovered := queueEntry(restored.sessions[0], request)
			if recovered == nil || recovered.Status != "discarded" || len(recovered.Snapshots) != 0 {
				t.Fatalf("restart did not finish interrupted cleanup: %#v", recovered)
			}
			restored.scheduleInputs(restored.sessions[0].ID)
			if restored.sessions[0].codex != nil || restored.sessions[0].claude != nil || len(restored.clients) != 0 {
				t.Fatal("cleanup recovery replayed provider work")
			}
			if data, readErr := os.ReadFile(source); readErr != nil || string(data) != "cleanup completion crash" {
				t.Fatal("cleanup changed the original source", readErr)
			}
			if _, statErr := os.Stat(path + ".previous"); !os.IsNotExist(statErr) {
				t.Fatal("successful recovery did not retire the beforeimage", statErr)
			}
			restored.close()
			restarted, err := newApp(dir, nil)
			if err != nil {
				t.Fatal("completed cleanup was not restart-stable", err)
			}
			defer restarted.close()
			if entry := queueEntry(restarted.sessions[0], request); entry == nil || entry.Status != "discarded" || len(entry.Snapshots) != 0 {
				t.Fatalf("completed cleanup did not remain discarded: %#v", entry)
			}
		})
	}
}

func readCleanupCandidate(t *testing.T, path, request string) *queuedInput {
	t.Helper()
	data, err := settingsRead(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var disk queueDisk
	if err = settingsDecode(data, &disk); err != nil {
		t.Fatal(err)
	}
	for _, entry := range disk.Entries {
		if entry.RequestID == request {
			return entry
		}
	}
	t.Fatal("cleanup candidate has no requested owner")
	return nil
}

func interruptCleanupPromotion(t *testing.T, dir string) {
	t.Helper()
	journal, err := os.OpenFile(filepath.Join(dir, "sessions.jsonl"), os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// Use real journal and queue recovery with a deterministic fault at the main
	// write boundary, before promotion can retire the original beforeimage.
	recovery := &app{dataDir: dir, journal: journal, hub: newEventHub(), clients: map[string]*rpcClient{}, redact: func(text string) string { return text }}
	defer recovery.close()
	if err = recovery.restore(); err != nil {
		t.Fatal(err)
	}
	writes := 0
	recovery.writeInputs = func(path string, data []byte) error {
		writes++
		if err := settingsAtomicWrite(path, data); err != nil {
			return err
		}
		return errSettingsDurability
	}
	if err = recovery.restoreInputs(); err == nil || writes != 1 || !strings.Contains(err.Error(), "could not be durably promoted") {
		t.Fatal("interruption did not reach recovered-main replacement", err, writes)
	}
}

func TestQueueRepairIncompatiblePendingCleanupCandidates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*queuedInput)
		wantErr bool
	}{
		{"request", func(q *queuedInput) { q.RequestID = "other-request" }, false},
		{"request_hash", func(q *queuedInput) { q.RequestHash = "other-request-hash" }, true},
		{"task", func(q *queuedInput) { q.TaskID = "other-task" }, true},
		{"generation", func(q *queuedInput) { q.Generation++ }, true},
		{"payload", func(q *queuedInput) { q.Text = "still-live payload" }, false},
		{"payload_hash", func(q *queuedInput) { q.PayloadHash = "other-payload" }, false},
		{"retention", func(q *queuedInput) { q.RetentionOnly = true }, false},
		{"outcome", func(q *queuedInput) { q.DeliveredInputRevision++ }, false},
		{"cleanup_outcome", func(q *queuedInput) { q.CleanupReason = "different final outcome" }, false},
		{"queued_revision", func(q *queuedInput) { q.QueuedAtInputRevision++ }, false},
		{"created", func(q *queuedInput) { q.CreatedAt = "other-time" }, false},
		{"cwd", func(q *queuedInput) { q.CWD = "/other" }, false},
		{"policy_revision", func(q *queuedInput) { q.PolicyRevision = "other-revision" }, false},
		{"policy_hash", func(q *queuedInput) { q.PolicyHash = "other-policy" }, false},
		{"runtime", func(q *queuedInput) { q.RuntimeHash = "other-runtime" }, false},
		{"missing_owner", func(q *queuedInput) { delete(q.Snapshots, "source") }, false},
		{"different_owner", func(q *queuedInput) {
			q.Snapshots["other-source"] = q.Snapshots["source"]
			delete(q.Snapshots, "source")
		}, false},
		{"snapshot_identity", func(q *queuedInput) {
			snapshot := q.Snapshots["source"]
			snapshot.DirectoryIdentity = "other-directory"
			q.Snapshots["source"] = snapshot
		}, true},
		{"snapshot_path", func(q *queuedInput) {
			snapshot := q.Snapshots["source"]
			snapshot.Path = "/private/other"
			q.Snapshots["source"] = snapshot
		}, true},
		{"queued", func(q *queuedInput) { q.Status = "queued" }, false},
		{"held", func(q *queuedInput) { q.Status = "held" }, false},
		{"dispatching", func(q *queuedInput) { q.Status = "dispatching" }, false},
		{"unknown", func(q *queuedInput) { q.Status = "unknown" }, false},
		{"retained", func(q *queuedInput) { q.Status = "retained" }, false},
	} {
		for _, changePrevious := range []bool{false, true} {
			slot := "/current"
			if changePrevious {
				slot = "/previous"
			}
			t.Run(tc.name+slot, func(t *testing.T) {
				candidate := func() queueDisk {
					return queueDisk{Schema: 1, SessionID: "session", TaskID: "task", Generation: 1, Entries: []*queuedInput{{
						RequestID: "request", RequestHash: "request-hash", TaskID: "task", Generation: 1,
						Status: "cleanup_pending", CleanupReason: "local discard", PayloadHash: "payload",
						Snapshots: map[string]attachmentSnapshot{"source": {Path: "/private/snapshot", Hash: "bytes", Size: 1, DirectoryIdentity: "directory"}},
					}}}
				}
				current, previous := candidate(), candidate()
				current.Entries[0].Reason = "Recovered cleanup"
				if changePrevious {
					tc.change(previous.Entries[0])
				} else {
					tc.change(current.Entries[0])
				}
				merged, err := mergeQueueCandidates(current, previous)
				if tc.wantErr {
					if err == nil {
						t.Fatal("conflicting candidates were not rejected")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(merged.Entries) == 0 {
					t.Fatal("incompatible candidates lost their owners")
				}
				for _, entry := range merged.Entries {
					if entry.Status != "unknown" {
						t.Fatalf("incompatible candidates acquired authority: %#v", entry)
					}
				}
			})
		}
	}
}

func TestQueueRepairIncompatiblePendingCleanupRestartPreservesSnapshots(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
	for _, missingOwner := range []bool{false, true} {
		name := "contradictory_outcome"
		if missingOwner {
			name = "different_owners"
		}
		t.Run(name, func(t *testing.T) {
			a, s := queueNativeFixture(t)
			source := filepath.Join(s.CWD, "preserved.bin")
			if err := os.WriteFile(source, []byte("preserve incompatible ownership"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.selectAttachments(s.ID, []string{source}); err != nil {
				t.Fatal(err)
			}
			entry, err := a.enqueueInput(s.ID, "incompatible-cleanup", "queued payload", []string{source})
			if err != nil {
				t.Fatal(err)
			}
			snapshot := entry.Snapshots[source]
			a.attachmentCleanup = func(string, os.FileInfo, string, string) error {
				return errors.New("injected failure before unlink")
			}
			if err = a.discardInput(s.ID, entry.RequestID, false); err == nil {
				t.Fatal("cleanup did not stop before unlink")
			}
			path, dir := a.queuePath(s), a.dataDir
			a.close()
			data, err := settingsRead(path, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			var disk queueDisk
			if err = settingsDecode(data, &disk); err != nil {
				t.Fatal(err)
			}
			if err = settingsAtomicWrite(path+".previous", data); err != nil {
				t.Fatal(err)
			}
			if missingOwner {
				disk.Entries[0].Snapshots = nil
			} else {
				disk.Entries[0].DeliveredInputRevision++
			}
			data, err = json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			if err = settingsAtomicWrite(path, data); err != nil {
				t.Fatal(err)
			}
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.close()
			recovered := queueEntry(restored.sessions[0], entry.RequestID)
			if recovered == nil || recovered.Status != "unknown" || recovered.Snapshots[source] != snapshot {
				t.Fatalf("incompatible cleanup lost quarantined ownership: %#v", recovered)
			}
			if data, readErr := os.ReadFile(snapshot.Path); readErr != nil || string(data) != "preserve incompatible ownership" {
				t.Fatal("incompatible cleanup deleted retained bytes", readErr)
			}
			restored.scheduleInputs(restored.sessions[0].ID)
			if restored.sessions[0].codex != nil || restored.sessions[0].claude != nil || len(restored.clients) != 0 {
				t.Fatal("incompatible cleanup replayed provider work")
			}
		})
	}
}

func TestQueueRepairDuplicateCandidatesCannotAuthorizeCleanup(t *testing.T) {
	for _, duplicatePrevious := range []bool{false, true} {
		for _, liveFirst := range []bool{false, true} {
			pending := &queuedInput{RequestID: "request", TaskID: "task", Generation: 1, Status: "cleanup_pending"}
			live := *pending
			live.Status = "unknown"
			current := queueDisk{SessionID: "session", TaskID: "task", Generation: 1, Entries: []*queuedInput{pending}}
			previous := current
			duplicates := []*queuedInput{pending, &live}
			if liveFirst {
				duplicates = []*queuedInput{&live, pending}
			}
			if duplicatePrevious {
				previous.Entries = duplicates
			} else {
				current.Entries = duplicates
			}
			if _, err := mergeQueueCandidates(current, previous); err == nil {
				t.Fatalf("duplicate request owners were merged into cleanup authority: previous=%v liveFirst=%v", duplicatePrevious, liveFirst)
			}
		}
	}
}

func TestQueueRepairPartialMultiSnapshotCleanupRestarts(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
	a, s := queueNativeFixture(t)
	paths := []string{filepath.Join(s.CWD, "partial-a.bin"), filepath.Join(s.CWD, "partial-b.bin")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("original survives private cleanup"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.selectAttachments(s.ID, paths); err != nil {
		t.Fatal(err)
	}
	entry, err := a.enqueueInput(s.ID, "partial-cleanup", "two private snapshots", paths)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.attachmentCleanup = func(dataDir string, expected os.FileInfo, name, directoryIdentity string) error {
		calls++
		if calls == 2 {
			return errors.New("injected second unlink failure")
		}
		return removeOwnedAttachment(dataDir, expected, name, directoryIdentity)
	}
	if err = a.discardInput(s.ID, entry.RequestID, false); err == nil {
		t.Fatal("partial cleanup failure reported success")
	}
	if entry.Status != "cleanup_pending" || len(entry.Snapshots) != 2 {
		t.Fatalf("partial cleanup lost durable owner: %#v", entry)
	}
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal("restart could not finish partial cleanup", err)
	}
	defer restored.close()
	recovered := queueEntry(restored.sessions[0], entry.RequestID)
	if recovered == nil || recovered.Status != "discarded" || len(recovered.Snapshots) != 0 {
		t.Fatalf("restart did not finish partial cleanup: %#v", recovered)
	}
	for _, path := range paths {
		if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "original survives private cleanup" {
			t.Fatal("private cleanup changed unrelated composer source", path, readErr)
		}
	}
}
func TestQueueRepairDiscardTurnoverRestart(t *testing.T) {
	a, s := queueNativeFixture(t)
	q, err := a.enqueueInput(s.ID, "discard-before-turnover", "Unsent followup", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.discardInput(s.ID, q.RequestID, false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.Status = "idle"
	s.providerFinal = true
	s.task.State = "blocked"
	a.mu.Unlock()
	if err = a.send(s.ID, "next-objective", "An explicitly new objective", nil, false); err != nil {
		t.Fatal(err)
	}
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal("ordinary discard→new objective→restart failed", err)
	}
	defer restored.close()
	current := restored.sessions[0]
	if current.task == nil || current.task.Generation != 2 || !current.Restored {
		t.Fatal("turnover lost new task or writer quarantine")
	}
}
func TestQueueRepairPostReplaceEnqueueRetainsUnknownOwnership(t *testing.T) {
	a, s := queueNativeFixture(t)
	original := filepath.Join(s.CWD, "queue-file.txt")
	if err := os.WriteFile(original, []byte("owned input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.selectAttachments(s.ID, []string{original}); err != nil {
		t.Fatal(err)
	}
	path := s.attachmentSnapshots[original].Path
	postReplaceQueueFault(t, a)
	_, err := a.enqueueInput(s.ID, "uncertain-enqueue", "Must not be rolled back", []string{original})
	if !errors.Is(err, errSettingsDurability) {
		t.Fatal("actual replacement uncertainty was flattened to definite failure", err)
	}
	a.mu.Lock()
	q := queueEntry(s, "uncertain-enqueue")
	uncertain := s.queueUncertain
	a.mu.Unlock()
	if q == nil || q.Status != "unknown" || !uncertain {
		t.Fatal("uncertain accepted file was removed from memory/authority")
	}
	if err = a.selectAttachments(s.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("composer removed uncertain queue-owned snapshot", err)
	}
}
func TestQueueRepairPostReplaceDispatchNeverRestoresOldAuthority(t *testing.T) {
	a, s := queueNativeFixture(t)
	q, err := a.enqueueInput(s.ID, "uncertain-dispatch", "Changed objective", nil)
	if err != nil {
		t.Fatal(err)
	}
	postReplaceQueueFault(t, a)
	finishNativeQueueTurn(a, s)
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.task.InputRevision != 2 || q.DeliveredInputRevision != 2 || q.Status != "unknown" || !s.queueUncertain {
		t.Fatal("post-replacement dispatch rolled back authority", s.task.InputRevision, q.DeliveredInputRevision, q.Status)
	}
}
func TestQueueRepairPostReplaceDiscardRetainsRecoveryReferences(t *testing.T) {
	a, s := queueNativeFixture(t)
	original := filepath.Join(s.CWD, "discard-file.txt")
	if err := os.WriteFile(original, []byte("delayed reader"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.selectAttachments(s.ID, []string{original}); err != nil {
		t.Fatal(err)
	}
	q, err := a.enqueueInput(s.ID, "uncertain-discard", "Keep uncertain bytes", []string{original})
	if err != nil {
		t.Fatal(err)
	}
	path := q.Snapshots[original].Path
	postReplaceQueueFault(t, a)
	if err = a.discardInput(s.ID, q.RequestID, false); err == nil {
		t.Fatal("uncertain discard reported success")
	}
	a.mu.Lock()
	status := q.Status
	quarantined := s.queueUncertain
	a.mu.Unlock()
	if status != "unknown" || !quarantined {
		t.Fatal("uncertain discard silently restored a runnable old entry", status)
	}
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	recovered := queueEntry(restored.sessions[0], q.RequestID)
	if recovered == nil || len(recovered.Snapshots) != 1 {
		t.Fatal("restart lost uncertain discard snapshot ownership")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("uncertain discard unlinked potentially live bytes")
	}
}
func TestQueueRepairSnapshotDirectoryBarrierBeforeAcceptance(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	source := filepath.Join(s.CWD, "directory-proof.txt")
	if err := os.WriteFile(source, []byte("directory durability"), 0600); err != nil {
		t.Fatal(err)
	}
	fileSynced := false
	directoryCalled := false
	a.attachmentSyncFile = func(file *os.File) error { fileSynced = true; return file.Sync() }
	a.attachmentSyncDir = func(path string) error {
		directoryCalled = true
		if !fileSynced {
			t.Fatal("namespace durability attempted before file durability")
		}
		return errors.New("injected attachment namespace failure")
	}
	if err := a.selectAttachments(s.ID, []string{source}); err == nil || !directoryCalled {
		t.Fatal("attachment acknowledged without required directory durability", err, directoryCalled)
	}
	if len(s.Attachments) != 0 {
		t.Fatal("non-durable attachment became selectable")
	}
}

func TestQueueRepairDispatchCrashRecoversNewAuthorityWithoutReplay(t *testing.T) {
	a, s := queueNativeFixture(t)
	q, err := a.enqueueInput(s.ID, "dispatch-crash", "Revised explicit objective", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.task.passes["plan_review"] = "old-objective-pass"
	a.mu.Unlock()
	postReplaceQueueFault(t, a)
	finishNativeQueueTurn(a, s)
	a.scheduleInputs(s.ID)
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	current := restored.sessions[0]
	entry := queueEntry(current, q.RequestID)
	if current.task.InputRevision != 2 || entry.DeliveredInputRevision != 2 || entry.Status != "unknown" || len(current.task.passes) != 0 {
		t.Fatal("interrupted replacement recovered stale authority or executable input")
	}
	restored.scheduleInputs(current.ID)
	if current.codex != nil {
		t.Fatal("recovery automatically reopened provider writer")
	}
}
func TestQueueRepairDefinitePreReplaceFailureKeepsComposerOwnership(t *testing.T) {
	a, s := queueNativeFixture(t)
	source := filepath.Join(s.CWD, "definite.txt")
	if err := os.WriteFile(source, []byte("still selected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.selectAttachments(s.ID, []string{source}); err != nil {
		t.Fatal(err)
	}
	original := s.attachmentSnapshots[source]
	a.writeInputs = func(string, []byte) error { return errors.New("controlled refusal before replacement") }
	if _, err := a.enqueueInput(s.ID, "definite", "Composer must retain this", []string{source}); err == nil || errors.Is(err, errQueueDurability) {
		t.Fatal("definite failure became false success or unknown", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(s.inputs) != 0 || s.queueUncertain || s.attachmentSnapshots[source] != original {
		t.Fatal("definite refusal removed composer ownership or quarantined unchanged store")
	}
}
func TestQueueRepairSnapshotDurabilityOrder(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	source := filepath.Join(s.CWD, "order.txt")
	if err := os.WriteFile(source, []byte("ordered barriers"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	a.attachmentSyncFile = func(file *os.File) error { calls = append(calls, "file"); return settingsSyncFile(file) }
	a.attachmentSyncDir = func(path string) error { calls = append(calls, path); return settingsSyncParent(path) }
	if err := a.selectAttachments(s.ID, []string{source}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[0] != "file" || calls[1] != filepath.Join(a.dataDir, "attachments") || calls[2] != a.dataDir {
		t.Fatal("file/directory/parent durability barriers did not precede acknowledgement", calls)
	}
}

func TestQueueRepairBeforeimageOnlyRestartPreservesAcceptedPayload(t *testing.T) {
	a, s := queueNativeFixture(t)
	q, err := a.enqueueInput(s.ID, "beforeimage-only", "Previously accepted local payload", nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := settingsRead(a.queuePath(s), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err = settingsAtomicWrite(a.queuePath(s)+".previous", data); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(a.queuePath(s)); err != nil {
		t.Fatal(err)
	}
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	recovered := queueEntry(restored.sessions[0], q.RequestID)
	if recovered == nil || recovered.Text != "Previously accepted local payload" || recovered.Status == "queued" {
		t.Fatal("missing main name silently dropped or replayed accepted beforeimage")
	}
}

func TestQueueRepairUncertainHTTPAdmissionIs503NotDefiniteRefusal(t *testing.T) {
	a, s := queueNativeFixture(t)
	postReplaceQueueFault(t, a)
	request := httptest.NewRequest("POST", "http://127.0.0.1:12345/api/sessions/"+s.ID+"/inputs", strings.NewReader(`{"requestId":"http-unknown","text":"Retain request identity","attachments":[]}`))
	request.Header.Set("Origin", "http://127.0.0.1:12345")
	request.Header.Set("Authorization", "Bearer fixture-token")
	response := httptest.NewRecorder()
	a.handler("127.0.0.1:12345", "fixture-token").ServeHTTP(response, request)
	if response.Code != 503 || !strings.Contains(response.Body.String(), "outcome_unknown") {
		t.Fatal("uncertain durable replacement looked like safe client refusal", response.Code, response.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if entry := queueEntry(s, "http-unknown"); entry == nil || entry.Status != "unknown" {
		t.Fatal("HTTP uncertainty lost retained receipt")
	}
}

func TestQueueRepairTwoSuccessiveCrashesKeepOriginalSnapshotOwners(t *testing.T) {
	for _, afterReplace := range []bool{false, true} {
		name := "before_merged_main"
		if afterReplace {
			name = "after_merged_main_replace"
		}
		t.Run(name, func(t *testing.T) {

			a, s := queueNativeFixture(t)
			source := filepath.Join(s.CWD, "successive-crash.txt")
			if err := os.WriteFile(source, []byte("original consumer bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.selectAttachments(s.ID, []string{source}); err != nil {
				t.Fatal(err)
			}
			entry, err := a.enqueueInput(s.ID, "double-crash", "Previously accepted original payload", []string{source})
			if err != nil {
				t.Fatal(err)
			}
			snapshot := entry.Snapshots[source].Path
			postReplaceQueueFault(t, a)
			if err = a.discardInput(s.ID, entry.RequestID, false); err == nil {
				t.Fatal("first injected interruption did not occur")
			}
			dir := a.dataDir
			a.close()

			// First restart reaches actual recovery promotion, then loses power immediately
			// at the merged main write. Exercise real journal/queue recovery routines
			// with no provider launched; the second restart uses the normal constructor.
			journal, err := os.OpenFile(filepath.Join(dir, "sessions.jsonl"), os.O_RDWR|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			firstRecovery := &app{dataDir: dir, journal: journal, hub: newEventHub(), clients: map[string]*rpcClient{}, redact: func(text string) string { return text }}
			if err = firstRecovery.restore(); err != nil {
				firstRecovery.close()
				t.Fatal(err)
			}
			writes := 0
			firstRecovery.writeInputs = func(path string, data []byte) error {
				writes++
				if afterReplace {
					if err := settingsAtomicWrite(path, data); err != nil {
						return err
					}
				}
				return errors.New("simulated second power loss at merged-main promotion")
			}
			err = firstRecovery.restoreInputs()
			firstRecovery.close()
			if err == nil || writes != 1 {
				t.Fatal("second crash did not hit actual merged-main boundary", err, writes)
			}

			secondRecovery, err := newApp(dir, nil)
			if err != nil {
				t.Fatal("second restart could not reconcile preserved candidates", err)
			}
			defer secondRecovery.close()
			recovered := queueEntry(secondRecovery.sessions[0], entry.RequestID)
			if recovered == nil || recovered.Text != "Previously accepted original payload" || len(recovered.Snapshots) != 1 || recovered.Status != "unknown" {
				t.Fatal("successive recovery crashes lost original payload/snapshot ownership")
			}
			if bytes, err := os.ReadFile(snapshot); err != nil || string(bytes) != "original consumer bytes" {
				t.Fatal("original delayed-consumer bytes were removed", err)
			}
			if secondRecovery.sessions[0].codex != nil {
				t.Fatal("double-crash recovery replayed a provider request")
			}

		})
	}
}
