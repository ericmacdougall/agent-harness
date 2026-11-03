package main

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	for _, retentionOnly := range []bool{false, true} {
		name := "queued_discard"
		if retentionOnly {
			name = "ordinary_finality"
		}
		t.Run(name, func(t *testing.T) {
			a, s := queueNativeFixture(t)
			source := filepath.Join(s.CWD, name+".bin")
			if err := os.WriteFile(source, []byte("cleanup completion crash"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.selectAttachments(s.ID, []string{source}); err != nil {
				t.Fatal(err)
			}
			request := "cleanup-queued"
			var entry *queuedInput
			var err error
			if retentionOnly {
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
			if retentionOnly {
				finishNativeQueueTurn(a, s)
			} else if err = a.discardInput(s.ID, request, false); err == nil {
				t.Fatal("cleanup completion interruption reported success")
			}
			if _, statErr := os.Stat(snapshot); !os.IsNotExist(statErr) {
				t.Fatal("fixture did not interrupt after snapshot unlink", statErr)
			}
			dir := a.dataDir
			a.close()
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatal("restart could not reconcile completed cleanup", err)
			}
			defer restored.close()
			recovered := queueEntry(restored.sessions[0], request)
			if recovered == nil || recovered.Status != "discarded" || len(recovered.Snapshots) != 0 {
				t.Fatalf("restart did not finish interrupted cleanup: %#v", recovered)
			}
			if restored.sessions[0].codex != nil {
				t.Fatal("cleanup recovery replayed provider work")
			}
		})
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
