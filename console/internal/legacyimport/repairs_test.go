package legacyimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ericmacdougall/agent-harness/console/internal/eventlog"
	"github.com/ericmacdougall/agent-harness/console/internal/kernel"
)

// queueDir makes a data directory with one session, "s", whose checkpoint is task t1
// generation 2 at input revision 3, and writes the given queue files for it.
func queueDir(t *testing.T, files map[string]any) (string, Session) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	os.MkdirAll(filepath.Join(dir, queueDirName), 0o700)
	os.MkdirAll(filepath.Join(dir, attachmentsDirName), 0o700)
	writeJournal(t, dir, `{"sessionId":"s","provider":"codex","providerId":"p","cwd":"/w","state":"created","taskId":"t1","checkpoint":{"id":"t1","generation":2,"inputRevision":3,"objectiveHash":"`+hexSHA("goal")+`"}}`+"\n")
	hash := sessionHash("s")
	for suffix, v := range files {
		var data []byte
		switch v := v.(type) {
		case string:
			data = []byte(v)
		default:
			data, _ = json.Marshal(v)
		}
		os.WriteFile(filepath.Join(dir, queueDirName, hash+suffix), data, 0o600)
	}
	j, _ := readJournal(dir)
	journal, err := DecodeJournal(j.data, true)
	if err != nil || len(journal.Sessions) != 1 {
		t.Fatal(err)
	}
	return dir, journal.Sessions[0]
}

func hexSHA(s string) string { return fmt.Sprintf("%x", sha([]byte(s))) }

func disk(entries ...map[string]any) map[string]any {
	return map[string]any{"schema": 1, "sessionId": "s", "taskId": "t1", "generation": 2, "inputRevision": 3,
		"objectiveHash": hexSHA("goal"), "objective": "goal", "entries": entries}
}

func entry(id, status, text string) map[string]any {
	return map[string]any{"requestId": id, "requestHash": hexSHA(id), "status": status, "taskId": "t1", "generation": 2, "text": text}
}

func decodeOne(t *testing.T, dir string, s Session) SessionQueue {
	t.Helper()
	q, err := decodeQueue(dir, []Session{s})
	if err != nil || len(q.Sessions) != 1 {
		t.Fatalf("%+v %v", q, err)
	}
	return q.Sessions[0]
}

// The queue rules of 6172744's restoreInputs, each as a negative case.
func TestQueueNegativeCases(t *testing.T) {
	// A queue whose entries are all discarded is neutral and loses its task header,
	// as in 0.1.0, so the header cases carry a live entry.
	cases := map[string]struct {
		files   map[string]any
		unknown string
		status  string
	}{
		"valid":                 {map[string]any{".json": disk(entry("r1", "queued", "x"))}, "", "held"},
		"beforeimage only":      {map[string]any{".json.previous": disk(entry("r1", "queued", "x"))}, "", "unknown"},
		"beforeimage agrees":    {map[string]any{".json": disk(entry("r1", "queued", "x")), ".json.previous": disk(entry("r1", "queued", "x"), entry("r0", "discarded", ""))}, "", "unknown"},
		"beforeimage disagrees": {map[string]any{".json": disk(entry("r1", "queued", "x")), ".json.previous": disk(entry("r1", "queued", "y"))}, "beforeimage_conflict", ""},
		"beforeimage corrupt":   {map[string]any{".json": disk(entry("r1", "queued", "x")), ".json.previous": "{"}, "beforeimage_unreadable", ""},
		"duplicate key":         {map[string]any{".json": `{"schema":1,"schema":1,"sessionId":"s","entries":[]}`}, "queue_unreadable", ""},
		"unknown field":         {map[string]any{".json": `{"schema":1,"sessionId":"s","entries":[],"extra":1}`}, "queue_unreadable", ""},
		"trailing data":         {map[string]any{".json": `{"schema":1,"sessionId":"s","entries":[]} {}`}, "queue_unreadable", ""},
		"other session":         {map[string]any{".json": map[string]any{"schema": 1, "sessionId": "x", "entries": []any{}}}, "queue_unreadable", ""},
		"task mismatch":         {map[string]any{".json": func() map[string]any { d := disk(entry("r1", "queued", "x")); d["taskId"] = "t9"; return d }()}, "task_mismatch", ""},
		"revision older":        {map[string]any{".json": func() map[string]any { d := disk(entry("r1", "queued", "x")); d["inputRevision"] = 2; return d }()}, "revision_older", ""},
		"objective mismatch":    {map[string]any{".json": func() map[string]any { d := disk(entry("r1", "queued", "x")); d["objective"] = "other"; return d }()}, "objective_mismatch", ""},
		"duplicate request":     {map[string]any{".json": disk(entry("r1", "queued", "x"), entry("r1", "queued", "x"))}, "entry_invalid", ""},
		"unknown status":        {map[string]any{".json": disk(entry("r1", "teleported", "x"))}, "entry_status", ""},
		"attachment outside": {map[string]any{".json": disk(func() map[string]any {
			e := entry("r1", "queued", "x")
			e["snapshots"] = map[string]any{"a": map[string]any{"Path": "/etc/passwd", "Hash": "h", "Size": 1}}
			return e
		}())}, "attachment_path", ""},
		"attachment traversal": {map[string]any{".json": disk(func() map[string]any {
			e := entry("r1", "queued", "x")
			e["snapshots"] = map[string]any{"a": map[string]any{"Path": "@ATT@../sessions.jsonl", "Hash": "h", "Size": 1}}
			return e
		}())}, "attachment_path", ""},
		"too many attachments": {map[string]any{".json": disk(func() map[string]any {
			e := entry("r1", "queued", "x")
			snaps := map[string]any{}
			for i := 0; i <= queueSnapshotLimit; i++ {
				snaps[strconv.Itoa(i)] = map[string]any{"Path": fmt.Sprintf("@ATT@f%d", i), "Hash": "h", "Size": 1}
			}
			e["snapshots"] = snaps
			return e
		}())}, "queue_bound", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, s := queueDir(t, nil)
			resolved, _ := filepath.EvalSymlinks(dir)
			att := filepath.Join(resolved, attachmentsDirName) + string(filepath.Separator)
			for suffix, v := range tc.files {
				data, ok := v.(string)
				if !ok {
					b, _ := json.Marshal(v)
					data = string(b)
				}
				data = strings.ReplaceAll(data, "@ATT@", strings.ReplaceAll(att, `\`, `\\`))
				os.WriteFile(filepath.Join(dir, queueDirName, sessionHash("s")+suffix), []byte(data), 0o600)
			}
			q := decodeOne(t, dir, s)
			if q.Unknown != tc.unknown {
				t.Fatalf("unknown %q, want %q", q.Unknown, tc.unknown)
			}
			if tc.status != "" && (len(q.Inputs) == 0 || q.Inputs[0].Status != tc.status) {
				t.Fatalf("inputs %+v, want first status %q", q.Inputs, tc.status)
			}
		})
	}
}

// An attachment reached through a link, or changed since it was queued, is not
// intact; one that matches is.
func TestAttachmentIntegrity(t *testing.T) {
	dir, s := queueDir(t, nil)
	resolved, _ := filepath.EvalSymlinks(dir)
	att := filepath.Join(resolved, attachmentsDirName)
	os.WriteFile(filepath.Join(att, "good"), []byte("bytes"), 0o600)
	os.WriteFile(filepath.Join(att, "changed"), []byte("other"), 0o600)
	snaps := map[string]any{
		"1": map[string]any{"Path": filepath.Join(att, "good"), "Hash": hexSHA("bytes"), "Size": 5},
		"2": map[string]any{"Path": filepath.Join(att, "changed"), "Hash": hexSHA("bytes"), "Size": 5},
		"3": map[string]any{"Path": filepath.Join(att, "missing"), "Hash": hexSHA("bytes"), "Size": 5},
	}
	if runtime.GOOS != "windows" {
		os.Symlink(filepath.Join(att, "good"), filepath.Join(att, "link"))
		snaps["4"] = map[string]any{"Path": filepath.Join(att, "link"), "Hash": hexSHA("bytes"), "Size": 5}
	}
	e := entry("r1", "queued", "x")
	e["snapshots"] = snaps
	data, _ := json.Marshal(disk(e))
	os.WriteFile(filepath.Join(dir, queueDirName, sessionHash("s")+".json"), data, 0o600)
	q := decodeOne(t, dir, s)
	if q.Unknown != "" {
		t.Fatal(q.Unknown)
	}
	got := map[string]bool{}
	for _, snap := range q.Inputs[0].Snapshots {
		got[filepath.Base(snap.Path)] = snap.Intact
	}
	if !got["good"] || got["changed"] || got["missing"] || got["link"] {
		t.Fatalf("intact: %v", got)
	}
}

// A data directory reached through a symlinked parent still matches the resolved
// paths 0.1.0 wrote.
func TestQueueThroughLinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	real := filepath.Join(root, "real")
	os.MkdirAll(filepath.Join(real, "data", attachmentsDirName), 0o700)
	os.MkdirAll(filepath.Join(real, "data", queueDirName), 0o700)
	os.Symlink(real, filepath.Join(root, "link"))
	dir := filepath.Join(root, "link", "data")
	att := filepath.Join(real, "data", attachmentsDirName, "a")
	os.WriteFile(att, []byte("bytes"), 0o600)
	writeJournal(t, dir, `{"sessionId":"s","provider":"codex","providerId":"p","cwd":"/w","state":"created","taskId":"t1","checkpoint":{"id":"t1","generation":2,"inputRevision":3,"objectiveHash":"`+hexSHA("goal")+`"}}`+"\n")
	e := entry("r1", "queued", "x")
	e["snapshots"] = map[string]any{"1": map[string]any{"Path": att, "Hash": hexSHA("bytes"), "Size": 5}}
	data, _ := json.Marshal(disk(e))
	os.WriteFile(filepath.Join(dir, queueDirName, sessionHash("s")+".json"), data, 0o600)
	r, err := Verify(dir)
	if err != nil || len(r.Queue.Sessions) != 1 || r.Queue.Sessions[0].Unknown != "" || !r.Queue.Sessions[0].Inputs[0].Snapshots[0].Intact {
		t.Fatalf("%+v %v", r.Queue, err)
	}
}

// Files 0.1.0 never reads (Finder metadata, a temp file) are reported, not imported,
// and neither block the import nor trip R1.
func TestStrayFilesAreLeftAlone(t *testing.T) {
	dir := install(t, "many")
	os.MkdirAll(filepath.Join(dir, queueDirName), 0o700)
	os.WriteFile(filepath.Join(dir, queueDirName, ".DS_Store"), []byte("x"), 0o600)
	r, err := Verify(dir)
	if err != nil || len(r.Unsupported) != 0 || r.Queue.Files != 0 || strings.Join(r.Queue.Stray, ",") != ".DS_Store" {
		t.Fatalf("%+v %v", r, err)
	}
	log, _, _, err := Import(ctx, dir, Options{Now: at(1)})
	if err != nil {
		t.Fatal(err)
	}
	log.Close()
	if err = Rollback(ctx, dir, at(2)); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, queueDirName, ".DS_Store"), []byte("changed"), 0o600)
	log, _, outcome, err := Import(ctx, dir, Options{Now: at(3)})
	if err != nil || outcome != SwapFinished {
		t.Fatalf("%s %v", outcome, err)
	}
	log.Close()
	if data, _ := os.ReadFile(filepath.Join(dir, queueDirName, ".DS_Store")); string(data) != "changed" {
		t.Fatal("stray file touched")
	}
}

func TestJournalTypesMatch010(t *testing.T) {
	base := `{"sessionId":"a","provider":"codex","providerId":"p","cwd":"/w","state":"created"`
	for name, extra := range map[string]string{
		"cascade number":     `,"cascade":5`,
		"task stage number":  `,"taskStage":5`,
		"attempts text":      `,"checkpoint":{"attempts":"x"}`,
		"subject files text": `,"checkpoint":{"subject":{"files":"x"}}`,
		"bursts text":        `,"checkpoint":{"bursts":"x"}`,
	} {
		if _, err := DecodeJournal([]byte(base+extra+"}\n"), true); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: 0.1.0 refuses this line but the decoder accepted it: %v", name, err)
		}
	}
	// A task record with no checkpoint still names the task, as restoreCheckpoint does.
	j, err := DecodeJournal([]byte(base+`,"taskId":"t1","taskGeneration":4,"taskStage":"plan"}`+"\n"), true)
	if err != nil || j.Sessions[0].Checkpoint == nil || j.Sessions[0].Checkpoint.ID != "t1" || j.Sessions[0].Checkpoint.Generation != 4 {
		t.Fatalf("%+v %v", j.Sessions, err)
	}
}

// The imported fact carries the checkpoint's task identity, revision, objective and
// passes; the kernel projection does not hold them until K1d, so read the batch.
func TestBatchCarriesCheckpoint(t *testing.T) {
	data := `{"sessionId":"task","provider":"claude","providerId":"c","cwd":"/w","state":"created","taskId":"t1","checkpoint":{"id":"t1","generation":2,"inputRevision":3,"objectiveHash":"abc","passes":{"plan":"d"}}}` + "\n"
	j, err := DecodeJournal([]byte(data), true)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := batch(kernel.NewProjection(), Report{Journal: j}, 1, at(1))
	if err != nil {
		t.Fatal(err)
	}
	f := facts[0]
	if f.TaskID != "t1" || f.Generation != 2 || f.InputRevision != 3 || f.ObjectiveHash != "abc" || f.Passes["plan"] != "d" {
		t.Fatalf("fact %+v", f)
	}
	// No queue may reach a batch until K1c maps its overrides.
	if _, err = batch(kernel.NewProjection(), Report{Journal: j, Queue: Queue{Files: 1}}, 1, at(1)); !errors.Is(err, ErrRefused) {
		t.Fatalf("queue reached a batch: %v", err)
	}
}

func TestRollbackRefusals(t *testing.T) {
	// No import recorded.
	dir := filepath.Join(t.TempDir(), "data")
	os.MkdirAll(dir, 0o700)
	log, _, _, err := eventlog.Open(ctx, dir, at(1))
	if err != nil {
		t.Fatal(err)
	}
	log.Close()
	writeJournal(t, dir, Sentinel)
	if err = Rollback(ctx, dir, at(2)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no import") {
		t.Fatalf("no import: %v", err)
	}
	// The kept copy is gone: refuse and leave the sentinel.
	dir = install(t, "many")
	if log, _, _, err = Import(ctx, dir, Options{Now: at(1)}); err != nil {
		t.Fatal(err)
	}
	log.Close()
	names, _ := filepath.Glob(filepath.Join(dir, journalName+".imported-*"))
	for _, n := range names {
		os.Remove(n)
	}
	before := snapshot(t, dir, false)
	if err = Rollback(ctx, dir, at(2)); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no imported journal copy") {
		t.Fatalf("no copy: %v", err)
	}
	sameFiles(t, before, snapshot(t, dir, false))
}

// A reimport retried with the same clock reading as generation 1 still finishes.
func TestSameClockReimport(t *testing.T) {
	dir := install(t, "torn-tail")
	log, _, _, err := Import(ctx, dir, Options{Now: at(1)})
	if err != nil {
		t.Fatal(err)
	}
	log.Close()
	if err = Rollback(ctx, dir, at(1)); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(filepath.Join(dir, journalName), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(line("after", "created", "") + `{"torn`)
	f.Close()
	log, p, outcome, err := Import(ctx, dir, Options{Now: at(1), Reimport: true})
	if err != nil || outcome != Imported || p.LegacyGeneration != 2 {
		t.Fatalf("%s %v", outcome, err)
	}
	log.Close()
	imported, _ := filepath.Glob(filepath.Join(dir, journalName+".imported-*"))
	torn, _ := filepath.Glob(filepath.Join(dir, journalName+".torn-*"))
	if len(imported) != 2 || len(torn) != 2 {
		t.Fatalf("copies: %v %v", imported, torn)
	}
}

// A failure at every step of a reimport, then a reimport, ends at generation 2 with
// the sentinel and generation 2's journal kept.
func TestReimportFailureAtEachStepRecovers(t *testing.T) {
	prepare := func(t *testing.T) (string, string) {
		dir := install(t, "torn-tail")
		log, _, _, err := Import(ctx, dir, Options{Now: at(1)})
		if err != nil {
			t.Fatal(err)
		}
		log.Close()
		if err = Rollback(ctx, dir, at(2)); err != nil {
			t.Fatal(err)
		}
		f, _ := os.OpenFile(filepath.Join(dir, journalName), os.O_APPEND|os.O_WRONLY, 0o600)
		f.WriteString(line("after", "created", ""))
		f.Close()
		data, _ := os.ReadFile(filepath.Join(dir, journalName))
		return dir, JournalDigest(data)
	}
	dir, _ := prepare(t)
	rec := &recorder{}
	log, _, _, err := Import(ctx, dir, Options{Now: at(3), Reimport: true, fs: rec})
	if err != nil {
		t.Fatal(err)
	}
	log.Close()
	for step := 1; step <= len(rec.calls); step++ {
		t.Run(strconv.Itoa(step), func(t *testing.T) {
			dir, digest := prepare(t)
			if _, _, _, err := Import(ctx, dir, Options{Now: at(3), Reimport: true, fs: &recorder{failAt: step}}); err == nil {
				t.Fatal("injected failure not reported")
			}
			log, p, outcome, err := Import(ctx, dir, Options{Now: at(4), Reimport: true})
			if err != nil {
				t.Fatalf("recovery: %v", err)
			}
			defer log.Close()
			if p.LegacyGeneration != 2 || p.LegacyImported != digest {
				t.Fatalf("after %s: generation %d", outcome, p.LegacyGeneration)
			}
			if data, _ := os.ReadFile(filepath.Join(dir, journalName)); string(data) != Sentinel {
				t.Fatal("no sentinel")
			}
			if name, _ := findImported(dir, digest); name == "" {
				t.Fatal("generation 2 journal not kept")
			}
		})
	}
}

// killer exits the process at one filesystem step, as a kill would: no deferred
// cleanup and no error return.
type killer struct {
	recorder
	at int
}

func (k *killer) maybe() {
	if len(k.calls) == k.at {
		os.Exit(3)
	}
}
func (k *killer) WriteSync(p string, d []byte, x bool) error {
	err := k.recorder.WriteSync(p, d, x)
	k.maybe()
	return err
}
func (k *killer) Link(a, b string) error   { err := k.recorder.Link(a, b); k.maybe(); return err }
func (k *killer) Rename(a, b string) error { err := k.recorder.Rename(a, b); k.maybe(); return err }
func (k *killer) SyncDir(d string) error   { err := k.recorder.SyncDir(d); k.maybe(); return err }

// TestKilledChild is the child side of TestKillAtEachBarrier.
func TestKilledChild(t *testing.T) {
	dir, step := os.Getenv("LEGACYIMPORT_KILL_DIR"), os.Getenv("LEGACYIMPORT_KILL_STEP")
	if dir == "" {
		t.Skip("child process only")
	}
	n, _ := strconv.Atoi(step)
	Import(ctx, dir, Options{Now: at(1), fs: &killer{at: n}})
	os.Exit(4) // the kill point was never reached
}

// A process killed right after each filesystem step, then a normal open, ends
// imported with the sentinel and the journal kept.
func TestKillAtEachBarrier(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a process per step")
	}
	dir := install(t, "torn-tail")
	rec := &recorder{}
	log, _, _, err := Import(ctx, dir, Options{Now: at(1), fs: rec})
	if err != nil {
		t.Fatal(err)
	}
	log.Close()
	for step := 1; step <= len(rec.calls); step++ {
		t.Run(strconv.Itoa(step), func(t *testing.T) {
			dir := install(t, "torn-tail")
			original, _ := os.ReadFile(filepath.Join(dir, journalName))
			cmd := exec.Command(os.Args[0], "-test.run=^TestKilledChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "LEGACYIMPORT_KILL_DIR="+dir, "LEGACYIMPORT_KILL_STEP="+strconv.Itoa(step))
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 3 {
				t.Fatalf("child did not die at step %d: %v %s", step, err, out)
			}
			log, p, outcome, err := Import(ctx, dir, Options{Now: at(2)})
			if err != nil {
				t.Fatalf("recovery after kill at %s: %v", rec.calls[step-1], err)
			}
			defer log.Close()
			if p.LegacyGeneration != 1 || p.LegacyImported != JournalDigest(original) {
				t.Fatalf("after %s: %+v", outcome, p.LegacyGeneration)
			}
			if data, _ := os.ReadFile(filepath.Join(dir, journalName)); string(data) != Sentinel {
				t.Fatal("no sentinel")
			}
			if name, _ := findImported(dir, p.LegacyImported); name == "" {
				t.Fatal("journal copy lost")
			}
		})
	}
}

// Objective text and attachment bytes stay out of the report (INV6); queue text is
// covered in TestCanaryNeverReachesTheLog.
func TestQueueCanary(t *testing.T) {
	const canary = "CANARY-9e1d"
	dir, s := queueDir(t, nil)
	resolved, _ := filepath.EvalSymlinks(dir)
	att := filepath.Join(resolved, attachmentsDirName, "a")
	os.WriteFile(att, []byte(canary), 0o600)
	e := entry("r1", "queued", canary)
	e["snapshots"] = map[string]any{"1": map[string]any{"Path": att, "Hash": hexSHA(canary), "Size": len(canary)}}
	d := disk(e)
	d["objective"], d["objectiveHash"] = canary, hexSHA(canary)
	data, _ := json.Marshal(d)
	os.WriteFile(filepath.Join(dir, queueDirName, sessionHash("s")+".json"), data, 0o600)
	r, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = s
	if text := fmt.Sprintf("%+v %#v", r, r); strings.Contains(text, canary) {
		t.Fatal("canary in the report")
	}
}

// Sizes are checked before anything is read: more queue bytes than the importer
// holds refuses without reading them. The files are sparse, so this costs no disk.
func TestQueueTotalBound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	os.MkdirAll(filepath.Join(dir, queueDirName), 0o700)
	for i := 0; i*queueFileLimit <= maxQueueBytes; i++ {
		name := filepath.Join(dir, queueDirName, sessionHash(strconv.Itoa(i))+".json")
		f, err := os.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(queueFileLimit); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	if _, _, err := readQueueDir(dir); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "more than the importer reads") {
		t.Fatalf("over the total bound: %v", err)
	}
}
