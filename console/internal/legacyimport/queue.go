package legacyimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Limits from 6172744's queue_store.go.
const (
	queueFileLimit       = 1 << 20
	queueTextLimit       = 256 << 10
	queueEntryTextLimit  = 128 << 10
	queueAttachmentLimit = 16 << 20
	queueReceiptLimit    = 256
	queueSnapshotLimit   = 16
	queueDirName         = "queued-inputs"
	attachmentsDirName   = "attachments"
	maxQueueFiles        = 4096
	// maxQueueBytes bounds what the importer holds in memory across all queue files.
	maxQueueBytes = 64 << 20
)

type queueDisk struct {
	Schema        int           `json:"schema"`
	SessionID     string        `json:"sessionId"`
	TaskID        string        `json:"taskId"`
	Generation    uint64        `json:"generation"`
	InputRevision uint64        `json:"inputRevision"`
	ObjectiveHash string        `json:"objectiveHash"`
	Objective     string        `json:"objective"`
	Entries       []*queueEntry `json:"entries"`
}

type queueEntry struct {
	RetentionOnly          bool                    `json:"retentionOnly,omitempty"`
	CleanupReason          string                  `json:"cleanupReason,omitempty"`
	RequestHash            string                  `json:"requestHash"`
	RequestID              string                  `json:"requestId"`
	Status                 string                  `json:"status"`
	CreatedAt              string                  `json:"createdAt"`
	Reason                 string                  `json:"reason"`
	TaskID                 string                  `json:"taskId"`
	Generation             uint64                  `json:"generation"`
	QueuedAtInputRevision  uint64                  `json:"queuedAtInputRevision"`
	DeliveredInputRevision uint64                  `json:"deliveredInputRevision"`
	CWD                    string                  `json:"cwd"`
	PolicyRevision         string                  `json:"policyRevision"`
	Text                   string                  `json:"text"`
	PayloadHash            string                  `json:"payloadHash"`
	PolicyHash             string                  `json:"policyHash"`
	RuntimeHash            string                  `json:"runtimeHash"`
	Snapshots              map[string]snapshotDisk `json:"snapshots"`
}

// snapshotDisk has no json tags in 6172744, so its keys are the Go field names.
type snapshotDisk struct {
	Path              string
	Hash              string
	Size              int64
	DirectoryIdentity string
}

// Snapshot is an attachment reference. The bytes stay where they are.
type Snapshot struct {
	Path, Hash        string
	Size              int64
	DirectoryIdentity string
	// Intact is false when the file is missing, redirected or changed.
	Intact bool
}

// HeldInput is one recovered queue entry. Its text never leaves this package: only
// its hash and length do (INV6).
type HeldInput struct {
	RequestID, RequestHash, Status, TaskID string
	Generation                             uint64
	TextHash                               string
	TextBytes                              int
	Snapshots                              []Snapshot
	// NoIdentity is set when a snapshot has no DirectoryIdentity, so a later release
	// must skip the identity-guarded cleanup and leave the file for the user.
	NoIdentity bool
}

// SessionQueue is what a session's queue files hold. Unknown is set, with a reason
// code, when the files could not be read as 0.1.0 would; that is a deliberate change
// from 0.1.0, which refuses to start.
type SessionQueue struct {
	SessionID     string
	Unknown       string
	TaskID        string
	Generation    uint64
	InputRevision uint64
	ObjectiveHash string
	Inputs        []HeldInput
}

// Queue is the queued-inputs directory.
type Queue struct {
	Sessions []SessionQueue
	// Orphans are queue files whose session is not imported.
	Orphans []string
	// Stray are names that are not a queue file or its beforeimage. 0.1.0 never reads
	// them, so they are reported and left alone, outside the digest and the guard.
	Stray []string
	// Digest covers every queue file, length-prefixed, sorted by name. Empty if none.
	Digest string
	Files  int
}

var queueName = regexp.MustCompile(`^([0-9a-f]{64})\.json(\.previous)?$`)

func sessionHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// readQueueDir reads the files 0.1.0 reads in queued-inputs: <sha256>.json and its
// .previous beforeimage. Other names are returned as stray, by name only, since
// 0.1.0 never reads them. Sizes are checked before any read. A missing directory is
// an empty queue.
func readQueueDir(dir string) (map[string][]byte, []string, error) {
	path := filepath.Join(dir, queueDirName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return map[string][]byte{}, nil, nil
	}
	if err != nil || !info.IsDir() {
		return nil, nil, refuse("queued-inputs is not a directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, refuse("queued-inputs cannot be listed")
	}
	if len(entries) > maxQueueFiles {
		return nil, nil, refuse("queued-inputs holds more files than the importer reads")
	}
	var stray []string
	var total int64
	var read []os.DirEntry
	for _, entry := range entries {
		if !queueName.MatchString(entry.Name()) {
			stray = append(stray, entry.Name())
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > queueFileLimit {
			return nil, nil, refuse("queued-inputs holds a queue file that is not a bounded regular file")
		}
		if total += info.Size(); total > maxQueueBytes {
			return nil, nil, refuse("queued-inputs holds more than the importer reads")
		}
		read = append(read, entry)
	}
	files := map[string][]byte{}
	for _, entry := range read {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil || len(data) > queueFileLimit {
			return nil, nil, refuse("a queue file cannot be read")
		}
		files[entry.Name()] = data
	}
	sort.Strings(stray)
	return files, stray, nil
}

// QueueDigest is length-prefixed so no two file sets share a digest.
func QueueDigest(files map[string][]byte) string {
	if len(files) == 0 {
		return ""
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	var n [8]byte
	for _, name := range names {
		binary.BigEndian.PutUint64(n[:], uint64(len(name)))
		h.Write(n[:])
		h.Write([]byte(name))
		binary.BigEndian.PutUint64(n[:], uint64(len(files[name])))
		h.Write(n[:])
		h.Write(files[name])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// decodeStrict is 6172744's settingsDecode: unique keys, no unknown fields, no
// trailing data.
func decodeStrict(data []byte, out any) error {
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("extra data")
	}
	return nil
}

func uniqueKeys(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, _ := key.(string)
			if seen[name] {
				return errors.New("duplicate key")
			}
			seen[name] = true
			if err = uniqueKeys(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = uniqueKeys(d); err != nil {
				return err
			}
		}
	}
	_, err = d.Token()
	return err
}

func neutral(disk queueDisk) queueDisk {
	for _, e := range disk.Entries {
		if e == nil || e.Status != "discarded" || e.Text != "" || len(e.Snapshots) != 0 {
			return disk
		}
	}
	disk.TaskID, disk.Generation, disk.InputRevision, disk.ObjectiveHash, disk.Objective = "", 0, 0, "", ""
	return disk
}

// merge is 6172744's mergeQueueCandidates.
func merge(current, previous queueDisk) (queueDisk, error) {
	if current.SessionID != previous.SessionID {
		return current, errors.New("foreign beforeimage")
	}
	chosen := current
	if chosen.TaskID == "" {
		chosen = previous
	}
	if current.TaskID != "" && previous.TaskID != "" {
		if current.TaskID != previous.TaskID || current.Generation != previous.Generation {
			return current, errors.New("conflicting tasks")
		}
		if previous.InputRevision > current.InputRevision {
			chosen = previous
		}
		if previous.InputRevision == current.InputRevision && previous.ObjectiveHash != current.ObjectiveHash {
			return current, errors.New("conflicting objectives")
		}
	}
	byID := map[string]*queueEntry{}
	var order []string
	for _, disk := range []queueDisk{previous, current} {
		for _, e := range disk.Entries {
			if e == nil || e.RequestID == "" {
				return current, errors.New("invalid entry")
			}
			prior := byID[e.RequestID]
			if prior == nil {
				c := *e
				c.Snapshots = map[string]snapshotDisk{}
				for k, v := range e.Snapshots {
					c.Snapshots[k] = v
				}
				byID[e.RequestID] = &c
				order = append(order, e.RequestID)
				continue
			}
			if prior.TaskID != e.TaskID || prior.Generation != e.Generation || prior.RequestHash != e.RequestHash {
				return current, errors.New("conflicting identity")
			}
			if prior.Text != "" && e.Text != "" && prior.Text != e.Text {
				return current, errors.New("conflicting payload")
			}
			if prior.Text == "" {
				prior.Text = e.Text
			}
			for k, v := range e.Snapshots {
				if old, ok := prior.Snapshots[k]; ok && old != v {
					return current, errors.New("conflicting attachment")
				}
				prior.Snapshots[k] = v
			}
			if e.DeliveredInputRevision > prior.DeliveredInputRevision {
				prior.DeliveredInputRevision = e.DeliveredInputRevision
			}
			if e.Status != "discarded" {
				prior.Status = e.Status
			}
		}
	}
	chosen.Entries = nil
	for _, id := range order {
		e := byID[id]
		if e.Text != "" || len(e.Snapshots) > 0 || e.Status != "discarded" {
			e.Status = "unknown"
		}
		chosen.Entries = append(chosen.Entries, e)
	}
	if len(chosen.Entries) > queueReceiptLimit {
		return current, errors.New("too many entries")
	}
	return neutral(chosen), nil
}

func validHeader(disk queueDisk, id string) bool {
	return disk.Schema == 1 && disk.SessionID == id && len(disk.Entries) <= queueReceiptLimit && len(disk.Objective) <= queueTextLimit
}

// decodeSession reads one session's queue files the way restoreInputs does, without
// writing, promoting or cleaning anything. Any failure becomes an Unknown reason.
func decodeSession(dir string, s Session, main, previous []byte, hasMain, hasPrevious bool) SessionQueue {
	out := SessionQueue{SessionID: s.ID}
	data := main
	if !hasMain {
		data = previous
	}
	var disk queueDisk
	if decodeStrict(data, &disk) != nil || !validHeader(disk, s.ID) {
		out.Unknown = "queue_unreadable"
		return out
	}
	disk = neutral(disk)
	merged := !hasMain
	if hasMain && hasPrevious && !bytes.Equal(sha(previous), sha(main)) {
		var prev queueDisk
		if decodeStrict(previous, &prev) != nil || !validHeader(prev, s.ID) {
			out.Unknown = "beforeimage_unreadable"
			return out
		}
		next, err := merge(disk, neutral(prev))
		if err != nil {
			out.Unknown = "beforeimage_conflict"
			return out
		}
		disk, merged = next, true
	}
	if disk.TaskID != "" {
		cp := s.Checkpoint
		if cp == nil || disk.TaskID != cp.ID || disk.Generation != cp.Generation {
			out.Unknown = "task_mismatch"
			return out
		}
		if disk.InputRevision < cp.InputRevision {
			out.Unknown = "revision_older"
			return out
		}
		if hex.EncodeToString(sha([]byte(disk.Objective))) != disk.ObjectiveHash {
			out.Unknown = "objective_mismatch"
			return out
		}
	}
	out.TaskID, out.Generation, out.InputRevision, out.ObjectiveHash = disk.TaskID, disk.Generation, disk.InputRevision, disk.ObjectiveHash
	attachments := filepath.Join(dir, attachmentsDirName) + string(filepath.Separator)
	seen := map[string]bool{}
	text, total, snapshots := 0, int64(0), 0
	// Attachments are read only after the queue's bounds pass, as in 0.1.0.
	type check struct {
		input, snapshot int
		disk            snapshotDisk
	}
	var pending []check
	for _, e := range disk.Entries {
		if e == nil || e.RequestID == "" || len(e.RequestID) > 128 || seen[e.RequestID] ||
			e.Status != "discarded" && (e.TaskID != disk.TaskID || e.Generation != disk.Generation) || len(e.Text) > queueEntryTextLimit {
			out.Unknown = "entry_invalid"
			return out
		}
		seen[e.RequestID] = true
		text += len(e.Text)
		held := HeldInput{RequestID: e.RequestID, RequestHash: e.RequestHash, TaskID: e.TaskID, Generation: e.Generation, TextBytes: len(e.Text)}
		if e.Text != "" {
			held.TextHash = hex.EncodeToString(sha([]byte(e.Text)))
		}
		switch e.Status {
		case "queued", "held":
			held.Status = "held"
		case "dispatching", "unknown":
			held.Status = "unknown"
		case "cleanup_pending", "retained", "discarded":
			held.Status = e.Status
		default:
			out.Unknown = "entry_status"
			return out
		}
		if merged && held.Status != "discarded" {
			held.Status = "unknown"
		}
		keys := make([]string, 0, len(e.Snapshots))
		for k := range e.Snapshots {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			a := e.Snapshots[k]
			snapshots++
			total += a.Size
			if a.Size < 0 || filepath.Clean(a.Path) != a.Path || !strings.HasPrefix(a.Path, attachments) {
				out.Unknown = "attachment_path"
				return out
			}
			snap := Snapshot{Path: a.Path, Hash: a.Hash, Size: a.Size, DirectoryIdentity: a.DirectoryIdentity, Intact: e.Status == "cleanup_pending"}
			if !snap.Intact {
				pending = append(pending, check{len(out.Inputs), len(held.Snapshots), a})
			}
			if a.DirectoryIdentity == "" {
				held.NoIdentity = true
			}
			held.Snapshots = append(held.Snapshots, snap)
		}
		out.Inputs = append(out.Inputs, held)
	}
	if text > queueTextLimit || total > queueAttachmentLimit || snapshots > queueSnapshotLimit {
		out.Unknown = "queue_bound"
		out.Inputs = nil
		return out
	}
	for _, c := range pending {
		out.Inputs[c.input].Snapshots[c.snapshot].Intact = attachmentIntact(c.disk)
	}
	return out
}

func sha(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// attachmentIntact reads the snapshot as 6172744's selectedAttachments does.
func attachmentIntact(a snapshotDisk) bool {
	resolved, err := filepath.EvalSymlinks(a.Path)
	if err != nil || resolved != a.Path {
		return false
	}
	info, err := os.Lstat(a.Path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != a.Size || a.Size > queueAttachmentLimit {
		return false
	}
	data, err := os.ReadFile(a.Path)
	return err == nil && hex.EncodeToString(sha(data)) == a.Hash
}

// decodeQueue reads queued-inputs for the imported sessions. Callers hold the
// console lock. Files for sessions not imported are orphans; other names are stray.
// Nothing is written.
func decodeQueue(dir string, sessions []Session) (Queue, error) {
	files, stray, err := readQueueDir(dir)
	if err != nil {
		return Queue{}, err
	}
	// 0.1.0 resolves its data directory before writing snapshot paths (state.go:207).
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	out := Queue{Digest: QueueDigest(files), Files: len(files), Stray: stray}
	claimed := map[string]bool{}
	for _, s := range sessions {
		hash := sessionHash(s.ID)
		main, hasMain := files[hash+".json"]
		previous, hasPrevious := files[hash+".json.previous"]
		if !hasMain && !hasPrevious {
			continue
		}
		claimed[hash+".json"], claimed[hash+".json.previous"] = true, true
		out.Sessions = append(out.Sessions, decodeSession(dir, s, main, previous, hasMain, hasPrevious))
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if claimed[name] {
			continue
		}
		out.Orphans = append(out.Orphans, name)
	}
	return out, nil
}
