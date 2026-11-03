package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxSessions = 24
const maxMessageBytes = 256 << 10
const maxSessionBytes = 512 << 10

type message struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
	Streaming bool   `json:"streaming"`
	AgentID   string `json:"agentId,omitempty"`
}
type agent struct {
	ControlReason   string `json:"controlReason,omitempty"`
	Effort          string `json:"effort,omitempty"`
	RuntimeProvider string `json:"runtimeProvider,omitempty"`
	CWD             string `json:"cwd,omitempty"`
	turnID          string
	ID              string  `json:"id"`
	ParentID        string  `json:"parentId"`
	Name            string  `json:"name"`
	Role            string  `json:"role"`
	Task            string  `json:"task"`
	Model           string  `json:"model"`
	Provider        string  `json:"provider"`
	Status          string  `json:"status"`
	LastSeen        *string `json:"lastSeen"`
	LastWrite       *string `json:"lastWrite"`
	CanPause        bool    `json:"canPause"`
	CanResume       bool    `json:"canResume"`
	CanStop         bool    `json:"canStop"`
}
type question struct {
	inputRevision uint64
	objectiveHash string
	epoch         uint64
	turnID        string
	target        string
	requestID     string
	generation    uint64
	client        *rpcClient
	run           *claudeRun
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Title         string   `json:"title"`
	Prompt        string   `json:"prompt"`
	Choices       []string `json:"choices"`
	ExpiresAt     string   `json:"expiresAt"`
	Questions     []any    `json:"questions,omitempty"`
	rpcID         json.RawMessage
	method        string
	params        map[string]any
}
type supervision struct {
	State           string `json:"state"`
	NextCheckpoint  string `json:"nextCheckpoint"`
	RemainingBursts int    `json:"remainingBursts"`
	Reason          string `json:"reason"`
	progress        uint64
	lastProgress    uint64
}
type session struct {
	queueUncertain      bool
	resumeRequested     bool
	delivery            *queuedDelivery
	reviewInputRevision uint64
	reviewObjectiveHash string
	inputs              []*queuedInput
	scheduled           bool
	pendingReviewResult string
	Cascade             *cascadeSelection `json:"cascade,omitempty"`
	cancelRequested     bool
	providerFinal       bool
	Restored            bool `json:"restored"`
	reviewTaskID        string
	reviewGeneration    uint64
	reviewStage         string
	reviewDigest        string
	dispatchMu          sync.Mutex
	controlEpoch        uint64
	dispatchEpoch       uint64
	Work                *trackedTask `json:"work,omitempty"`
	task                *trackedTask
	reviewParent        string
	reviewDone          chan struct{}
	ID                  string         `json:"id"`
	Provider            string         `json:"provider"`
	ProviderID          string         `json:"providerId"`
	PolicyRevision      string         `json:"policyRevision"`
	ProfileID           string         `json:"profileId,omitempty"`
	Title               string         `json:"title"`
	CWD                 string         `json:"cwd"`
	Status              string         `json:"status"`
	Model               string         `json:"model"`
	Effort              string         `json:"effort"`
	Messages            []message      `json:"messages"`
	Agents              []agent        `json:"agents"`
	Attachments         []string       `json:"attachments"`
	Usage               map[string]any `json:"usage"`
	Error               string         `json:"error"`
	PendingQuestions    []question     `json:"pendingQuestions"`
	Supervision         supervision    `json:"supervision"`
	policy              resolvedPolicy
	lastRequest         string
	filters             map[string]streamRedactor
	turnID              string
	codexTurn           *codexTurnBinding
	context             string
	requests            map[string]string
	requestOrder        []string
	codex               *rpcClient
	claude              *claudeRun
	claudeStarted       bool
	// Runtime identity that owns the Claude conversation; a change refuses --resume.
	conversationRuntimeHash string
	attachmentSnapshots     map[string]attachmentSnapshot
}
type providerInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path"`
	Reason    string `json:"reason"`
}
type journalRecord struct {
	ReviewInputRevision uint64            `json:"reviewInputRevision,omitempty"`
	ReviewObjectiveHash string            `json:"reviewObjectiveHash,omitempty"`
	Cascade             *cascadeSelection `json:"cascade,omitempty"`
	Checkpoint          *checkpointRecord `json:"checkpoint,omitempty"`
	ReviewTaskID        string            `json:"reviewTaskId,omitempty"`
	ReviewGeneration    uint64            `json:"reviewGeneration,omitempty"`
	ReviewStage         string            `json:"reviewStage,omitempty"`
	ReviewDigest        string            `json:"reviewDigest,omitempty"`
	PolicyRevision      string            `json:"policyRevision,omitempty"`
	ReviewParent        string            `json:"reviewParent,omitempty"`
	TaskID              string            `json:"taskId,omitempty"`
	TaskGeneration      uint64            `json:"taskGeneration,omitempty"`
	TaskStage           string            `json:"taskStage,omitempty"`
	SubjectDigest       string            `json:"subjectDigest,omitempty"`
	ReviewStatus        string            `json:"reviewStatus,omitempty"`
	At                  string            `json:"at"`
	SessionID           string            `json:"sessionId"`
	Provider            string            `json:"provider"`
	ProviderID          string            `json:"providerId"`
	ProfileID           string            `json:"profileId,omitempty"`
	CWD                 string            `json:"cwd"`
	RequestID           string            `json:"requestId,omitempty"`
	State               string            `json:"state"`
}
type runtimeResolver func(provider, profile string) (string, []string, error)
type app struct {
	writeInputs        func(string, []byte) error
	attachmentSyncFile func(*os.File) error
	attachmentSyncDir  func(string) error
	attachmentCleanup  func(string, os.FileInfo, string, string) error
	dataDirInfo        os.FileInfo
	releaseState       func()
	coreSecretMu       sync.Mutex
	coreSecrets        []string
	mu                 sync.Mutex
	sessions           []*session
	revision           uint64
	active             string
	reference          *reference
	providers          []providerInfo
	hub                *eventHub
	dataDir            string
	defaultCWD         string
	journal            *os.File
	journalMu          sync.Mutex
	clients            map[string]*rpcClient
	runtime            runtimeResolver
	redact             func(string) string
	resolvePolicy      policyResolver
	newRedactor        func() streamRedactor
	shutdown           func()
	gitMu              sync.Mutex
	reviews            []*session
	origin             string
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func freshID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func newApp(dir string, ref *reference) (*app, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if info, e := os.Lstat(dir); e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("console state directory must be a real directory")
	}
	resolvedDir, resolveErr := filepath.EvalSymlinks(dir)
	if resolveErr != nil {
		return nil, resolveErr
	}
	dir = resolvedDir
	release, lockErr := settingsLock(filepath.Join(dir, "console.lock"))
	if lockErr != nil {
		return nil, errors.New("another console process owns this state directory")
	}
	setupOK := false
	defer func() {
		if !setupOK {
			release()
		}
	}()
	file := filepath.Join(dir, "sessions.jsonl")
	if i, e := os.Lstat(file); e == nil && (!i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("console journal must be a regular file")
	}
	f, e := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return nil, e
	}
	dataDirInfo, e := os.Lstat(dir)
	if e != nil {
		f.Close()
		return nil, e
	}
	a := &app{reference: ref, hub: newEventHub(), dataDir: dir, dataDirInfo: dataDirInfo, journal: f, clients: map[string]*rpcClient{}, runtime: defaultRuntime, resolvePolicy: defaultPolicy, newRedactor: func() streamRedactor { return plainStream{} }, redact: func(value string) string { return value }}
	a.releaseState = release
	a.providers = discoverProviders()
	if e = a.restore(); e != nil {
		f.Close()
		return nil, e
	}
	if e = a.restoreInputs(); e != nil {
		f.Close()
		return nil, e
	}
	setupOK = true
	return a, nil
}
func (a *app) record(s *session, request, state string) error {
	r := journalRecord{At: now(), SessionID: s.ID, Provider: s.Provider, ProviderID: s.ProviderID, ProfileID: s.ProfileID, CWD: s.CWD, RequestID: request, State: state}
	r.Cascade = s.Cascade
	r.ReviewParent = s.reviewParent
	r.ReviewTaskID = s.reviewTaskID
	r.ReviewGeneration = s.reviewGeneration
	r.ReviewStage = s.reviewStage
	r.ReviewDigest = s.reviewDigest
	r.ReviewInputRevision = s.reviewInputRevision
	r.ReviewObjectiveHash = s.reviewObjectiveHash
	r.PolicyRevision = s.PolicyRevision
	if s.task != nil {
		r.Checkpoint = checkpointSnapshot(s)
		r.TaskID = s.task.ID
		r.TaskGeneration = s.task.Generation
		r.TaskStage = s.task.Stage
		r.SubjectDigest = s.task.Subject.Digest
		r.ReviewStatus = s.task.ReviewStatus
	}
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(b) > 60000 {
		return errors.New("journal metadata exceeds single-record recovery bound")
	}
	a.journalMu.Lock()
	defer a.journalMu.Unlock()
	info, statErr := a.journal.Stat()
	if statErr != nil || info.Size()+int64(len(b)+1) > 8<<20 {
		return errors.New("journal recovery bound reached; preserve state and start a new directory")
	}
	if _, e = a.journal.Write(append(b, '\n')); e != nil {
		return e
	}
	return a.journal.Sync()
}
func (a *app) changedLocked() {
	a.revision++
	a.hub.publish("state", "", map[string]any{"revision": a.revision})
}
func (a *app) findLocked(id string) *session {
	for _, s := range a.sessions {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// Restored tabs are read-only and an unresolved one cannot be closed, so counting
// them would let old history refuse all new work.
func (a *app) atSessionLimitLocked() bool {
	live := 0
	for _, s := range a.sessions {
		if !s.Restored {
			live++
		}
	}
	return live >= maxSessions
}
func (a *app) state() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(a.sessions)
	var sessions []map[string]any
	_ = json.Unmarshal(b, &sessions)
	for index, s := range sessions {
		current := a.sessions[index]
		s["pendingInputs"] = a.inputStateLocked(current)
		unresolved := oneOf(current.requests[current.lastRequest], "intent", "accepted", "unknown")
		s["unresolved"] = unresolved
		s["canStop"] = unresolved && !current.Restored && (current.codex != nil || current.claude != nil)
		a.cleanValue(s)
	}
	var ref *reference
	if a.reference != nil {
		copy := *a.reference
		copy.Body = a.clean(copy.Body)
		copy.Title = a.clean(copy.Title)
		ref = &copy
	}
	return map[string]any{"revision": a.revision, "sessions": sessions, "activeSession": a.active, "defaultCwd": a.defaultCWD, "reference": ref, "providers": a.providers, "shortcuts": []string{"Ctrl/Cmd+Enter send", "Alt/Option+Shift+N new session", "Alt/Option+Shift+[ or ] previous/next session", "Alt/Option+Shift+O attach", "Alt/Option+Shift+W cwd", "Alt/Option+Shift+K Codex terminal", "Alt/Option+Shift+L Claude terminal"}}
}
func (a *app) addMessageLocked(s *session, m message) {
	if a.redact != nil {
		m.Text = a.clean(m.Text)
	}
	if len(m.Text) > maxMessageBytes {
		m.Text = m.Text[:maxMessageBytes] + "\n[display clipped; provider history retained]"
	}
	if m.Timestamp == "" {
		m.Timestamp = now()
	}
	if m.ID == "" {
		m.ID = freshID()
	}
	for i := range s.Messages {
		if s.Messages[i].ID == m.ID {
			s.Messages[i] = m
			return
		}
	}
	s.Messages = append(s.Messages, m)
	size := 0
	for _, v := range s.Messages {
		size += len(v.Text)
	}
	for len(s.Messages) > 500 || (size > maxSessionBytes && len(s.Messages) > 1) {
		size -= len(s.Messages[0].Text)
		s.Messages = s.Messages[1:]
	}
}
func emptySession(provider, cwd, profile string) *session {
	return &session{ID: freshID(), Provider: provider, ProfileID: profile, Title: "New " + provider + " session", CWD: cwd, Status: "starting", Model: "gpt-6.1-sol", Effort: "high", Messages: []message{}, Agents: []agent{}, Attachments: []string{}, Usage: map[string]any{}, PendingQuestions: []question{}, requests: map[string]string{}, filters: map[string]streamRedactor{}, Supervision: supervision{State: "idle", RemainingBursts: 3}}
}
func (a *app) close() {
	a.mu.Lock()
	clients := make([]*rpcClient, 0, len(a.clients))
	for _, c := range a.clients {
		clients = append(clients, c)
	}
	for _, s := range append(append([]*session{}, a.sessions...), a.reviews...) {
		if s.claude != nil {
			s.claude.cancel()
		}
	}
	a.mu.Unlock()
	for _, c := range clients {
		c.close()
	}
	a.journalMu.Lock()
	_ = a.journal.Close()
	if a.releaseState != nil {
		a.releaseState()
		a.releaseState = nil
	}
	a.journalMu.Unlock()
}
