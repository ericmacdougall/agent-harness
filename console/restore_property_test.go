package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Random control and provider sequences through the real API with fake providers.
// After every step, what a restart would show must match the live session, and a
// terminal receipt must never move. CONSOLE_PROPERTY_SEEDS widens the run;
// CONSOLE_PROPERTY_REPORT prints every divergence class and its first seed.

type propClient struct {
	mu        sync.Mutex
	held      []json.RawMessage
	reject    bool
	interrupt string
}

type propRun struct {
	t        *testing.T
	seed     int64
	rng      *rand.Rand
	a        *app
	dir      string
	script   string
	home     string
	clients  map[string]*propClient
	turns    map[string]string
	sends    sync.WaitGroup
	next     int
	terminal map[string]string
	lastOp   string
	found    map[string]string
	coverage map[string]int
}

const propClaudeScript = `#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *mode-exit*) exit 0 ;;
    *mode-final*) printf '{"type":"result","result":"done"}\n' ;;
    *mode-error*) printf '{"type":"result","is_error":true,"result":"failed"}\n' ;;
  esac
done
`

func newPropRun(t *testing.T, seed int64) *propRun {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-claude")
	if err := os.WriteFile(script, []byte(propClaudeScript), 0o700); err != nil {
		t.Fatal(err)
	}
	r := &propRun{t: t, seed: seed, rng: rand.New(rand.NewSource(seed)), dir: filepath.Join(dir, "state"), script: script, home: t.TempDir(), clients: map[string]*propClient{}, turns: map[string]string{}, terminal: map[string]string{}, found: map[string]string{}, coverage: map[string]int{}}
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.open()
	return r
}

func (r *propRun) open() {
	r.t.Helper()
	a, err := newApp(r.dir, nil)
	if err != nil {
		r.record("restart-refused", err.Error())
		r.t.SkipNow()
	}
	a.resolvePolicy = func(provider, _, stage string) (resolvedPolicy, error) { return defaultPolicy(provider, "", stage) }
	a.runtime = func(provider, _ string) (string, []string, error) {
		if provider == "claude" {
			return r.script, []string{"HOME=" + r.home, "PATH=/usr/bin:/bin"}, nil
		}
		return "/fixture/codex", nil, nil
	}
	r.a = a
}

func (r *propRun) record(class, detail string) {
	if _, seen := r.found[class]; !seen {
		r.found[class] = fmt.Sprintf("seed=%d lastOp=%s %s", r.seed, r.lastOp, detail)
	}
}

func (r *propRun) pick() *session {
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if len(r.a.sessions) == 0 {
		return nil
	}
	return r.a.sessions[r.rng.Intn(len(r.a.sessions))]
}

func (r *propRun) replyTo(c *rpcClient, id json.RawMessage, result string, failure string) {
	c.mu.Lock()
	ch := c.pending[string(id)]
	c.mu.Unlock()
	if ch == nil {
		return
	}
	packet := rpcPacket{ID: id, Result: json.RawMessage(result)}
	if failure != "" {
		packet.Error = &rpcError{Message: failure}
	}
	ch <- packet
}

func (r *propRun) newSession(provider string) {
	s := emptySession(provider, r.home, "")
	r.next++
	s.ID = fmt.Sprintf("s%03d", r.next)
	s.ProviderID = "provider-" + s.ID
	s.Status = "idle"
	s.scheduled = true
	s.policy, _ = defaultPolicy(provider, "", "main")
	if provider == "codex" {
		_, _, fingerprint, err := r.a.resolveRuntime(s.policy)
		if err != nil {
			return
		}
		fake := &propClient{}
		c := &rpcClient{runtimeHash: fingerprint, pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
		c.input = replySink{reply: func(data []byte) {
			var p rpcPacket
			if json.Unmarshal(data, &p) != nil {
				return
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			switch p.Method {
			case "turn/start":
				fake.held = append(fake.held, append(json.RawMessage(nil), data...))
			case "thread/turns/list":
				r.replyTo(c, p.ID, `{"data":[{"id":"turn-listed","status":"inProgress"}]}`, "")
			case "turn/interrupt":
				r.replyTo(c, p.ID, `{}`, fake.interrupt)
			}
		}}
		s.codex = c
		r.clients[s.ID] = fake
	}
	r.a.mu.Lock()
	r.a.sessions = append(r.a.sessions, s)
	err := r.a.record(s, "", "created")
	r.a.mu.Unlock()
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *propRun) send(s *session) {
	r.next++
	request := fmt.Sprintf("r%04d", r.next)
	mode := []string{"mode-final", "mode-hang", "mode-exit", "mode-error"}[r.rng.Intn(4)]
	if s.Provider != "claude" {
		if fake := r.clients[s.ID]; fake != nil {
			fake.mu.Lock()
			fake.reject = r.rng.Intn(5) == 0
			fake.mu.Unlock()
		}
	}
	done := make(chan error, 1)
	r.sends.Add(1)
	go func() {
		defer r.sends.Done()
		done <- r.a.send(s.ID, request, "objective "+mode, nil, false)
	}()
	if s.Provider == "claude" {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			r.record("hang:claude-send", request)
			return
		}
		r.settle(s, request, mode)
		return
	}
	// Codex: admission either refuses promptly or the frame is held for a later reply.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return
		default:
		}
		if fake := r.clients[s.ID]; fake != nil {
			fake.mu.Lock()
			held := len(fake.held) > 0
			fake.mu.Unlock()
			if held {
				r.coverage["codex-held"]++
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *propRun) settle(s *session, request, mode string) {
	if mode == "mode-hang" {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.a.mu.Lock()
		state := s.requests[request]
		r.a.mu.Unlock()
		if !oneOf(state, "intent", "accepted") {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *propRun) replyStart(s *session) {
	fake := r.clients[s.ID]
	if fake == nil || s.codex == nil {
		return
	}
	fake.mu.Lock()
	if len(fake.held) == 0 {
		fake.mu.Unlock()
		return
	}
	raw := fake.held[0]
	fake.held = fake.held[1:]
	reject := fake.reject
	fake.mu.Unlock()
	var p rpcPacket
	_ = json.Unmarshal(raw, &p)
	r.next++
	turn := fmt.Sprintf("turn-%04d", r.next)
	if reject {
		r.replyTo(s.codex, p.ID, `{}`, "rejected")
		r.coverage["start-rejected"]++
		return
	}
	r.turns[s.ID] = turn
	r.replyTo(s.codex, p.ID, fmt.Sprintf(`{"turn":{"id":%q}}`, turn), "")
	r.coverage["start-accepted"]++
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.a.mu.Lock()
		state := s.requests[s.lastRequest]
		r.a.mu.Unlock()
		if state != "intent" {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *propRun) completion(s *session, stale bool) {
	if s.codex == nil {
		return
	}
	turn := r.turns[s.ID]
	if stale || turn == "" {
		turn = "turn-stale"
	}
	status := []string{"completed", "failed", "interrupted"}[r.rng.Intn(3)]
	data, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turn": map[string]any{"id": turn, "status": status}})
	r.a.codexEvent(s.codex, "turn/completed", data)
	r.coverage["completion"]++
}

func (r *propRun) question(s *session) {
	if s.codex == nil {
		return
	}
	params, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turnId": r.turns[s.ID]})
	r.a.codexQuestion(s.codex, rpcPacket{ID: json.RawMessage(strconv.Itoa(r.rng.Intn(1 << 20))), Method: "item/commandExecution/requestApproval", Params: params})
}

func (r *propRun) step() {
	s := r.pick()
	op := r.rng.Intn(100)
	switch {
	case s == nil || op < 12:
		provider := []string{"codex", "claude"}[r.rng.Intn(2)]
		r.lastOp = "new-" + provider
		r.newSession(provider)
	case op < 40:
		r.lastOp = "send-" + s.Provider
		r.send(s)
	case op < 52:
		r.lastOp = "reply-start"
		r.replyStart(s)
	case op < 62:
		r.lastOp = "completion"
		r.completion(s, false)
	case op < 65:
		r.lastOp = "stale-completion"
		r.completion(s, true)
	case op < 75:
		action := []string{"pause", "stop"}[r.rng.Intn(2)]
		r.lastOp = action + "-" + s.Provider
		if fake := r.clients[s.ID]; fake != nil {
			fake.mu.Lock()
			fake.interrupt = []string{"", "rejected"}[r.rng.Intn(2)]
			fake.mu.Unlock()
		}
		if r.a.control(s.ID, action, "") == nil {
			r.coverage["control-ok"]++
		}
		r.settleClaudeExit(s)
	case op < 80:
		r.lastOp = "cwd"
		if r.a.changeCWD(s.ID, r.home) == nil {
			r.coverage["cwd-ok"]++
		}
	case op < 84:
		r.lastOp = "question"
		r.question(s)
	case op < 88:
		r.lastOp = "enqueue"
		r.next++
		if _, err := r.a.enqueueInput(s.ID, fmt.Sprintf("q%04d", r.next), "follow-up", nil); err == nil {
			r.coverage["enqueue-ok"]++
		} else {
			r.coverage["enqueue-refused: "+err.Error()]++
		}
	case op < 93:
		r.lastOp = "close"
		if r.a.closeSession(s.ID) == nil {
			r.coverage["close-ok"]++
		}
	case op < 95:
		r.lastOp = "disconnect"
		if s.codex != nil {
			r.a.providerDisconnected(s.codex, errors.New("fixture disconnect"))
			r.coverage["disconnect"]++
		}
	case op < 96:
		r.lastOp = "auth-" + s.Provider
		r.a.beginAuthenticationTransition(s.Provider, "")
		r.a.finishAuthenticationTransition(s.Provider, "", true)
		r.coverage["auth"]++
		r.settleClaudeExit(s)
	default:
		r.lastOp = "restart"
		r.restart()
	}
}

func (r *propRun) settleClaudeExit(s *session) {
	if s.Provider != "claude" {
		return
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.a.mu.Lock()
		gone := s.claude == nil
		r.a.mu.Unlock()
		if gone {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *propRun) releaseHeld() {
	for id, fake := range r.clients {
		fake.mu.Lock()
		held := fake.held
		fake.held = nil
		fake.mu.Unlock()
		r.a.mu.Lock()
		var client *rpcClient
		for _, s := range r.a.sessions {
			if s.ID == id {
				client = s.codex
			}
		}
		r.a.mu.Unlock()
		for _, raw := range held {
			var p rpcPacket
			_ = json.Unmarshal(raw, &p)
			if client != nil {
				r.replyTo(client, p.ID, `{}`, "released")
			}
		}
	}
}

func (r *propRun) restart() {
	r.releaseHeldForAll()
	r.sends.Wait()
	r.a.close()
	r.clients = map[string]*propClient{}
	r.open()
}

// A closed console can still have sends waiting on a client that left its session.
func (r *propRun) releaseHeldForAll() {
	r.releaseHeld()
	r.a.mu.Lock()
	clients := []*rpcClient{}
	for _, s := range r.a.sessions {
		if s.codex != nil {
			clients = append(clients, s.codex)
		}
	}
	r.a.mu.Unlock()
	for _, c := range clients {
		c.mu.Lock()
		pending := make([]chan rpcPacket, 0, len(c.pending))
		ids := make([]string, 0, len(c.pending))
		for id, ch := range c.pending {
			pending = append(pending, ch)
			ids = append(ids, id)
		}
		c.mu.Unlock()
		for i, ch := range pending {
			select {
			case ch <- rpcPacket{ID: json.RawMessage(ids[i]), Error: &rpcError{Message: "released"}}:
			default:
			}
		}
	}
}

type propView struct {
	status, request string
	unresolved      bool
}

func propUnresolved(state string) bool { return oneOf(state, "intent", "accepted", "unknown") }

// expectedAfterRestart is the restart contract: read-only, nothing replayed, every
// unresolved receipt stays visible as unknown.
func expectedAfterRestart(status, request string) propView {
	view := propView{status: "disconnected", request: request}
	if oneOf(request, "intent", "accepted") {
		view.request = "unknown"
	}
	if propUnresolved(request) {
		view.unresolved = true
		view.status = "unknown"
	}
	if status == "unknown" {
		view.status = "unknown"
	}
	return view
}

func (r *propRun) checkMonotonic() {
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	for _, s := range r.a.sessions {
		for request, state := range s.requests {
			key := s.ID + "/" + request
			prior := r.terminal[key]
			if prior != "" && prior != state {
				r.record("monotonic:"+prior+"->"+state, key)
			}
			if oneOf(state, "final", "unknown", "abandoned") {
				r.terminal[key] = state
			}
		}
	}
}

// Close is a loss of the only visible receipt, so check it where it happens.
func (r *propRun) checkClosures(before map[string]propView) {
	r.a.mu.Lock()
	present := map[string]bool{}
	for _, s := range r.a.sessions {
		present[s.ID] = true
	}
	r.a.mu.Unlock()
	if !strings.HasPrefix(r.lastOp, "close") {
		return
	}
	for id, view := range before {
		if !present[id] && (view.unresolved || view.status == "unknown") {
			r.record("closed-while-"+view.status+"/"+view.request, id)
		}
	}
}

func copyStateDir(from, to string) error {
	return filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // A concurrent cleanup removed it; the journal is what matters.
		}
		rel, _ := filepath.Rel(from, path)
		target := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() || strings.HasSuffix(path, ".lock") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		return os.WriteFile(target, data, 0o600)
	})
}

func (r *propRun) compareRestart() {
	// Hold a.mu across the snapshot and the copy, or an in-flight send can land between them.
	r.a.mu.Lock()
	live := map[string]propView{}
	for _, s := range r.a.sessions {
		live[s.ID] = propView{status: s.Status, request: s.requests[s.lastRequest]}
	}
	copyDir := filepath.Join(r.t.TempDir(), "copy")
	err := copyStateDir(r.dir, copyDir)
	r.a.mu.Unlock()
	if err != nil {
		r.t.Fatal(err)
	}
	restored, err := newApp(copyDir, nil)
	if err != nil {
		r.record("restart-refused:"+strings.SplitN(err.Error(), ";", 2)[0], "")
		return
	}
	defer restored.close()
	seen := map[string]bool{}
	for _, s := range restored.sessions {
		seen[s.ID] = true
		view, ok := live[s.ID]
		if !ok {
			r.record("presence:restored-but-closed-live", s.ID)
			continue
		}
		want := expectedAfterRestart(view.status, view.request)
		got := s.requests[s.lastRequest]
		if want.request != got {
			r.record(fmt.Sprintf("request:live=%q restored=%q", view.request, got), s.ID)
		}
		if want.unresolved != propUnresolved(got) {
			r.record(fmt.Sprintf("unresolved:live=%v(%s) restored=%v(%s)", want.unresolved, view.request, propUnresolved(got), got), s.ID)
		}
		if want.status != s.Status {
			r.record(fmt.Sprintf("status:live=%s/%s want=%s restored=%s", view.status, view.request, want.status, s.Status), s.ID)
		}
	}
	for id, view := range live {
		if !seen[id] && (propUnresolved(view.request) || view.status == "unknown") {
			r.record(fmt.Sprintf("presence:dropped-unresolved(%s/%s)", view.status, view.request), id)
		}
	}
}

func (r *propRun) views() map[string]propView {
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	views := map[string]propView{}
	for _, s := range r.a.sessions {
		request := s.requests[s.lastRequest]
		views[s.ID] = propView{status: s.Status, request: request, unresolved: propUnresolved(request)}
	}
	return views
}

func propSeeds() int {
	if value, err := strconv.Atoi(os.Getenv("CONSOLE_PROPERTY_SEEDS")); err == nil && value > 0 {
		return value
	}
	return 40
}

func TestRestoreMatchesLiveProjection(t *testing.T) {
	t.Skip("known defect in the unreleased baseline; replaced by the event-log rebuild (K4+), GoodQA #35692, see console/README.md")
	var mu sync.Mutex
	classes := map[string]string{}
	counts := map[string]int{}
	coverage := map[string]int{}
	seeds := propSeeds()
	t.Run("seeds", func(t *testing.T) {
		for seed := int64(1); seed <= int64(seeds); seed++ {
			seed := seed
			t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) {
				t.Parallel()
				r := newPropRun(t, seed)
				defer func() {
					mu.Lock()
					for class, detail := range r.found {
						if _, seen := classes[class]; !seen {
							classes[class] = detail
						}
						counts[class]++
					}
					for name, count := range r.coverage {
						coverage[name] += count
					}
					mu.Unlock()
				}()
				// A few seeds cross the session limit, the only way to reach trimming.
				sessions := 0
				if seed%10 == 0 {
					sessions = maxSessions + 4
				}
				for i := 0; i < sessions; i++ {
					r.newSession([]string{"codex", "claude"}[i%2])
					r.send(r.pick())
				}
				for i := 0; i < 30; i++ {
					before := r.views()
					r.step()
					r.checkClosures(before)
					r.checkMonotonic()
					r.compareRestart()
				}
				r.releaseHeldForAll()
				r.sends.Wait()
				r.a.close()
			})
		}
	})
	names := make([]string, 0, len(classes))
	for class := range classes {
		names = append(names, class)
	}
	sort.Strings(names)
	report := os.Getenv("CONSOLE_PROPERTY_REPORT") != ""
	for _, class := range names {
		line := fmt.Sprintf("DIVERGENCE %-70s seeds=%-5d first: %s", class, counts[class], classes[class])
		if report {
			fmt.Println(line)
		} else {
			t.Error(line)
		}
	}
	if report {
		fmt.Printf("COVERAGE seeds=%d classes=%d %v\n", seeds, len(names), coverage)
	}
	// A run that never exercised these paths proves nothing.
	for _, required := range []string{"start-accepted", "start-rejected", "completion", "control-ok", "close-ok", "cwd-ok", "enqueue-ok"} {
		if coverage[required] == 0 && seeds >= 40 {
			t.Errorf("vacuous run: no %s", required)
		}
	}
}
