package main

// Asks / Owners / Requirements view (read-only). The console never parses the harness ledgers itself: it runs
// the `ah` CLI (`ah asks`, `ah owners`, `ah requirements`, `ah sessions`) with no shell, a deadline and an output
// cap, validates every field it forwards, and reports each section as "unavailable" independently when ah fails.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	askRowCap       = 2000
	ownerRowCap     = 3000
	askTextCap      = 600
	askFieldCap     = 300
	askOutputCap    = 8 << 20
	askSessionCap   = 6
	askRecentWindow = 72 * time.Hour
)

var (
	asksRunTimeout = 15 * time.Second
	asksCacheTTL   = 10 * time.Second
	askSessionRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`)
	// asksRun runs ah and returns bounded stdout; tests replace it.
	asksRun = runAh

	asksMu    sync.Mutex
	asksCache = map[string]asksCacheEntry{}
)

type asksCacheEntry struct {
	at  time.Time
	out []byte
}

func asksCacheReset() {
	asksMu.Lock()
	asksCache = map[string]asksCacheEntry{}
	asksMu.Unlock()
}

// ahCommand finds ah: $AH_BIN (executed directly), else python3 on ~/.claude/hooks/ah.py.
func ahCommand(ctx context.Context, args []string) (*exec.Cmd, error) {
	if bin := os.Getenv("AH_BIN"); bin != "" {
		return exec.CommandContext(ctx, bin, args...), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	script := filepath.Join(home, ".claude", "hooks", "ah.py")
	if fi, err := os.Stat(script); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("ah is not installed")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, py, append([]string{"-I", script}, args...)...), nil
}

func runAh(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, asksRunTimeout)
	defer cancel()
	cmd, err := ahCommand(ctx, args)
	if err != nil {
		return nil, err
	}
	out := &cappedBuffer{limit: askOutputCap}
	cmd.Stdout = out // stderr is dropped: it can carry paths and tracebacks
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, errors.New("ah failed or timed out")
	}
	if len(out.data) >= out.limit {
		return nil, errors.New("ah output exceeded its bound")
	}
	return out.data, nil
}

func askCached(ctx context.Context, args ...string) ([]byte, error) {
	key := string(bytes.Join(func() [][]byte {
		b := make([][]byte, len(args))
		for i, a := range args {
			b[i] = []byte(a)
		}
		return b
	}(), []byte{0}))
	asksMu.Lock()
	if e, ok := asksCache[key]; ok && time.Since(e.at) < asksCacheTTL {
		asksMu.Unlock()
		return e.out, nil
	}
	asksMu.Unlock()
	out, err := asksRun(ctx, args...)
	if err != nil {
		return nil, err
	}
	asksMu.Lock()
	if len(asksCache) > 64 {
		asksCache = map[string]asksCacheEntry{}
	}
	asksCache[key] = asksCacheEntry{at: time.Now(), out: out}
	asksMu.Unlock()
	return out, nil
}

type viewSection struct {
	Rows      []map[string]any `json:"rows"`
	Error     string           `json:"error,omitempty"`
	Truncated bool             `json:"truncated,omitempty"`
	Total     int              `json:"total"`
}

func unavailable(msg string) viewSection {
	return viewSection{Rows: []map[string]any{}, Error: "unavailable: " + msg}
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// field helpers: a wrong type yields the zero value, never a panic and never a raw object in the page.
func (a *app) sf(m map[string]any, key string, n int) string {
	s, _ := m[key].(string)
	return clip(a.clean(s), n)
}
func nf(m map[string]any, key string) any {
	switch v := m[key].(type) {
	case float64:
		return v
	}
	return nil
}

var (
	askStrKeys   = []string{"session", "owner", "source", "source_label", "at", "resolved_at", "ticket", "state", "why"}
	reqStrKeys   = []string{"session", "source", "at", "state", "ticket", "owner", "evidence"}
	ownerStrKeys = []string{"session", "agent_id", "type", "task", "state", "severity", "last_activity", "ticket", "parent"}
)

func (a *app) fill(row, m map[string]any, keys []string) {
	for _, k := range keys {
		cap := askFieldCap
		if k == "why" || k == "task" {
			cap = 400
		}
		if v := a.sf(m, k, cap); v != "" {
			row[k] = v
		}
	}
	for _, k := range []string{"age_s", "idle_s", "surfaced_count"} {
		if v := nf(m, k); v != nil {
			row[k] = v
		}
	}
}

func rowsOf(raw []byte, key string) ([]any, int, error) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return nil, 0, errors.New("ah returned invalid JSON")
	}
	if ok, present := doc["ok"].(bool); present && !ok {
		return nil, 0, errors.New("ah refused the request")
	}
	list, isList := doc[key].([]any)
	if !isList {
		return nil, 0, errors.New("ah returned an unexpected shape")
	}
	total := len(list)
	if t, ok := doc["total"].(float64); ok && int(t) >= total {
		total = int(t)
	}
	return list, total, nil
}

func (a *app) askSection(ctx context.Context, scope []string, key string, strKeys []string, capN int, extra func(map[string]any, map[string]any)) viewSection {
	args := append([]string{key}, scope...)
	raw, err := askCached(ctx, args...)
	if err != nil {
		return unavailable(a.clean(err.Error()))
	}
	list, total, err := rowsOf(raw, key)
	if err != nil {
		return unavailable(err.Error())
	}
	sec := viewSection{Rows: []map[string]any{}, Total: total}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, ok := m["id"].(string)
		if !ok || id == "" {
			continue
		}
		if len(sec.Rows) >= capN {
			sec.Truncated = true
			break
		}
		row := map[string]any{"id": clip(id, 40), "text": a.sf(m, "text", askTextCap)}
		a.fill(row, m, strKeys)
		if extra != nil {
			extra(row, m)
		}
		sec.Rows = append(sec.Rows, row)
	}
	if total > len(sec.Rows) {
		sec.Truncated = true
	}
	return sec
}

func (a *app) ownerRows(ctx context.Context, sessions []string) viewSection {
	sec := viewSection{Rows: []map[string]any{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 2)
	failed := 0
	for _, s := range sessions {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			raw, err := askCached(ctx, "owners", "--session", s)
			var list []any
			if err == nil {
				list, _, err = rowsOf(raw, "owners")
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				return
			}
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				id, ok := m["agent_id"].(string)
				if !ok || id == "" {
					continue
				}
				sec.Total++
				if len(sec.Rows) >= ownerRowCap {
					sec.Truncated = true
					continue
				}
				row := map[string]any{"id": clip(id, 40), "session": s}
				a.fill(row, m, ownerStrKeys)
				row["session"] = s
				if b, ok := m["owner"].(bool); ok {
					row["owner"] = b
				}
				if b, ok := m["decision_required"].(bool); ok {
					row["decision_required"] = b
				}
				if d, ok := m["disposition"].(map[string]any); ok {
					disp := map[string]any{}
					for _, k := range []string{"kind", "at", "ref", "reason", "until"} {
						if v := a.sf(d, k, askFieldCap); v != "" {
							disp[k] = v
						}
					}
					if b, ok := d["live"].(bool); ok {
						disp["live"] = b
					}
					row["disposition"] = disp
				}
				sec.Rows = append(sec.Rows, row)
			}
		}(s)
	}
	wg.Wait()
	if failed > 0 && len(sec.Rows) == 0 {
		return unavailable("ah owners failed for every session")
	}
	return sec
}

// recentSessions: the newest few sessions with activity inside the window (owners cost ~1 s each).
func (a *app) recentSessions(ctx context.Context) ([]string, error) {
	raw, err := askCached(ctx, "sessions")
	if err != nil {
		return nil, err
	}
	list, _, err := rowsOfKey(raw, "sessions")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, item := range list {
		m, _ := item.(map[string]any)
		s, _ := m["session"].(string)
		at, _ := m["last_activity"].(string)
		t, perr := time.Parse(time.RFC3339, at)
		if !askSessionRE.MatchString(s) || perr != nil || time.Since(t) > askRecentWindow {
			continue
		}
		if out = append(out, s); len(out) >= askSessionCap {
			break
		}
	}
	return out, nil
}

func rowsOfKey(raw []byte, key string) ([]any, int, error) { return rowsOf(raw, key) }

func (a *app) asksViewHTTP(w http.ResponseWriter, r *http.Request) {
	session := r.URL.Query().Get("session")
	if session != "" && !askSessionRE.MatchString(session) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_session", "message": "invalid session id"}})
		return
	}
	ctx := r.Context()
	scope := []string{"--all"}
	if session != "" {
		scope = []string{"--session", session}
	}
	var asks, reqs, owners viewSection
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		asks = a.askSection(ctx, scope, "asks", askStrKeys, askRowCap, func(row, m map[string]any) {
			if v, ok := m["surfaced_count"]; ok && v == nil {
				row["surfaced_count"] = nil
			}
		})
	}()
	go func() {
		defer wg.Done()
		reqs = a.askSection(ctx, scope, "requirements", reqStrKeys, askRowCap, nil)
	}()
	go func() {
		defer wg.Done()
		sessions := []string{session}
		if session == "" {
			var err error
			if sessions, err = a.recentSessions(ctx); err != nil {
				owners = unavailable(a.clean(err.Error()))
				return
			}
		}
		owners = a.ownerRows(ctx, sessions)
	}()
	wg.Wait()
	writeJSON(w, 200, map[string]any{"generated": time.Now().UTC().Format(time.RFC3339), "asks": asks, "owners": owners, "requirements": reqs})
}
