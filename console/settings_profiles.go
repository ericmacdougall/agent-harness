package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type settingsLogin struct {
	ID         string `json:"id"`
	ProfileID  string `json:"profileId"`
	Generation string `json:"-"`
	State      string `json:"state"`
	URL        string `json:"url,omitempty"`
	Code       string `json:"code,omitempty"`
	Reason     string `json:"reason"`
	CheckedAt  string `json:"checkedAt"`
	cancel     context.CancelFunc
}

func (s *settingsStore) registerProfileRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/settings/profiles/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ExpectedRevision  uint64 `json:"expectedRevision"`
			ProfileID         string `json:"profileId"`
			ProfileGeneration string `json:"profileGeneration"`
		}
		if e := decodeJSON(w, r, &in); e != nil {
			settingsError(w, e)
			return
		}
		task, e := s.startLogin(in.ExpectedRevision, in.ProfileID, in.ProfileGeneration)
		if e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, task)
	})
	mux.HandleFunc("GET /api/settings/profiles/login", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		task := s.login[r.URL.Query().Get("id")]
		if task == nil {
			s.mu.Unlock()
			settingsError(w, errors.New("login task not found"))
			return
		}
		copy := *task
		s.mu.Unlock()
		writeJSON(w, 200, copy)
	})
	mux.HandleFunc("GET /api/settings/usage", func(w http.ResponseWriter, r *http.Request) {
		result, e := s.usage(r.Context(), r.URL.Query().Get("profileId"))
		if e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, result)
	})
}
func (s *settingsStore) startLogin(revision uint64, id, generation string) (settingsLogin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disk.Revision != revision {
		return settingsLogin{}, errSettingsConflict
	}
	p, ok := s.profileLocked(id)
	if !ok || p.Generation != generation || !p.Allowed {
		return settingsLogin{}, errSettingsConflict
	}
	if p.Kind != "device" && p.Kind != "subscription" {
		return settingsLogin{}, errors.New("use a managed device or subscription profile for official login")
	}
	for _, task := range s.login {
		if task.ProfileID == id && oneOf(task.State, "running", "awaiting_user") {
			return settingsLogin{}, errors.New("a login is already active for this profile")
		}
	}
	if len(s.login) >= 64 {
		return settingsLogin{}, errors.New("login task limit reached; restart after completing sign-ins")
	}
	binary, e := discoverBinary(p.Provider)
	if e != nil {
		return settingsLogin{}, e
	}
	home, e := s.profileHome(p)
	if e != nil {
		return settingsLogin{}, e
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	version, e := credentialCommand(ctx, binary, []string{"--version"}, "")
	if e != nil {
		return settingsLogin{}, errors.New("cannot verify provider CLI version")
	}
	if p.Provider == "claude" && !settingsClaudeVersionSafe(version) {
		return settingsLogin{}, errors.New("Claude isolated subscription profiles require verified CLI 2.1.316 or later in 2.1")
	}
	if p.Provider == "codex" && !settingsCodexVersionSafe(version) {
		return settingsLogin{}, errors.New("Codex isolated native-keyring profiles require verified CLI 0.166 or later in the 0.x family")
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	task := &settingsLogin{ID: freshID(), ProfileID: id, Generation: generation, State: "running", Reason: "Complete the official provider browser sign-in", CheckedAt: time.Now().UTC().Format(time.RFC3339), cancel: cancel}
	s.login[task.ID] = task
	go s.runLogin(runCtx, task, p, binary, home)
	return *task, nil
}
func settingsClaudeVersionSafe(v string) bool {
	m := regexp.MustCompile(`^2\.1\.(\d+)`).FindStringSubmatch(strings.TrimSpace(v))
	if len(m) != 2 {
		return false
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	return n >= 316
}
func settingsCodexVersionSafe(v string) bool {
	m := regexp.MustCompile(`^codex-cli 0\.(\d+)\.`).FindStringSubmatch(strings.TrimSpace(v))
	if len(m) != 2 {
		return false
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	return n >= 166
}
func (s *settingsStore) runLogin(ctx context.Context, task *settingsLogin, p settingsProfile, binary, home string) {
	args := []string{"login", "--device-auth", "-c", "cli_auth_credentials_store=\"keyring\""}
	key := "CODEX_HOME"
	if p.Provider == "claude" {
		args = []string{"auth", "login", "--claudeai"}
		key = "CLAUDE_CONFIG_DIR"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Cancel = func() error { terminateProcess(cmd); return nil }
	cmd.WaitDelay = time.Second
	env := []string{}
	for _, entry := range os.Environ() {
		k, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(k, "CODEX_") || strings.HasPrefix(k, "CLAUDE_") || strings.HasPrefix(k, "OPENAI_") || strings.HasPrefix(k, "ANTHROPIC_") {
			continue
		}
		env = append(env, entry)
	}
	cmd.Env = append(env, key+"="+home)
	configureProcess(cmd)
	reader, writer := io.Pipe()
	cmd.Stdout = writer
	cmd.Stderr = writer
	s.mu.Lock()
	current, ok := s.profileLocked(p.ID)
	valid := ok && current.Generation == task.Generation && task.State != "cancelled"
	s.mu.Unlock()
	if !valid {
		task.cancel()
		_ = reader.Close()
		_ = writer.Close()
		return
	}
	err := cmd.Start()
	if err == nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			scanner := bufio.NewScanner(io.LimitReader(reader, 65536))
			scanner.Buffer(make([]byte, 4096), 8192)
			for scanner.Scan() {
				s.parseLoginLine(task, scanner.Text())
			}
			_ = reader.Close()
		}()
		err = cmd.Wait()
		_ = writer.Close()
		<-done
	} else {
		_ = writer.Close()
	}
	_ = reader.Close()
	if err == nil {
		checkArgs := []string{"-c", "cli_auth_credentials_store=\"keyring\"", "login", "status"}
		if p.Provider == "claude" {
			checkArgs = []string{"auth", "status", "--json"}
		}
		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		check := exec.CommandContext(checkCtx, binary, checkArgs...)
		check.Env = cmd.Env
		output := &cappedBuffer{limit: 8192}
		check.Stdout = output
		check.Stderr = io.Discard
		err = check.Run()
		cancel()
		if err == nil && p.Provider == "claude" {
			var status struct {
				LoggedIn bool `json:"loggedIn"`
			}
			if json.Unmarshal(output.data, &status) != nil || !status.LoggedIn {
				err = errors.New("official profile auth status did not confirm sign-in")
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok = s.profileLocked(p.ID)
	if !ok || current.Generation != task.Generation || task.State == "cancelled" {
		task.State = "cancelled"
		task.Reason = "Profile changed; any completed isolated provider login may require manual cleanup"
		return
	}
	task.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		task.State = "failed"
		task.Reason = "Official login did not complete; retry supported sign-in or inspect its browser window. Raw credential output was discarded."
	} else {
		task.State = "complete"
		task.Reason = "Official login completed; entitlement and harness execution remain unverified"
	}
	task.cancel()
}

var settingsLoginURL = regexp.MustCompile(`https://[^\s<>"']+`)
var settingsLoginCode = regexp.MustCompile(`\b[A-Z0-9]{4}-[A-Z0-9]{4}\b`)

func (s *settingsStore) parseLoginLine(task *settingsLogin, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if task.State == "cancelled" {
		return
	}
	for _, candidate := range settingsLoginURL.FindAllString(line, -1) {
		u, e := url.Parse(candidate)
		if e != nil || u.Scheme != "https" || u.User != nil || !oneOf(u.Host, "auth.openai.com", "chatgpt.com", "claude.ai", "platform.claude.com") {
			continue
		}
		unsafe := false
		for key := range u.Query() {
			if oneOf(strings.ToLower(key), "access_token", "refresh_token", "id_token", "client_secret", "api_key", "password") {
				unsafe = true
			}
		}
		if unsafe || u.Fragment != "" {
			continue
		}
		task.URL = u.String()
		task.State = "awaiting_user"
	}
	if task.URL != "" {
		if code := settingsLoginCode.FindString(line); code != "" {
			task.Code = code
		}
	}
	task.CheckedAt = time.Now().UTC().Format(time.RFC3339)
}
func (s *settingsStore) usage(ctx context.Context, id string) (map[string]any, error) {
	s.mu.Lock()
	p, ok := s.profileLocked(id)
	s.mu.Unlock()
	if !ok || !p.Allowed {
		return nil, errors.New("profile unavailable")
	}
	result := map[string]any{"profileId": id, "source": "supported provider CLI", "checkedAt": time.Now().UTC().Format(time.RFC3339), "available": false, "reason": "Account balance and remaining quota are not exposed by this installed provider interface", "measurements": []map[string]any{}}
	if p.Provider != "codex" || s.app == nil {
		return result, nil
	}
	client, e := s.app.codexClient(id)
	if e != nil {
		result["reason"] = "Provider connection unavailable; complete official login first"
		return result, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var raw struct {
		RateLimits *settingsRateSnapshot           `json:"rateLimits"`
		ByID       map[string]settingsRateSnapshot `json:"rateLimitsByLimitId"`
	}
	if e = client.call(ctx, "account/rateLimits/read", map[string]any{}, &raw); e != nil {
		result["reason"] = "Supported interface did not return rate limits; sign-in alone does not establish quota"
		return result, nil
	}
	measurements := []map[string]any{}
	appendWindow := func(name string, w *settingsRateWindow) {
		if w == nil {
			return
		}
		m := map[string]any{"name": name, "value": w.UsedPercent, "unit": "percent", "limit": 100}
		if w.ResetsAt > 0 {
			m["resetsAt"] = time.Unix(w.ResetsAt, 0).UTC().Format(time.RFC3339)
		}
		measurements = append(measurements, m)
	}
	if raw.RateLimits != nil {
		appendWindow("primary rate window used", raw.RateLimits.Primary)
		appendWindow("secondary rate window used", raw.RateLimits.Secondary)
	}
	for name, item := range raw.ByID {
		appendWindow(name+" primary used", item.Primary)
		appendWindow(name+" secondary used", item.Secondary)
	}
	result["measurements"] = measurements
	result["source"] = "Codex app-server account/rateLimits/read"
	result["available"] = len(measurements) > 0
	if len(measurements) > 0 {
		result["reason"] = "Actual rate-window measurements; no inferred cash balance"
	}
	return result, nil
}

type settingsRateWindow struct {
	UsedPercent float64 `json:"usedPercent"`
	ResetsAt    int64   `json:"resetsAt"`
}
type settingsRateSnapshot struct {
	Primary   *settingsRateWindow `json:"primary"`
	Secondary *settingsRateWindow `json:"secondary"`
}
