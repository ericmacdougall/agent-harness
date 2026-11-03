package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed web
var webFiles embed.FS

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "operation_failed", "message": publicError(err)}})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid or oversized JSON request")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("extra request data")
	}
	return nil
}
func (a *app) handler(host, token string) http.Handler {
	mux := http.NewServeMux()
	a.registerInputs(mux)
	mux.HandleFunc("POST /checkpoint", a.checkpointHTTP)
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.state()) })
	mux.HandleFunc("GET /api/events", a.hub.serve)
	mux.HandleFunc("POST /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Provider  string `json:"provider"`
			CWD       string `json:"cwd"`
			ProfileID string `json:"profileId"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		current, err := a.createSession(input.Provider, input.CWD, input.ProfileID)
		if err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"id": current.ID, "session": map[string]any{"id": current.ID}})
	})
	mux.HandleFunc("POST /api/sessions/import", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Provider string `json:"provider"`
			ID       string `json:"id"`
			CWD      string `json:"cwd"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		current, err := a.createSession(input.Provider, input.CWD, "")
		if err != nil {
			a.apiError(w, err)
			return
		}
		if input.Provider == "codex" {
			a.importContext(current, input.ID)
		}
		writeJSON(w, 200, map[string]any{"id": current.ID})
	})
	mux.HandleFunc("POST /api/sessions/{id}/continue-as-new", a.continueAsNewHTTP)
	mux.HandleFunc("POST /api/sessions/{id}/close", func(w http.ResponseWriter, r *http.Request) {
		if err := a.closeSession(r.PathValue("id")); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"closed": true})
	})
	mux.HandleFunc("POST /api/sessions/{id}/send", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			RequestID   string   `json:"requestId"`
			Text        string   `json:"text"`
			Attachments []string `json:"attachments"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		if err := a.send(r.PathValue("id"), input.RequestID, input.Text, input.Attachments, false); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"accepted": true})
	})
	mux.HandleFunc("POST /api/sessions/{id}/control", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Action  string `json:"action"`
			AgentID string `json:"agentId"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		if err := a.control(r.PathValue("id"), input.Action, input.AgentID); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"accepted": true})
	})
	mux.HandleFunc("POST /api/sessions/{id}/answer", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			QuestionID string `json:"questionId"`
			Answer     any    `json:"answer"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		if err := a.answerQuestion(r.PathValue("id"), input.QuestionID, input.Answer); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"accepted": true})
	})
	mux.HandleFunc("POST /api/sessions/{id}/cwd", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Path string `json:"path"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		if err := a.changeCWD(r.PathValue("id"), input.Path); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"changed": true})
	})
	mux.HandleFunc("POST /api/sessions/{id}/attachments", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Paths []string `json:"paths"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			a.apiError(w, err)
			return
		}
		if err := a.selectAttachments(r.PathValue("id"), input.Paths); err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"accepted": true})
	})
	mux.HandleFunc("GET /api/sessions/{id}/agents/{agent}/messages", func(w http.ResponseWriter, r *http.Request) {
		current, err := a.sessionCopy(r.PathValue("id"))
		if err != nil {
			a.apiError(w, err)
			return
		}
		target := r.PathValue("agent")
		a.mu.Lock()
		valid := false
		for _, child := range current.Agents {
			if child.ID == target {
				valid = true
			}
		}
		provider := current.Provider
		a.mu.Unlock()
		if !valid {
			a.apiError(w, errors.New("agent is not owned by this session"))
			return
		}
		a.mu.Lock()
		var reviewMessages []message
		for _, review := range a.reviews {
			if review.reviewParent == current.ID && review.ProviderID == target {
				reviewMessages = append([]message{}, review.Messages...)
				break
			}
		}
		a.mu.Unlock()
		if reviewMessages != nil {
			writeJSON(w, 200, map[string]any{"messages": reviewMessages, "status": "independent review transcript"})
			return
		}
		if provider == "claude" {
			a.mu.Lock()
			items := []message{}
			for _, item := range current.Messages {
				if item.AgentID == target {
					items = append(items, item)
				}
			}
			a.mu.Unlock()
			writeJSON(w, 200, map[string]any{"messages": items, "status": "available forwarded Claude messages"})
			return
		}
		items, err := a.transcript(current, target)
		if err != nil {
			a.apiError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"messages": items, "status": "loaded"})
	})
	mux.HandleFunc("GET /api/files", a.files)
	mux.HandleFunc("GET /api/git", a.gitStatusHTTP)
	mux.HandleFunc("POST /api/git/refresh", a.gitRefreshHTTP)
	mux.HandleFunc("POST /api/git/sync", a.gitSyncHTTP)
	mux.HandleFunc("POST /api/git/remove", a.gitRemoveHTTP)
	mux.HandleFunc("POST /api/launch", a.launchHTTP)
	mux.HandleFunc("POST /api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"stopping": true})
		if a.shutdown != nil {
			go a.shutdown()
		}
	})
	if settingsRegister != nil {
		settingsRegister(mux, a)
	}
	assets, _ := fs.Sub(webFiles, "web")
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	origin := "http://" + host
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Agent-Harness-Console", version)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Host != host {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if remote := r.Header.Get("Origin"); remote != "" && remote != origin {
			http.Error(w, "foreign origin", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			expected := "Bearer " + token
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
				http.Error(w, "authorization required", http.StatusUnauthorized)
				return
			}
			if r.Method != "GET" && r.Header.Get("Origin") != origin {
				http.Error(w, "same-origin mutation required", http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *app) files(w http.ResponseWriter, r *http.Request) {
	path, err := validCWD(r.URL.Query().Get("path"))
	if err != nil {
		a.apiError(w, err)
		return
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		a.apiError(w, errors.New("directory cannot be read"))
		return
	}
	rows := []map[string]any{}
	for _, entry := range entries {
		if len(rows) >= 1000 {
			break
		}
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, e := entry.Info()
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		rows = append(rows, map[string]any{"name": entry.Name(), "path": filepath.Join(path, entry.Name()), "directory": entry.IsDir(), "size": info.Size()})
	}
	writeJSON(w, 200, map[string]any{"path": path, "parent": filepath.Dir(path), "entries": rows})
}
func (a *app) validateAttachments(paths []string) error {
	if len(paths) > 16 {
		return errors.New("at most 16 attachments per message")
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return errors.New("attachment paths must be absolute")
		}
		if credentialFile(path) {
			return errors.New("credential files cannot be attached automatically")
		}
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("attachment must be an existing regular file")
		}
		if info.Size() > 16<<20 {
			return errors.New("attachment exceeds 16 MiB")
		}
	}
	return nil
}

func (a *app) apiError(w http.ResponseWriter, err error) {
	if errors.Is(err, errQueueDurability) {
		writeJSON(w, 503, map[string]any{"error": map[string]string{"code": "outcome_unknown", "message": a.clean(publicError(err))}})
		return
	}
	apiError(w, errors.New(a.clean(publicError(err))))
}
