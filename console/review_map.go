package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PR review map endpoints. The console never builds the page itself: it runs the
// harness review_map.py with a fixed argv, derives the repository from an existing
// session (never from the request), and serves the result from an unguessable,
// expiring, sandboxed URL so the page's script cannot reach the console token or API.

const (
	reviewMapTTL        = time.Hour
	reviewMapMaxEntries = 64
	reviewMapMaxOutput  = 1 << 20
	reviewMapMaxPage    = 8 << 20
)

type reviewMapEntry struct {
	path    string
	repo    string
	number  int
	sha     string
	tickets []string
	expires time.Time
}

var (
	reviewMapMu      sync.Mutex
	reviewMapEntries = map[string]*reviewMapEntry{}
	reviewMapBusy    = map[string]bool{}
	scriptTag        = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	ticketRef        = regexp.MustCompile(`^GoodQA [a-z0-9][a-z0-9-]{0,62}#[1-9][0-9]{0,9}$`)
	// reviewMapRun is replaced in tests; it returns stdout (bounded) of the script.
	reviewMapRun = runReviewMapScript
)

func reviewMapScript() (string, error) {
	if explicit := os.Getenv("HARNESS_REVIEW_MAP"); explicit != "" {
		return explicit, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("home directory unavailable")
	}
	return filepath.Join(home, ".claude", "hooks", "review_map.py"), nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return len(p), nil // drop the excess; the caller sees truncated JSON and fails closed
	}
	return b.Buffer.Write(p)
}

func runReviewMapScript(ctx context.Context, args []string) ([]byte, error) {
	script, err := reviewMapScript()
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(script); statErr != nil || !info.Mode().IsRegular() {
		return nil, errors.New("review_map.py is not installed; install the harness hooks or set HARNESS_REVIEW_MAP")
	}
	cmd := exec.CommandContext(ctx, "python3", append([]string{"-I", script}, args...)...)
	// Minimal environment: no console token, no inherited secrets.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LANG=C", "USER=" + os.Getenv("USER")}
	if value := os.Getenv("HARNESS_REVIEW_WORK"); value != "" {
		cmd.Env = append(cmd.Env, "HARNESS_REVIEW_WORK="+value)
	}
	out := &limitedBuffer{limit: reviewMapMaxOutput}
	cmd.Stdout = out
	cmd.Stderr = nil
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	return out.Bytes(), runErr
}

func (a *app) sessionRepo(sessionID string) (string, error) {
	a.mu.Lock()
	current := a.findLocked(sessionID)
	if current == nil {
		a.mu.Unlock()
		return "", errors.New("session not found")
	}
	cwd := current.CWD
	a.mu.Unlock()
	cwd, err := validCWD(cwd)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_CONFIG_NOSYSTEM=1"}
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("the session directory is not inside a Git repository")
	}
	top, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		return "", errors.New("repository path unavailable")
	}
	return top, nil
}

func scriptError(out []byte, fallback string) error {
	var reply struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(out, &reply) == nil && reply.Error != "" {
		message := reply.Error
		if len(message) > 300 {
			message = message[:300]
		}
		return errors.New(message)
	}
	return errors.New(fallback)
}

func (a *app) prListHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID string `json:"sessionId"`
		State     string `json:"state"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	state := input.State
	if state != "open" && state != "merged" && state != "closed" && state != "all" {
		state = "open"
	}
	repo, err := a.sessionRepo(input.SessionID)
	if err != nil {
		apiError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, runErr := reviewMapRun(ctx, []string{"list", "--repo", repo, "--state", state, "--limit", "30"})
	var parsed map[string]any
	if runErr != nil || json.Unmarshal(out, &parsed) != nil || parsed["status"] != "OK" {
		apiError(w, scriptError(out, "could not list pull requests; is gh installed and signed in for this repository?"))
		return
	}
	writeJSON(w, 200, parsed)
}

func newNonce() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func reviewMapsDir() (string, error) {
	if value := os.Getenv("HARNESS_REVIEW_WORK"); value != "" {
		return filepath.EvalSymlinks(value)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(filepath.Join(home, ".agent-harness", "work", "review-maps"))
}

func (a *app) prMapHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID string `json:"sessionId"`
		Number    int    `json:"number"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	if input.Number < 1 || input.Number > 999999999 {
		apiError(w, errors.New("invalid pull request number"))
		return
	}
	repo, err := a.sessionRepo(input.SessionID)
	if err != nil {
		apiError(w, err)
		return
	}
	key := repo + "#" + strconv.Itoa(input.Number)
	reviewMapMu.Lock()
	if reviewMapBusy[key] {
		reviewMapMu.Unlock()
		apiError(w, errors.New("a review map for this pull request is already being generated"))
		return
	}
	reviewMapBusy[key] = true
	reviewMapMu.Unlock()
	defer func() { reviewMapMu.Lock(); delete(reviewMapBusy, key); reviewMapMu.Unlock() }()
	args := []string{"generate", "--repo", repo, "--pr", strconv.Itoa(input.Number)}
	if value := os.Getenv("HARNESS_REVIEW_WORK"); value != "" {
		args = append(args, "--out-dir", value)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	out, runErr := reviewMapRun(ctx, args)
	var result struct {
		Status  string         `json:"status"`
		Path    string         `json:"path"`
		SHA     string         `json:"sha256"`
		Tickets []string       `json:"tickets"`
		Counts  map[string]int `json:"counts"`
		Head    string         `json:"head"`
	}
	if runErr != nil || json.Unmarshal(out, &result) != nil || result.Status != "WROTE" {
		apiError(w, scriptError(out, "the review map could not be generated"))
		return
	}
	dir, err := reviewMapsDir()
	if err != nil {
		apiError(w, errors.New("review map directory unavailable"))
		return
	}
	real, err := filepath.EvalSymlinks(result.Path)
	info, statErr := os.Lstat(real)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Size() > reviewMapMaxPage ||
		filepath.Dir(real) != dir {
		apiError(w, errors.New("the generated map is outside the review map directory"))
		return
	}
	nonce, err := newNonce()
	if err != nil {
		apiError(w, errors.New("could not create a map handle"))
		return
	}
	reviewMapMu.Lock()
	now := time.Now()
	for id, item := range reviewMapEntries {
		if now.After(item.expires) {
			delete(reviewMapEntries, id)
		}
	}
	if len(reviewMapEntries) >= reviewMapMaxEntries {
		reviewMapMu.Unlock()
		apiError(w, errors.New("too many open review maps; wait for older ones to expire"))
		return
	}
	reviewMapEntries[nonce] = &reviewMapEntry{path: real, repo: repo, number: input.Number, sha: result.SHA,
		tickets: result.Tickets, expires: now.Add(reviewMapTTL)}
	reviewMapMu.Unlock()
	writeJSON(w, 200, map[string]any{"status": "READY", "mapId": nonce, "url": "/review-map/" + nonce,
		"sha256": result.SHA, "tickets": result.Tickets, "counts": result.Counts, "head": result.Head})
}

func reviewMapLookup(id string) *reviewMapEntry {
	reviewMapMu.Lock()
	defer reviewMapMu.Unlock()
	item := reviewMapEntries[id]
	if item == nil || time.Now().After(item.expires) {
		delete(reviewMapEntries, id)
		return nil
	}
	copy := *item
	return &copy
}

// reviewMapServe sends the page with its own CSP: only its hash-pinned script runs and the
// `sandbox` directive (no allow-same-origin) gives it an opaque origin, so it cannot read
// the console token or call /api even though it is served from the console host.
func (a *app) reviewMapServe(w http.ResponseWriter, r *http.Request) {
	item := reviewMapLookup(r.PathValue("id"))
	if item == nil {
		http.Error(w, "review map expired or unknown", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(item.path)
	if err != nil || len(data) > reviewMapMaxPage {
		http.Error(w, "review map unavailable", http.StatusNotFound)
		return
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != item.sha {
		http.Error(w, "review map changed since it was generated", http.StatusConflict)
		return
	}
	scripts := scriptTag.FindAllSubmatch(data, -1)
	if len(scripts) != 1 {
		http.Error(w, "review map has an unexpected script layout", http.StatusConflict)
		return
	}
	digest := sha256.Sum256(scripts[0][1])
	pin := base64.StdEncoding.EncodeToString(digest[:])
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-%s'; "+
		"connect-src 'none'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox allow-scripts", pin))
	h.Set("Content-Disposition", "inline")
	_, _ = w.Write(data)
}

func (a *app) prAttachHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		MapID   string   `json:"mapId"`
		Tickets []string `json:"tickets"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	item := reviewMapLookup(input.MapID)
	if item == nil {
		apiError(w, errors.New("review map expired; generate it again"))
		return
	}
	if len(input.Tickets) == 0 || len(input.Tickets) > 8 {
		apiError(w, errors.New("confirm between one and eight tickets"))
		return
	}
	guard := "attach:" + item.sha
	reviewMapMu.Lock()
	if reviewMapBusy[guard] {
		reviewMapMu.Unlock()
		apiError(w, errors.New("an attach for this review map is already running"))
		return
	}
	reviewMapBusy[guard] = true
	reviewMapMu.Unlock()
	defer func() { reviewMapMu.Lock(); delete(reviewMapBusy, guard); reviewMapMu.Unlock() }()
	known := map[string]bool{}
	for _, ref := range item.tickets {
		known[ref] = true
	}
	args := []string{"attach", "--map", item.path, "--expect-sha256", item.sha, "--yes"}
	for _, ref := range input.Tickets {
		if !ticketRef.MatchString(ref) || !known[ref] {
			apiError(w, errors.New("a ticket is not one of the references in this pull request's commits"))
			return
		}
		args = append(args, "--ticket", ref)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	out, runErr := reviewMapRun(ctx, args)
	var parsed map[string]any
	if json.Unmarshal(out, &parsed) != nil {
		apiError(w, scriptError(out, "attach did not return a result"))
		return
	}
	status := 200
	if runErr != nil {
		status = 207 // partial: the per-ticket results say which failed
	}
	writeJSON(w, status, parsed)
}
