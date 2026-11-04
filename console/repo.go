package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type branchInfo struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
	Ahead    int    `json:"ahead"`
	Behind   int    `json:"behind"`
	Current  bool   `json:"current"`
	Remote   bool   `json:"remote"`
}
type worktreeInfo struct {
	Path     string `json:"path"`
	Branch   string `json:"branch"`
	Head     string `json:"head"`
	Dirty    bool   `json:"dirty"`
	Current  bool   `json:"current"`
	Ahead    int    `json:"ahead"`
	Behind   int    `json:"behind"`
	Locked   bool   `json:"locked"`
	Prunable bool   `json:"prunable"`
	Upstream string `json:"upstream"`
}
type repositoryInfo struct {
	Root      string         `json:"root"`
	Branch    string         `json:"branch"`
	Head      string         `json:"head"`
	Dirty     bool           `json:"dirty"`
	Branches  []branchInfo   `json:"branches"`
	Worktrees []worktreeInfo `json:"worktrees"`
}

func commandOutput(ctx context.Context, cwd, binary string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = cwd
	out := &cappedBuffer{limit: 2 << 20}
	command.Stdout = out
	command.Stderr = &cappedBuffer{limit: 32768}
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("%s command failed or timed out", filepath.Base(binary))
	}
	if len(out.data) >= out.limit {
		return "", errors.New("command output exceeded its bound")
	}
	return string(out.data), nil
}
func runCommand(ctx context.Context, cwd, binary string, args ...string) error {
	_, err := commandOutput(ctx, cwd, binary, args...)
	return err
}
func gitOutput(cwd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return commandOutput(ctx, cwd, "git", args...)
}
func gitTracking(path string) (string, int, int) {
	name, e := gitOutput(path, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
	if e != nil {
		return "", 0, 0
	}
	counts, e := gitOutput(path, "rev-list", "--left-right", "--count", "HEAD...@{upstream}")
	if e != nil {
		return strings.TrimSpace(name), 0, 0
	}
	parts := strings.Fields(counts)
	if len(parts) != 2 {
		return strings.TrimSpace(name), 0, 0
	}
	ahead, _ := strconv.Atoi(parts[0])
	behind, _ := strconv.Atoi(parts[1])
	return strings.TrimSpace(name), ahead, behind
}
func containedPath(root, path string) bool {
	relative, e := filepath.Rel(root, path)
	return e == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
func readRepository(cwd string) (repositoryInfo, error) {
	result := repositoryInfo{Branches: []branchInfo{}, Worktrees: []worktreeInfo{}}
	root, e := gitOutput(cwd, "rev-parse", "--show-toplevel")
	if e != nil {
		return result, errors.New("selected cwd is not inside a Git worktree")
	}
	result.Root = strings.TrimSpace(root)
	head, e := gitOutput(cwd, "rev-parse", "HEAD")
	if e != nil {
		return result, e
	}
	result.Head = strings.TrimSpace(head)
	branch, _ := gitOutput(cwd, "branch", "--show-current")
	result.Branch = strings.TrimSpace(branch)
	status, e := gitOutput(cwd, "status", "--porcelain", "-z")
	if e != nil {
		return result, e
	}
	result.Dirty = status != ""
	refs, e := gitOutput(cwd, "for-each-ref", "--format=%(refname:short)%09%(upstream:short)%09%(upstream:track)%09%(refname)", "refs/heads", "refs/remotes")
	if e != nil {
		return result, e
	}
	for _, line := range strings.Split(strings.TrimSpace(refs), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			continue
		}
		item := branchInfo{Name: fields[0], Upstream: fields[1], Current: fields[0] == result.Branch, Remote: strings.HasPrefix(fields[3], "refs/remotes/")}
		tracking := strings.Fields(strings.Trim(fields[2], "[]"))
		for i := 0; i+1 < len(tracking); i++ {
			value, _ := strconv.Atoi(strings.Trim(tracking[i+1], ","))
			if tracking[i] == "ahead" {
				item.Ahead = value
			}
			if tracking[i] == "behind" {
				item.Behind = value
			}
		}
		result.Branches = append(result.Branches, item)
	}
	trees, e := gitOutput(cwd, "worktree", "list", "--porcelain", "-z")
	if e != nil {
		return result, e
	}
	var item worktreeInfo
	flush := func() {
		if item.Path != "" {
			state, err := gitOutput(item.Path, "status", "--porcelain", "-z")
			item.Dirty = err != nil || state != ""
			item.Current = containedPath(item.Path, cwd)
			item.Upstream, item.Ahead, item.Behind = gitTracking(item.Path)
			result.Worktrees = append(result.Worktrees, item)
		}
		item = worktreeInfo{}
	}
	for _, raw := range bytes.Split([]byte(trees), []byte{0}) {
		field := string(raw)
		if field == "" {
			flush()
			continue
		}
		key, value, _ := strings.Cut(field, " ")
		switch key {
		case "worktree":
			if item.Path != "" {
				flush()
			}
			item.Path = value
		case "HEAD":
			item.Head = value
		case "branch":
			item.Branch = strings.TrimPrefix(value, "refs/heads/")
		case "locked":
			item.Locked = true
		case "prunable":
			item.Prunable = true
		}
	}
	flush()
	return result, nil
}
func (a *app) repoForSession(id string) (repositoryInfo, error) {
	a.mu.Lock()
	current := a.findLocked(id)
	if current == nil {
		a.mu.Unlock()
		return repositoryInfo{}, errors.New("session not found")
	}
	cwd := current.CWD
	a.mu.Unlock()
	return readRepository(cwd)
}
func (a *app) gitStatusHTTP(w http.ResponseWriter, r *http.Request) {
	result, e := a.repoForSession(r.URL.Query().Get("sessionId"))
	if e != nil {
		apiError(w, e)
		return
	}
	writeJSON(w, 200, result)
}
func (a *app) gitRefreshHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID string `json:"sessionId"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	a.gitMu.Lock()
	defer a.gitMu.Unlock()
	repo, e := a.repoForSession(input.SessionID)
	if e == nil {
		_, e = gitOutput(repo.Root, "fetch", "--prune")
	}
	if e != nil {
		apiError(w, e)
		return
	}
	result, e := a.repoForSession(input.SessionID)
	if e != nil {
		apiError(w, e)
		return
	}
	writeJSON(w, 200, result)
}
func (a *app) gitSyncHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID    string `json:"sessionId"`
		Path         string `json:"path"`
		ExpectedHead string `json:"expectedHead"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	a.gitMu.Lock()
	defer a.gitMu.Unlock()
	repo, e := a.repoForSession(input.SessionID)
	if e != nil {
		apiError(w, e)
		return
	}
	var selected *worktreeInfo
	for i := range repo.Worktrees {
		if repo.Worktrees[i].Path == input.Path {
			selected = &repo.Worktrees[i]
		}
	}
	if selected == nil || selected.Head != input.ExpectedHead || selected.Dirty || selected.Locked || selected.Branch == "" {
		apiError(w, errors.New("sync requires the current expected clean attached worktree"))
		return
	}
	if _, e = gitOutput(selected.Path, "fetch", "--prune"); e != nil {
		apiError(w, e)
		return
	}
	check, e := gitOutput(selected.Path, "rev-parse", "HEAD")
	if e != nil || strings.TrimSpace(check) != input.ExpectedHead {
		apiError(w, errors.New("worktree changed during sync"))
		return
	}
	if selected.Upstream != "" {
		if _, e = gitOutput(selected.Path, "merge", "--ff-only", "@{upstream}"); e != nil {
			apiError(w, errors.New("histories diverged or merge is unsafe"))
			return
		}
		_, e = gitOutput(selected.Path, "push")
	} else {
		_, e = gitOutput(selected.Path, "push", "--set-upstream", "origin", "HEAD")
	}
	if e != nil {
		apiError(w, errors.New("local work is retained; remote push did not complete successfully"))
		return
	}
	result, e := a.repoForSession(input.SessionID)
	if e != nil {
		apiError(w, e)
		return
	}
	writeJSON(w, 200, result)
}
func (a *app) gitRemoveHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID    string `json:"sessionId"`
		Path         string `json:"path"`
		ExpectedHead string `json:"expectedHead"`
		ConfirmPath  string `json:"confirmPath"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	a.gitMu.Lock()
	defer a.gitMu.Unlock()
	repo, e := a.repoForSession(input.SessionID)
	if e != nil {
		apiError(w, e)
		return
	}
	var selected *worktreeInfo
	for i := range repo.Worktrees {
		if repo.Worktrees[i].Path == input.Path {
			selected = &repo.Worktrees[i]
		}
	}
	if selected == nil || input.ConfirmPath != selected.Path || input.ExpectedHead != selected.Head || selected.Dirty || selected.Locked || selected.Upstream == "" || selected.Ahead > 0 {
		apiError(w, errors.New("removal refused: confirm the exact clean, unlocked, fully pushed worktree"))
		return
	}
	a.mu.Lock()
	protected := false
	for _, current := range a.sessions {
		if containedPath(selected.Path, current.CWD) {
			protected = true
		}
	}
	a.mu.Unlock()
	if protected {
		apiError(w, errors.New("a console session is using this worktree"))
		return
	}
	if _, e = gitOutput(repo.Root, "worktree", "remove", selected.Path); e != nil {
		apiError(w, e)
		return
	}
	result, e := a.repoForSession(input.SessionID)
	if e != nil {
		apiError(w, e)
		return
	}
	writeJSON(w, 200, result)
}
