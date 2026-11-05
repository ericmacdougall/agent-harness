package main

// Ledger sync state for the sidebar icon (docs/ledger.md). The console never reads a ledger itself: it runs
// `harness tickets sync-state --json` for each working directory, with no shell, a deadline, an output cap and
// at most four at once, and reports "unknown" for anything that goes wrong.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	ledgerMaxDirs     = 32
	ledgerOutputCap   = 64 * 1024
	ledgerParallel    = 4
	ledgerCacheWindow = 10 * time.Second
)

var ledgerRunTimeout = 3 * time.Second

var ledgerStates = map[string]bool{"none": true, "local-only": true, "pending": true, "synced": true, "diverged": true, "tracked": true}

type ledgerState struct {
	State    string `json:"state"`
	Unsynced int    `json:"unsynced"`
	Slug     string `json:"slug"`
}

type ledgerCacheEntry struct {
	at    time.Time
	state ledgerState
}

var (
	ledgerMu    sync.Mutex
	ledgerCache = map[string]ledgerCacheEntry{}
	ledgerSlots = make(chan struct{}, ledgerParallel)
	ledgerNow   = time.Now
	// ledgerRun runs the harness binary and returns its bounded stdout; tests replace it.
	ledgerRun = runHarnessSyncState
)

// harnessBinary finds the harness executable: $HARNESS_BIN, else `harness` beside this executable, else PATH.
func harnessBinary() (string, error) {
	if p := os.Getenv("HARNESS_BIN"); p != "" {
		return p, nil
	}
	if exe, err := os.Executable(); err == nil {
		beside := filepath.Join(filepath.Dir(exe), "harness")
		if fi, err := os.Stat(beside); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return beside, nil
		}
	}
	return exec.LookPath("harness")
}

func runHarnessSyncState(ctx context.Context, dir string) ([]byte, error) {
	bin, err := harnessBinary()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, ledgerRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "tickets", "sync-state", "--json")
	cmd.Dir = dir
	out := &cappedBuffer{limit: ledgerOutputCap}
	cmd.Stdout = out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, errors.New("sync-state failed or timed out")
	}
	if len(out.data) >= out.limit {
		return nil, errors.New("sync-state output exceeded its bound")
	}
	return out.data, nil
}

// ledgerFor returns the state for one working directory: "unknown" unless the directory is absolute, real and
// the harness answers with one of the six states.
func ledgerFor(ctx context.Context, dir string) ledgerState {
	unknown := ledgerState{State: "unknown"}
	if !filepath.IsAbs(dir) {
		return unknown
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return unknown
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return unknown
	}
	ledgerMu.Lock()
	if c, ok := ledgerCache[real]; ok && ledgerNow().Sub(c.at) < ledgerCacheWindow {
		ledgerMu.Unlock()
		return c.state
	}
	ledgerMu.Unlock()
	select {
	case ledgerSlots <- struct{}{}:
		defer func() { <-ledgerSlots }()
	case <-ctx.Done():
		return unknown
	}
	out, err := ledgerRun(ctx, real)
	if err != nil {
		return unknown
	}
	var doc struct {
		State    string `json:"state"`
		Unsynced int    `json:"unsynced_ops"`
		Slug     string `json:"slug"`
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	if dec.Decode(&doc) != nil || !ledgerStates[doc.State] {
		return unknown
	}
	if doc.Unsynced < 0 {
		doc.Unsynced = 0
	}
	st := ledgerState{State: doc.State, Unsynced: doc.Unsynced}
	if len(doc.Slug) <= 40 && slugOK(doc.Slug) {
		st.Slug = doc.Slug
	}
	ledgerMu.Lock()
	ledgerCache[real] = ledgerCacheEntry{at: ledgerNow(), state: st}
	ledgerMu.Unlock()
	return st
}

func slugOK(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// ledgerSyncHTTP serves POST /api/ledger/sync-state: {"cwds": [...]} -> {"states": {cwd: state}}.
func (a *app) ledgerSyncHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Cwds []string `json:"cwds"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	if len(input.Cwds) == 0 || len(input.Cwds) > ledgerMaxDirs {
		apiError(w, errors.New("send between 1 and 32 working directories"))
		return
	}
	states := make(map[string]ledgerState, len(input.Cwds))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, dir := range input.Cwds {
		dir := dir
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := ledgerFor(r.Context(), dir)
			mu.Lock()
			states[dir] = st
			mu.Unlock()
		}()
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"states": states})
}
