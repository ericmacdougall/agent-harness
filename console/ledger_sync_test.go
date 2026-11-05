package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ledgerReset(t *testing.T) {
	t.Helper()
	old, oldNow, oldTimeout := ledgerRun, ledgerNow, ledgerRunTimeout
	ledgerMu.Lock()
	ledgerCache = map[string]ledgerCacheEntry{}
	ledgerMu.Unlock()
	t.Cleanup(func() { ledgerRun, ledgerNow, ledgerRunTimeout = old, oldNow, oldTimeout })
}

func ledgerPost(t *testing.T, body string) (int, map[string]ledgerState) {
	t.Helper()
	w := post(t, testApp(t), "/api/ledger/sync-state", body)
	var out struct {
		States map[string]ledgerState `json:"states"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.States
}

func realDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLedgerSyncStatesAndUnknowns(t *testing.T) {
	ledgerReset(t)
	good, garbage, bad, errDir := realDir(t), realDir(t), realDir(t), realDir(t)
	ledgerRun = func(_ context.Context, dir string) ([]byte, error) {
		switch dir {
		case good:
			return []byte(`{"state":"pending","unsynced_ops":3,"slug":"demo"}`), nil
		case garbage:
			return []byte(`not json`), nil
		case bad:
			return []byte(`{"state":"admin","unsynced_ops":1}`), nil
		}
		return nil, fmt.Errorf("boom")
	}
	file := filepath.Join(good, "file.txt")
	os.WriteFile(file, []byte("x"), 0o600)
	body, _ := json.Marshal(map[string]any{"cwds": []string{good, garbage, bad, errDir, "relative/dir", file, filepath.Join(good, "missing")}})
	code, states := ledgerPost(t, string(body))
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if st := states[good]; st.State != "pending" || st.Unsynced != 3 || st.Slug != "demo" {
		t.Fatalf("good: %+v", st)
	}
	for _, d := range []string{garbage, bad, errDir, "relative/dir", file, filepath.Join(good, "missing")} {
		if states[d].State != "unknown" {
			t.Errorf("%s: %+v (want unknown)", d, states[d])
		}
	}
}

func TestLedgerSyncRefusesBadRequests(t *testing.T) {
	ledgerReset(t)
	ledgerRun = func(context.Context, string) ([]byte, error) { return []byte(`{"state":"synced"}`), nil }
	many := make([]string, 33)
	for i := range many {
		many[i] = "/"
	}
	b, _ := json.Marshal(map[string]any{"cwds": many})
	if code, _ := ledgerPost(t, string(b)); code != 400 {
		t.Fatalf("33 directories: %d", code)
	}
	if code, _ := ledgerPost(t, `{"cwds":[]}`); code != 400 {
		t.Fatalf("empty: %d", code)
	}
	if code, _ := ledgerPost(t, `{"cwds":["/"],"extra":1}`); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
	// A cross-origin request and a missing token never reach the handler.
	a := testApp(t)
	h := a.handler("127.0.0.1:1", "tok")
	r := httptest.NewRequest("POST", "http://127.0.0.1:1/api/ledger/sync-state", strings.NewReader(`{"cwds":["/"]}`))
	r.Host = "127.0.0.1:1"
	r.Header.Set("Origin", "http://evil.example")
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-origin: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "http://127.0.0.1:1/api/ledger/sync-state", strings.NewReader(`{"cwds":["/"]}`))
	r.Host = "127.0.0.1:1"
	r.Header.Set("Origin", "http://127.0.0.1:1")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
}

func TestLedgerSyncResolvesSymlinksAndCaches(t *testing.T) {
	ledgerReset(t)
	real := realDir(t)
	link := filepath.Join(realDir(t), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	var calls int32
	var seen string
	ledgerRun = func(_ context.Context, dir string) ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		seen = dir
		return []byte(`{"state":"synced","unsynced_ops":0,"slug":"a"}`), nil
	}
	now := time.Unix(1000, 0)
	ledgerNow = func() time.Time { return now }
	body := `{"cwds":["` + link + `"]}`
	if _, st := ledgerPost(t, body); st[link].State != "synced" || seen != real {
		t.Fatalf("symlink not resolved before use: %q vs %q", seen, real)
	}
	ledgerPost(t, body)
	if calls != 1 {
		t.Fatalf("a result inside 10 s was recomputed: %d calls", calls)
	}
	now = now.Add(11 * time.Second)
	ledgerPost(t, body)
	if calls != 2 {
		t.Fatalf("an expired result was not recomputed: %d calls", calls)
	}
}

func TestLedgerSyncRunsAtMostFourAtOnce(t *testing.T) {
	ledgerReset(t)
	var cur, peak int32
	ledgerRun = func(context.Context, string) ([]byte, error) {
		n := atomic.AddInt32(&cur, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(60 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		return []byte(`{"state":"local-only","unsynced_ops":1}`), nil
	}
	dirs := make([]string, 16)
	for i := range dirs {
		dirs[i] = realDir(t)
	}
	b, _ := json.Marshal(map[string]any{"cwds": dirs})
	if code, st := ledgerPost(t, string(b)); code != 200 || len(st) != 16 {
		t.Fatalf("%d %d", code, len(st))
	}
	if peak > ledgerParallel || peak < 2 {
		t.Fatalf("peak concurrency %d (limit %d)", peak, ledgerParallel)
	}
}

// The real runner: no shell, argv is fixed, the directory is only ever a working directory, and a hung
// harness is stopped at the deadline.
func TestLedgerSyncRealRunnerNoShellAndDeadline(t *testing.T) {
	ledgerReset(t)
	root := realDir(t)
	evil := filepath.Join(root, "a b;touch pwned;$(touch pwned2)")
	if err := os.Mkdir(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	argvLog := filepath.Join(root, "argv.log")
	script := filepath.Join(root, "harness")
	os.WriteFile(script, []byte("#!/bin/sh\necho \"$#:$1:$2:$3\" >> '"+argvLog+"'\npwd >> '"+argvLog+"'\necho '{\"state\":\"local-only\",\"unsynced_ops\":2,\"slug\":\"x\"}'\n"), 0o755)
	t.Setenv("HARNESS_BIN", script)
	if st := ledgerFor(context.Background(), evil); st.State != "local-only" || st.Unsynced != 2 {
		t.Fatalf("%+v", st)
	}
	b, _ := os.ReadFile(argvLog)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if lines[0] != "3:tickets:sync-state:--json" || lines[1] != evil {
		t.Fatalf("argv or cwd: %q", lines)
	}
	for _, f := range []string{"pwned", "pwned2"} {
		if _, err := os.Stat(filepath.Join(evil, f)); err == nil {
			t.Fatalf("the directory name was executed: %s", f)
		}
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			t.Fatalf("the directory name was executed: %s", f)
		}
	}
	// A hung harness stops at the deadline and reads as unknown.
	os.WriteFile(script, []byte("#!/bin/sh\nsleep 20\n"), 0o755)
	ledgerRunTimeout = 300 * time.Millisecond
	hung := realDir(t)
	started := time.Now()
	if st := ledgerFor(context.Background(), hung); st.State != "unknown" {
		t.Fatalf("%+v", st)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("deadline not enforced: %s", time.Since(started))
	}
	// Output past the cap is unknown; a missing binary is unknown.
	os.WriteFile(script, []byte("#!/bin/sh\nhead -c 200000 /dev/zero | tr '\\0' 'a'\n"), 0o755)
	if st := ledgerFor(context.Background(), realDir(t)); st.State != "unknown" {
		t.Fatalf("oversized output: %+v", st)
	}
	t.Setenv("HARNESS_BIN", filepath.Join(root, "absent"))
	if st := ledgerFor(context.Background(), realDir(t)); st.State != "unknown" {
		t.Fatalf("missing binary: %+v", st)
	}
	var wg sync.WaitGroup
	wg.Wait()
}

func TestLedgerSyncCacheIsBounded(t *testing.T) {
	ledgerReset(t)
	ledgerRun = func(context.Context, string) ([]byte, error) { return []byte(`{"state":"synced"}`), nil }
	base := realDir(t)
	for i := 0; i < ledgerCacheMax+50; i++ {
		d := filepath.Join(base, fmt.Sprintf("d%d", i))
		os.Mkdir(d, 0o755)
		ledgerFor(context.Background(), d)
	}
	ledgerMu.Lock()
	n := len(ledgerCache)
	ledgerMu.Unlock()
	if n > ledgerCacheMax {
		t.Fatalf("cache grew to %d (max %d)", n, ledgerCacheMax)
	}
}
