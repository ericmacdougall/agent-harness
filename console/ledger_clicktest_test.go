package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestServeForClickTest serves the real console handler (real harness binary, real sync-state) with seeded
// sessions and no provider processes, for a browser click-test of the ledger icon. It only runs when asked:
//
//	LEDGER_CLICKTEST_ADDR=127.0.0.1:18765 LEDGER_CLICKTEST_DIRS=/a:/b LEDGER_CLICKTEST_SECONDS=900 \
//	HARNESS_BIN=/path/to/harness HOME=/scratch/home go test ./console -run TestServeForClickTest -v
//
// Open http://127.0.0.1:18765/#token=tok
func TestServeForClickTest(t *testing.T) {
	addr := os.Getenv("LEDGER_CLICKTEST_ADDR")
	if addr == "" {
		t.Skip("set LEDGER_CLICKTEST_ADDR to serve the console for a click-test")
	}
	seconds, _ := strconv.Atoi(os.Getenv("LEDGER_CLICKTEST_SECONDS"))
	if seconds <= 0 {
		seconds = 600
	}
	a := testApp(t)
	a.mu.Lock()
	for _, dir := range strings.Split(os.Getenv("LEDGER_CLICKTEST_DIRS"), ":") {
		if dir == "" {
			continue
		}
		s := emptySession("claude", dir, "")
		s.Status = "idle"
		s.Title = "Session in " + dir[strings.LastIndex(dir, "/")+1:]
		a.sessions = append(a.sessions, s)
	}
	a.mu.Unlock()
	srv := &http.Server{Addr: addr, Handler: a.handler(addr, "tok"), ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("CLICKTEST_URL http://%s/#token=tok\n", addr)
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(time.Duration(seconds) * time.Second)
	_ = srv.Close()
}
