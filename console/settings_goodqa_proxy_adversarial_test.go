package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGoodQAProxyRejectsHostileUpstreamAndNeverReplays(t *testing.T) {
	for _, mode := range []string{"wrong-id", "request", "oversize", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			_, _, snapshot, f := goodqaTestSetup(t)
			f.mu.Lock()
			f.mode = mode
			f.mu.Unlock()
			client := newGoodQAHTTP(snapshot.Endpoint, goodqaTestToken)
			if e := client.initialize(context.Background()); e != nil {
				t.Fatal(e)
			}
			client.timeout = 100 * time.Millisecond
			_, e := client.call(context.Background(), "tools/call", map[string]any{"name": "safe_read", "arguments": map[string]any{"nonce": "adversarial-control"}})
			var outcome *goodqaOutcomeError
			if !errors.As(e, &outcome) || !outcome.unknown {
				t.Fatal("invalid/accepted request was not labeled unknown")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.calls) != 1 {
				t.Fatal("request replayed")
			}
			if mode == "request" && f.rejected != 1 {
				t.Fatal("server-initiated request was not rejected")
			}
		})
	}
}
func TestGoodQAProxyRevocationAllowsOnlyAlreadyAcceptedCall(t *testing.T) {
	s, _, snapshot, f := goodqaTestSetup(t)
	f.accepted = make(chan struct{})
	f.release = make(chan struct{})
	client := newGoodQAHTTP(snapshot.Endpoint, goodqaTestToken)
	if e := client.initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	server := goodqaStdio{snapshot: snapshot, upstream: client, initialized: true, ready: true, diagnostics: io.Discard}
	done := make(chan any, 1)
	go func() {
		result, code, _ := server.call(context.Background(), json.RawMessage(`{"name":"safe_read","arguments":{"nonce":"accepted-before-revocation"}}`))
		if code != 0 {
			done <- nil
		} else {
			done <- result
		}
	}()
	<-f.accepted
	next := settingsTestCopy(s)
	next.GoodQA.Enabled = false
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	close(f.release)
	result := <-done
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), "accepted-before-revocation") {
		t.Fatal("already accepted call incorrectly discarded or replayed")
	}
	if _, code, _ := server.call(context.Background(), json.RawMessage(`{"name":"safe_read","arguments":{}}`)); code != -32003 {
		t.Fatal("new revoked call was dispatched")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 {
		t.Fatal("revocation allowed another upstream call")
	}
}
func TestGoodQAProxyConcurrentSessionsRemainScoped(t *testing.T) {
	_, v, snapshot, f := goodqaTestSetup(t)
	var wg sync.WaitGroup
	errorsOut := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out, log bytes.Buffer
			e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(goodqaTestInput()), &out, &log)
			if e == nil && strings.Contains(out.String()+log.String(), goodqaTestToken) {
				e = errors.New("bearer escaped")
			}
			errorsOut <- e
		}()
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		if e := <-errorsOut; e != nil {
			t.Fatal(e)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 2 || f.sessions != 3 {
		t.Fatal("two proxy sessions did not negotiate separate upstream sessions", len(f.calls), f.sessions)
	}
}
func TestGoodQAProxyForeignRedirectNeverReceivesCredential(t *testing.T) {
	hits := 0
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
	defer foreign.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, foreign.URL, 307) }))
	defer origin.Close()
	client := newGoodQAHTTP(origin.URL, goodqaTestToken)
	if e := client.initialize(context.Background()); e == nil {
		t.Fatal("redirect accepted")
	}
	if hits != 0 {
		t.Fatal("credential sent to redirected origin")
	}
}
func TestGoodQAProxyStaleOrMalformedAdmissionFailsBeforeUpstream(t *testing.T) {
	s, v, snapshot, f := goodqaTestSetup(t)
	data, _ := json.Marshal(snapshot)
	snapshot.CredentialRef = "malformed"
	bad, _ := json.Marshal(snapshot)
	path := filepath.Join(s.dir, "mcp", "malformed.json")
	if e := settingsAtomicWrite(path, bad); e != nil {
		t.Fatal(e)
	}
	if _, e := loadGoodQASnapshot(path, settingsDigest(bad)); e == nil {
		t.Fatal("malformed vault ref admitted")
	}
	_ = json.Unmarshal(data, &snapshot)
	next := settingsTestCopy(s)
	next.Defaults.Effort = "medium"
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	var out, logs bytes.Buffer
	if e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(goodqaTestInput()), &out, &logs); e == nil {
		t.Fatal("stale revision admitted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessions != 1 || len(f.calls) != 0 {
		t.Fatal("stale helper reached upstream")
	}
}
