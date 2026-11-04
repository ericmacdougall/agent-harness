package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testPage = "<!doctype html><html><body><script>var x=1;</script></body></html>"

func reviewMapSetup(t *testing.T) (*app, string, string, *[][]string) {
	t.Helper()
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	maps := t.TempDir()
	maps, _ = filepath.EvalSymlinks(maps)
	t.Setenv("HARNESS_REVIEW_WORK", maps)
	a := testApp(t)
	s := emptySession("codex", repo, "")
	s.ID = "s1"
	a.mu.Lock()
	a.sessions = append(a.sessions, s)
	a.mu.Unlock()
	page := filepath.Join(maps, "r-pr7-abc.html")
	if err := os.WriteFile(page, []byte(testPage), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(testPage))
	digest := hex.EncodeToString(sum[:])
	calls := &[][]string{}
	old := reviewMapRun
	t.Cleanup(func() { reviewMapRun = old; reviewMapEntries = map[string]*reviewMapEntry{} })
	reviewMapRun = func(_ context.Context, args []string) ([]byte, error) {
		*calls = append(*calls, args)
		switch args[0] {
		case "generate":
			b, _ := json.Marshal(map[string]any{"status": "WROTE", "path": page, "sha256": digest, "head": "abc",
				"tickets": []string{"GoodQA goodqa#14388"}, "counts": map[string]int{"files": 1}})
			return b, nil
		case "list":
			return []byte(`{"status":"OK","repo":"r","prs":[{"number":7,"title":"t","state":"OPEN"}]}`), nil
		case "attach":
			return []byte(`{"status":"OK","results":[{"ticket":"GoodQA goodqa#14388","status":"ATTACHED"}]}`), nil
		}
		return nil, os.ErrInvalid
	}
	return a, "s1", digest, calls
}

func post(t *testing.T, a *app, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := a.handler("127.0.0.1:1", "tok")
	r := httptest.NewRequest("POST", "http://127.0.0.1:1"+path, strings.NewReader(body))
	r.Host = "127.0.0.1:1"
	r.Header.Set("Origin", "http://127.0.0.1:1")
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestReviewMapGenerateServeAttach(t *testing.T) {
	a, sid, digest, calls := reviewMapSetup(t)
	w := post(t, a, "/api/prs", `{"sessionId":"`+sid+`"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"number":7`) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/api/prs/review-map", `{"sessionId":"`+sid+`","number":7}`)
	if w.Code != 200 {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}
	var made struct {
		MapID, URL string
		Tickets    []string
	}
	_ = json.Unmarshal([]byte(strings.NewReplacer(`"mapId"`, `"MapID"`, `"url"`, `"URL"`, `"tickets"`, `"Tickets"`).Replace(w.Body.String())), &made)
	if len(made.MapID) < 40 || made.URL != "/review-map/"+made.MapID {
		t.Fatalf("handle: %+v", made)
	}
	if got := (*calls)[len(*calls)-1]; got[0] != "generate" || got[2] == "" || got[3] != "--pr" || got[4] != "7" {
		t.Fatalf("argv %v", got)
	}
	// The map URL needs no console token (a frame cannot send one) but sends a sandboxed CSP pinned to the script.
	h := a.handler("127.0.0.1:1", "tok")
	r := httptest.NewRequest("GET", "http://127.0.0.1:1"+made.URL, nil)
	r.Host = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Body.String() != testPage {
		t.Fatalf("serve: %d", rec.Code)
	}
	script := sha256.Sum256([]byte("var x=1;"))
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"sandbox allow-scripts", "default-src 'none'", "connect-src 'none'", "'sha256-" + base64.StdEncoding.EncodeToString(script[:]) + "'", "frame-ancestors 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("csp missing %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "allow-same-origin") || rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatalf("sandbox must stay opaque-origin: %s", csp)
	}
	// Attach: only tickets that the PR's commits cite.
	w = post(t, a, "/api/prs/review-map/attach", `{"mapId":"`+made.MapID+`","tickets":["GoodQA other#1"]}`)
	if w.Code != 400 {
		t.Fatalf("foreign ticket accepted: %d %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/api/prs/review-map/attach", `{"mapId":"`+made.MapID+`","tickets":["GoodQA goodqa#14388"]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ATTACHED") {
		t.Fatalf("attach: %d %s", w.Code, w.Body.String())
	}
	if got := (*calls)[len(*calls)-1]; got[0] != "attach" || got[3] != "--expect-sha256" || got[4] != digest || got[5] != "--yes" || got[6] != "--ticket" || got[7] != "GoodQA goodqa#14388" {
		t.Fatalf("attach argv %v", got)
	}
}

func TestReviewMapRejectsHostileInput(t *testing.T) {
	a, sid, _, calls := reviewMapSetup(t)
	for name, body := range map[string]string{
		"shell metachar number": `{"sessionId":"` + sid + `","number":"1;id"}`,
		"zero":                  `{"sessionId":"` + sid + `","number":0}`,
		"negative":              `{"sessionId":"` + sid + `","number":-3}`,
		"huge":                  `{"sessionId":"` + sid + `","number":99999999999}`,
		"unknown session":       `{"sessionId":"nope","number":3}`,
		"client repo field":     `{"sessionId":"` + sid + `","number":3,"repo":"/etc"}`,
		"client path field":     `{"sessionId":"` + sid + `","number":3,"path":"/etc/passwd"}`,
	} {
		w := post(t, a, "/api/prs/review-map", body)
		if w.Code == 200 {
			t.Fatalf("%s accepted: %s", name, w.Body.String())
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("script ran for rejected input: %v", *calls)
	}
	// No bearer, no mutation.
	h := a.handler("127.0.0.1:1", "tok")
	r := httptest.NewRequest("POST", "http://127.0.0.1:1/api/prs", strings.NewReader(`{"sessionId":"s1"}`))
	r.Host = "127.0.0.1:1"
	r.Header.Set("Origin", "http://127.0.0.1:1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthenticated list: %d", w.Code)
	}
	// Unknown and tampered handles.
	r = httptest.NewRequest("GET", "http://127.0.0.1:1/review-map/deadbeef", nil)
	r.Host = "127.0.0.1:1"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("unknown handle: %d", w.Code)
	}
}

func TestReviewMapRefusesChangedOrOutsideFile(t *testing.T) {
	a, sid, _, _ := reviewMapSetup(t)
	w := post(t, a, "/api/prs/review-map", `{"sessionId":"`+sid+`","number":7}`)
	var made struct{ MapID string }
	_ = json.Unmarshal([]byte(strings.Replace(w.Body.String(), `"mapId"`, `"MapID"`, 1)), &made)
	reviewMapMu.Lock()
	path := reviewMapEntries[made.MapID].path
	reviewMapMu.Unlock()
	_ = os.WriteFile(path, []byte(testPage+"<!-- tamper -->"), 0o600)
	h := a.handler("127.0.0.1:1", "tok")
	r := httptest.NewRequest("GET", "http://127.0.0.1:1/review-map/"+made.MapID, nil)
	r.Host = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 409 {
		t.Fatalf("tampered map served: %d", rec.Code)
	}
	// A script that reports a path outside the map directory is refused.
	reviewMapRun = func(context.Context, []string) ([]byte, error) {
		return []byte(`{"status":"WROTE","path":"/etc/hosts","sha256":"x","tickets":[]}`), nil
	}
	w = post(t, a, "/api/prs/review-map", `{"sessionId":"`+sid+`","number":8}`)
	if w.Code == 200 {
		t.Fatalf("outside path accepted: %s", w.Body.String())
	}
}
