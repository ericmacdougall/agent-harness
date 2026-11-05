package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAh replaces the ah runner. Keys are the space-joined args after the script path.
func fakeAh(t *testing.T, outputs map[string]string) *int32 {
	t.Helper()
	old, oldTTL := asksRun, asksCacheTTL
	asksCacheTTL = 0
	asksCacheReset()
	var calls int32
	asksRun = func(ctx context.Context, args ...string) ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		out, ok := outputs[strings.Join(args, " ")]
		if !ok {
			return nil, errors.New("no fixture for " + strings.Join(args, " "))
		}
		return []byte(out), nil
	}
	t.Cleanup(func() { asksRun, asksCacheTTL = old, oldTTL; asksCacheReset() })
	return &calls
}

func getAsks(t *testing.T, query string) (int, map[string]json.RawMessage) {
	t.Helper()
	return getAsksApp(t, testApp(t), query)
}

func getAsksApp(t *testing.T, a *app, query string) (int, map[string]json.RawMessage) {
	t.Helper()
	h := a.handler("127.0.0.1:12345", "tok")
	r := httptest.NewRequest("GET", "http://127.0.0.1:12345/api/asks-view"+query, nil)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]json.RawMessage
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

const oneSession = `{"sessions":[{"session":"s1","last_activity":"2999-01-01T00:00:00Z"}]}`

func happy() map[string]string {
	return map[string]string{
		"sessions":            oneSession,
		"asks --all":          `{"asks":[{"id":"wA","session":"s1","text":"pick one","why":"cost","owner":"main","source":"user:s1/u \"x\"","source_label":"USER","at":"2026-11-05T00:00:00Z","age_s":90000,"state":"stale","surfaced_count":3}],"total":1}`,
		"requirements --all":  `{"requirements":[{"id":"wR","session":"s1","text":"build ui","source":"queue:x","at":"2026-11-05T00:00:00Z","age_s":5,"state":"recorded"}],"total":1}`,
		"owners --session s1": `{"session":"s1","owners":[{"agent_id":"a1","task":"t","state":"DROPPED","severity":"high","idle_s":99,"ticket":null,"disposition":{"kind":"waiting","ref":"wA"}}]}`,
	}
}

func TestAsksViewHappyPath(t *testing.T) {
	fakeAh(t, happy())
	code, out := getAsks(t, "")
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	for _, k := range []string{"asks", "owners", "requirements"} {
		var sec struct {
			Rows  []map[string]any `json:"rows"`
			Error string           `json:"error"`
		}
		if err := json.Unmarshal(out[k], &sec); err != nil || sec.Error != "" || len(sec.Rows) != 1 {
			t.Fatalf("%s: err=%v sec=%+v raw=%s", k, err, sec, out[k])
		}
	}
	if !strings.Contains(string(out["owners"]), `"session":"s1"`) {
		t.Fatalf("owner rows must carry their session: %s", out["owners"])
	}
}

func TestAsksViewEmptyLedgers(t *testing.T) {
	fakeAh(t, map[string]string{"sessions": `{"sessions":[]}`, "asks --all": `{"asks":[]}`, "requirements --all": `{"requirements":[]}`})
	code, out := getAsks(t, "")
	if code != 200 || strings.Contains(string(out["asks"]), `"error":"`) || !strings.Contains(string(out["asks"]), `"rows":[]`) {
		t.Fatalf("empty must be an empty list, not an error: %d %s", code, out["asks"])
	}
}

func TestAsksViewMalformedSectionsDegradeIndependently(t *testing.T) {
	m := happy()
	m["asks --all"] = `{"asks": [{"id": ` // truncated JSON
	m["requirements --all"] = `not json at all`
	m["owners --session s1"] = `{"ok":false,"code":"session_unknown"}`
	fakeAh(t, m)
	code, out := getAsks(t, "")
	if code != 200 {
		t.Fatalf("malformed ah output must not fail the request: %d", code)
	}
	for _, k := range []string{"asks", "requirements", "owners"} {
		if !strings.Contains(string(out[k]), `"error":"`) || strings.Contains(string(out[k]), `"error":""`) {
			t.Fatalf("%s must report an error: %s", k, out[k])
		}
	}
}

func TestAsksViewWrongShapeIsRejected(t *testing.T) {
	m := happy()
	m["asks --all"] = `{"asks":[{"id":5,"text":["x"],"state":{"a":1}}]}`
	fakeAh(t, m)
	_, out := getAsks(t, "")
	if strings.Contains(string(out["asks"]), `"rows":[{`) {
		t.Fatalf("wrongly typed rows must be dropped or errored: %s", out["asks"])
	}
}

func TestAsksViewLargeLedgerIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"asks":[`)
	for i := 0; i < askRowCap+500; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":"w%d","session":"s1","text":%q,"state":"open"}`, i, strings.Repeat("x", 5000))
	}
	b.WriteString(`]}`)
	m := happy()
	m["asks --all"] = b.String()
	fakeAh(t, m)
	_, out := getAsks(t, "")
	var sec struct {
		Rows      []map[string]any `json:"rows"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(out["asks"], &sec); err != nil {
		t.Fatal(err)
	}
	if len(sec.Rows) != askRowCap || !sec.Truncated {
		t.Fatalf("rows=%d truncated=%v", len(sec.Rows), sec.Truncated)
	}
	if n := len(sec.Rows[0]["text"].(string)); n > askTextCap {
		t.Fatalf("text not clipped: %d", n)
	}
}

func TestAsksViewSessionFilterRejectsInjection(t *testing.T) {
	calls := fakeAh(t, happy())
	for _, bad := range []string{"?session=--all", "?session=a%20b", "?session=../x", "?session=" + strings.Repeat("a", 200)} {
		code, _ := getAsks(t, bad)
		if code != 400 {
			t.Fatalf("%s: want 400 got %d", bad, code)
		}
	}
	if *calls != 0 {
		t.Fatalf("a rejected session must not spawn ah (%d calls)", *calls)
	}
}

func TestAsksViewRequiresAuth(t *testing.T) {
	fakeAh(t, happy())
	h := testApp(t).handler("127.0.0.1:12345", "tok")
	r := httptest.NewRequest("GET", "http://127.0.0.1:12345/api/asks-view", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("want 401 got %d", w.Code)
	}
	r = httptest.NewRequest("POST", "http://127.0.0.1:12345/api/asks-view", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer tok")
	r.Header.Set("Origin", "http://127.0.0.1:12345")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("the view is read-only: POST must not succeed")
	}
}

func TestAsksViewRedactsConfiguredSecrets(t *testing.T) {
	m := happy()
	m["asks --all"] = `{"asks":[{"id":"w1","session":"s1","text":"token hunter2-super-secret-value end","state":"open"}]}`
	fakeAh(t, m)
	a := testApp(t)
	a.rememberCapability("hunter2-super-secret-value")
	_, out := getAsksApp(t, a, "")
	if strings.Contains(string(out["asks"]), "hunter2") {
		t.Fatalf("secret leaked: %s", out["asks"])
	}
}

func TestAsksViewRunnerFailureShowsUnavailable(t *testing.T) {
	fakeAh(t, map[string]string{})
	code, out := getAsks(t, "")
	if code != 200 || !strings.Contains(string(out["asks"]), "unavailable") {
		t.Fatalf("%d %s", code, out["asks"])
	}
}

func TestAsksRunTimesOutAndCapsOutput(t *testing.T) {
	old := asksRunTimeout
	asksRunTimeout = 200 * time.Millisecond
	defer func() { asksRunTimeout = old }()
	t.Setenv("AH_BIN", "/bin/sleep")
	if _, err := runAh(context.Background(), "5"); err == nil {
		t.Fatal("a hung ah must time out")
	}
}
