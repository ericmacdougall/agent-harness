package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func validateGoodQAEndpoint(raw string, enabled bool) error {
	if raw == "" {
		if enabled {
			return errors.New("GoodQA requires an explicit MCP endpoint")
		}
		return nil
	}
	if len(raw) > 2048 {
		return errors.New("GoodQA endpoint too long")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return errors.New("GoodQA endpoint must be an absolute URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && oneOf(u.Hostname(), "127.0.0.1", "localhost", "::1")) {
		return errors.New("GoodQA requires HTTPS except explicit loopback HTTP")
	}
	return nil
}
func (s *settingsStore) registerGoodQARoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/settings/goodqa/probe", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if e := decodeJSON(w, r, &in); e != nil {
			settingsError(w, e)
			return
		}
		result, e := s.probeGoodQA(r.Context())
		if e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, result)
	})
}
func (s *settingsStore) probeGoodQA(ctx context.Context) (map[string]any, error) {
	s.mu.Lock()
	g := s.disk.Settings.GoodQA
	ref := s.disk.Refs["goodqa:credential"]
	s.mu.Unlock()
	if !g.Enabled {
		return nil, errors.New("GoodQA disabled; explicitly opt in before discovery")
	}
	if e := validateGoodQAEndpoint(g.Endpoint, true); e != nil {
		return nil, e
	}
	token := ""
	if ref != "" {
		var e error
		token, e = s.readSecret(ctx, ref)
		if e != nil {
			return nil, e
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := newGoodQAHTTP(g.Endpoint, token)
	if e := client.initialize(ctx); e != nil {
		return nil, errors.New("GoodQA initialization failed; check endpoint, credential scope and supported protocol")
	}
	tools, e := client.tools(ctx)
	if e != nil {
		return nil, errors.New("GoodQA catalog rejected: invalid, unsupported or beyond discovery limits")
	}
	safe := goodqaFilterJSON(goodqaCatalog{Generation: g.Generation, Endpoint: g.Endpoint, CredentialRef: ref, Tools: tools}, []string{token})
	data, _ := json.Marshal(safe)
	var catalog goodqaCatalog
	if settingsDecode(data, &catalog) != nil {
		return nil, errors.New("GoodQA catalog could not be safely recorded")
	}
	for _, tool := range catalog.Tools {
		if !goodqaToolName.MatchString(tool.Name) {
			return nil, errors.New("GoodQA catalog contains unsafe tool metadata")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disk.Settings.GoodQA.Generation != g.Generation || s.disk.Settings.GoodQA.Endpoint != g.Endpoint || s.disk.Refs["goodqa:credential"] != ref {
		return nil, errSettingsConflict
	}
	if e = settingsAtomicWrite(filepath.Join(s.dir, "goodqa-catalog.json"), data); e != nil {
		return nil, e
	}
	out := []map[string]any{}
	for _, tool := range catalog.Tools {
		out = append(out, map[string]any{"name": tool.Name, "capability": goodqaCapability(tool.Name), "available": true})
	}
	return map[string]any{"source": "MCP initialize + paginated tools/list", "checkedAt": time.Now().UTC().Format(time.RFC3339), "available": true, "reason": "Read-only discovery complete. Only explicitly selected names with enabled capability groups are exposed through the private proxy; no workers or queues activated.", "tools": out, "partial": false}, nil
}
func goodqaCapability(name string) string {
	name = strings.ToLower(name)
	for _, group := range []struct {
		capability string
		words      []string
	}{{"hive", []string{"hive"}}, {"browser", []string{"browser"}}, {"desktop", []string{"desktop"}}, {"remote", []string{"remote", "machine"}}, {"knowledge", []string{"knowledge", "memory"}}, {"decisions", []string{"decision"}}, {"projects", []string{"project"}}, {"tickets", []string{"ticket", "issue", "comment", "pipeline"}}} {
		for _, word := range group.words {
			if strings.Contains(name, word) {
				return group.capability
			}
		}
	}
	return "other"
}
func goodqaToolEnabled(g settingsGoodQA, name string) bool {
	selected := false
	for _, n := range g.AllowedTools {
		if n == name {
			selected = true
		}
	}
	if !selected {
		return false
	}
	switch goodqaCapability(name) {
	case "desktop":
		return g.Capabilities.Desktop
	case "browser":
		return g.Capabilities.Browser
	case "remote":
		return g.Capabilities.Remote
	case "knowledge":
		return g.Capabilities.Knowledge
	case "hive":
		return g.Capabilities.Hive
	case "tickets":
		return g.Capabilities.Tickets
	case "projects":
		return g.Capabilities.Projects
	case "decisions":
		return g.Capabilities.Decisions
	}
	return true
}
