package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type settingsDocument struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Exists   bool   `json:"exists"`
	Editable bool   `json:"editable"`
	Reason   string `json:"reason"`
	Digest   string `json:"digest"`
}
type settingsHook struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Event   string `json:"event"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
	Trust   string `json:"trust"`
	Digest  string `json:"digest"`
	Reason  string `json:"reason"`
}
type settingsParent struct {
	path string
	info os.FileInfo
}
type settingsPreview struct {
	Path, ExpectedDigest string
	Content              []byte
	Mode                 os.FileMode
	Expires              time.Time
	Parents              []settingsParent
	Hook                 *settingsDisabledHook
	Enable               bool
}
type settingsDisabledHook struct {
	ID, Path, Event string
	Group, Index    int
	Handler         json.RawMessage
	Digest          string
}

func (s *settingsStore) registerDocumentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/settings/documents", func(w http.ResponseWriter, r *http.Request) {
		docs, hooks, e := s.listDocuments(r.URL.Query().Get("cwd"))
		if e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"documents": docs, "hooks": hooks})
	})
	mux.HandleFunc("GET /api/settings/document", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		doc, ok := s.docs[r.URL.Query().Get("id")]
		s.mu.Unlock()
		if !ok {
			settingsError(w, errors.New("document is not in the current scoped listing"))
			return
		}
		data, e := settingsRead(doc.Path, 1<<20)
		if e != nil && !os.IsNotExist(e) {
			settingsError(w, e)
			return
		}
		mode := os.FileMode(0600)
		if f, e := os.Lstat(doc.Path); e == nil {
			mode = f.Mode().Perm()
		}
		writeJSON(w, 200, map[string]any{"id": doc.ID, "path": doc.Path, "content": s.redact(string(data)), "digest": settingsDigest(data), "mode": mode, "exists": e == nil, "editable": doc.Editable, "reason": doc.Reason})
	})
	mux.HandleFunc("POST /api/settings/preview", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Kind           string `json:"kind"`
			ID             string `json:"id"`
			ExpectedDigest string `json:"expectedDigest"`
			Content        string `json:"content"`
			Enabled        *bool  `json:"enabled"`
		}
		if e := decodeJSON(w, r, &in); e != nil {
			settingsError(w, e)
			return
		}
		id, p, e := s.previewDocument(in.Kind, in.ID, in.ExpectedDigest, in.Content, in.Enabled)
		if e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"previewId": id, "path": p.Path, "summary": fmt.Sprintf("Replace %d bytes after digest and parent-identity checks; preserve a private backup", len(p.Content)), "expiresAt": p.Expires.UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("POST /api/settings/apply", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			PreviewID string `json:"previewId"`
		}
		if e := decodeJSON(w, r, &in); e != nil {
			settingsError(w, e)
			return
		}
		path, digest, e := s.applyDocument(in.PreviewID)
		if e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, map[string]any{"path": path, "digest": digest, "backupCreated": true})
	})
}
func (s *settingsStore) listDocuments(cwd string) ([]settingsDocument, []settingsHook, error) {
	if cwd == "" && s.app != nil {
		cwd = s.app.defaultCWD
	}
	root, e := validCWD(cwd)
	if e != nil {
		return nil, nil, e
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, nil, e
	}
	candidates := []struct{ path, kind string }{{filepath.Join(root, "AGENTS.md"), "agents"}, {filepath.Join(root, "CLAUDE.md"), "claude"}, {filepath.Join(root, "MEMORY.md"), "memory"}, {filepath.Join(root, ".claude", "CLAUDE.md"), "claude"}, {filepath.Join(home, ".codex", "AGENTS.md"), "agents"}, {filepath.Join(home, ".claude", "CLAUDE.md"), "claude"}}
	docs := []settingsDocument{}
	for _, c := range candidates {
		doc := settingsDocument{ID: settingsDigest([]byte(c.path)), Path: c.path, Kind: c.kind, Editable: true}
		if e := settingsCheckParents(c.path); e != nil {
			doc.Editable = false
			doc.Reason = "Parent directory missing or symlinked; create it explicitly before editing"
		}
		data, e := settingsRead(c.path, 1<<20)
		if e == nil {
			doc.Exists = true
			doc.Digest = settingsDigest(data)
		} else if os.IsNotExist(e) {
			doc.Digest = settingsDigest(nil)
		} else {
			doc.Editable = false
			doc.Reason = e.Error()
		}
		docs = append(docs, doc)
	}
	hooks := []settingsHook{}
	for _, path := range []string{filepath.Join(home, ".codex", "hooks.json"), filepath.Join(home, ".claude", "settings.json"), filepath.Join(root, ".claude", "settings.json"), filepath.Join(root, ".claude", "settings.local.json")} {
		items, e := s.inspectHooks(path)
		if e == nil {
			hooks = append(hooks, items...)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.docs) > 1024 {
		s.docs = map[string]settingsDocument{}
	}
	for _, doc := range docs {
		s.docs[doc.ID] = doc
	}
	return docs, hooks, nil
}
func (s *settingsStore) previewDocument(kind, id, digest, content string, enabled *bool) (string, *settingsPreview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var path string
	var hook *settingsDisabledHook
	if kind == "hook" {
		if enabled == nil {
			return "", nil, errors.New("hook preview requires enabled")
		}
		h, newContent, e := s.hookContentLocked(id, digest, *enabled)
		if e != nil {
			return "", nil, e
		}
		hook = h
		path = h.Path
		content = string(newContent)
	} else if kind == "document" {
		doc, ok := s.docs[id]
		if !ok || !doc.Editable {
			return "", nil, errors.New("document is not editable in this scope")
		}
		path = doc.Path
	} else {
		return "", nil, errors.New("unsupported preview type")
	}
	if len(content) > 1<<20 {
		return "", nil, errors.New("document exceeds 1 MiB")
	}
	if e := settingsCheckParents(path); e != nil {
		return "", nil, e
	}
	old, e := settingsRead(path, 1<<20)
	if e != nil && !os.IsNotExist(e) {
		return "", nil, e
	}
	if settingsDigest(old) != digest {
		return "", nil, errSettingsConflict
	}
	if strings.Contains(string(old), "<!-- codex-bridge:begin") {
		start := strings.Index(string(old), "<!-- codex-bridge:begin")
		end := strings.Index(string(old)[start:], "<!-- codex-bridge:end -->")
		if end < 0 || !strings.Contains(content, string(old)[start:start+end+len("<!-- codex-bridge:end -->")]) {
			return "", nil, errors.New("preserve the disabled Codex bridge block exactly")
		}
	}
	// A masked readback cannot be safely written over the original value.
	if strings.Contains(content, "[REDACTED]") && s.redact(string(old)) != string(old) {
		return "", nil, errors.New("document contains masked secrets; edit the source through its owning credential tool")
	}
	mode := os.FileMode(0600)
	if f, e := os.Lstat(path); e == nil {
		mode = f.Mode().Perm()
	}
	parents := []settingsParent{}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		info, e := os.Lstat(d)
		if e != nil {
			return "", nil, e
		}
		parents = append(parents, settingsParent{d, info})
		if filepath.Dir(d) == d {
			break
		}
	}
	for key, p := range s.previews {
		if time.Now().After(p.Expires) {
			delete(s.previews, key)
		}
	}
	if len(s.previews) >= 32 {
		return "", nil, errors.New("preview limit reached; apply or wait for expiry")
	}
	p := &settingsPreview{Path: path, ExpectedDigest: digest, Content: []byte(content), Mode: mode, Expires: time.Now().Add(5 * time.Minute), Parents: parents, Hook: hook}
	if enabled != nil {
		p.Enable = *enabled
	}
	key := freshID()
	s.previews[key] = p
	return key, p, nil
}
func (s *settingsStore) applyDocument(id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.previews[id]
	if !ok || time.Now().After(p.Expires) {
		return "", "", errors.New("preview expired or missing")
	}
	delete(s.previews, id)
	for _, parent := range p.Parents {
		info, e := os.Lstat(parent.path)
		if e != nil || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, parent.info) {
			return "", "", errors.New("document parent identity changed")
		}
	}
	old, e := settingsRead(p.Path, 1<<20)
	if e != nil && !os.IsNotExist(e) {
		return "", "", e
	}
	if settingsDigest(old) != p.ExpectedDigest {
		return "", "", errSettingsConflict
	}
	backupDir := filepath.Join(s.dir, "backups")
	if e = settingsPrivateDirectory(backupDir); e != nil {
		return "", "", e
	}
	if e = settingsAtomicWrite(filepath.Join(backupDir, freshID()+".bak"), old); e != nil {
		return "", "", e
	}
	if p.Hook != nil && !p.Enable {
		if e = s.saveDisabledHookLocked(*p.Hook); e != nil {
			return "", "", e
		}
	}
	if e = settingsAtomicWriteMode(p.Path, p.Content, p.Mode); e != nil {
		return "", "", e
	}
	if p.Hook != nil && p.Enable {
		_ = os.Remove(filepath.Join(s.dir, "disabled-hooks", p.Hook.ID+".json"))
	}
	return p.Path, settingsDigest(p.Content), nil
}

// Duplicate JSON keys make an edit ambiguous. Reject at every nesting level.
func settingsUniqueJSON(data []byte) error {
	d := json.NewDecoder(strings.NewReader(string(data)))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return e
					}
					k, ok := key.(string)
					if !ok || seen[k] {
						return errors.New("duplicate JSON key")
					}
					seen[k] = true
					if e = walk(); e != nil {
						return e
					}
				}
			} else if delim == '[' {
				for d.More() {
					if e := walk(); e != nil {
						return e
					}
				}
			} else {
				return errors.New("unexpected delimiter")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("extra JSON")
	}
	return nil
}
func settingsHookGroups(data []byte) (map[string]any, map[string]any, error) {
	if e := settingsUniqueJSON(data); e != nil {
		return nil, nil, e
	}
	var root map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if decoder.Decode(&root) != nil {
		return nil, nil, errors.New("invalid hook JSON")
	}
	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		return nil, nil, errors.New("no supported hooks object")
	}
	return root, hooks, nil
}
func (s *settingsStore) inspectHooks(path string) ([]settingsHook, error) {
	data, e := settingsRead(path, 1<<20)
	if e != nil {
		return nil, e
	}
	_, events, e := settingsHookGroups(data)
	if e != nil {
		return nil, e
	}
	out := []settingsHook{}
	for event, value := range events {
		groups, _ := value.([]any)
		for gi, g := range groups {
			group, _ := g.(map[string]any)
			handlers, _ := group["hooks"].([]any)
			for hi, h := range handlers {
				raw, _ := json.Marshal(h)
				id := settingsDigest([]byte(path + "\x00" + event + "\x00" + fmt.Sprint(gi) + "\x00" + string(raw)))
				_ = hi
				out = append(out, settingsHook{ID: id, Path: path, Event: event, Label: "Configured " + event + " handler", Enabled: true, Trust: "unknown", Digest: settingsDigest(data), Reason: "Saved configuration; actual native trust and execution require verification"})
			}
		}
	}
	entries, _ := os.ReadDir(filepath.Join(s.dir, "disabled-hooks"))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, e := settingsRead(filepath.Join(s.dir, "disabled-hooks", entry.Name()), 1<<20)
		if e != nil {
			continue
		}
		var h settingsDisabledHook
		if json.Unmarshal(raw, &h) != nil || h.Path != path {
			continue
		}
		out = append(out, settingsHook{ID: h.ID, Path: path, Event: h.Event, Label: "Disabled " + h.Event + " handler", Enabled: false, Trust: "review_required", Digest: settingsDigest(data), Reason: "Enable through reviewed preview; native trust remains separate"})
	}
	return out, nil
}
func (s *settingsStore) hookContentLocked(id, digest string, enable bool) (*settingsDisabledHook, []byte, error) {
	home, _ := os.UserHomeDir()
	paths := []string{filepath.Join(home, ".codex", "hooks.json"), filepath.Join(home, ".claude", "settings.json")}
	for _, d := range s.docs {
		if d.Kind == "claude" {
			paths = append(paths, filepath.Join(filepath.Dir(d.Path), ".claude", "settings.json"), filepath.Join(filepath.Dir(d.Path), ".claude", "settings.local.json"))
		}
	}
	var disabled settingsDisabledHook
	if enable {
		if !validSettingsDigest(id) {
			return nil, nil, errors.New("invalid hook identifier")
		}
		raw, e := settingsRead(filepath.Join(s.dir, "disabled-hooks", id+".json"), 1<<20)
		if e != nil || !validSettingsDigest(id) || json.Unmarshal(raw, &disabled) != nil {
			return nil, nil, errors.New("disabled hook not available")
		}
		paths = []string{disabled.Path}
	}
	for _, path := range paths {
		data, e := settingsRead(path, 1<<20)
		if e != nil || settingsDigest(data) != digest {
			continue
		}
		root, events, e := settingsHookGroups(data)
		if e != nil {
			continue
		}
		for event, value := range events {
			groups, _ := value.([]any)
			for gi, g := range groups {
				group, _ := g.(map[string]any)
				handlers, _ := group["hooks"].([]any)
				if enable {
					if disabled.Event != event || disabled.Group != gi {
						continue
					}
					if disabled.Digest != digest {
						return nil, nil, errSettingsConflict
					}
					var h any
					decoder := json.NewDecoder(strings.NewReader(string(disabled.Handler)))
					decoder.UseNumber()
					if decoder.Decode(&h) != nil {
						return nil, nil, errors.New("invalid disabled hook")
					}
					index := disabled.Index
					if index > len(handlers) {
						return nil, nil, errSettingsConflict
					}
					handlers = append(handlers, nil)
					copy(handlers[index+1:], handlers[index:])
					handlers[index] = h
					group["hooks"] = handlers
					out, _ := json.MarshalIndent(root, "", "  ")
					return &disabled, append(out, '\n'), nil
				}
				for hi, h := range handlers {
					raw, _ := json.Marshal(h)
					key := settingsDigest([]byte(path + "\x00" + event + "\x00" + fmt.Sprint(gi) + "\x00" + string(raw)))
					if key != id {
						continue
					}
					handlers = append(handlers[:hi], handlers[hi+1:]...)
					group["hooks"] = handlers
					out, _ := json.MarshalIndent(root, "", "  ")
					out = append(out, '\n')
					disabled = settingsDisabledHook{ID: id, Path: path, Event: event, Group: gi, Index: hi, Handler: raw, Digest: settingsDigest(out)}
					return &disabled, out, nil
				}
			}
		}
	}
	return nil, nil, errors.New("hook changed or is outside the inspected supported configuration")
}
func validSettingsDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func (s *settingsStore) saveDisabledHookLocked(h settingsDisabledHook) error {
	dir := filepath.Join(s.dir, "disabled-hooks")
	if e := settingsPrivateDirectory(dir); e != nil {
		return e
	}
	data, _ := json.Marshal(h)
	return settingsAtomicWrite(filepath.Join(dir, h.ID+".json"), data)
}
