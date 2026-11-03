package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type settingsHealth struct {
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Storage string `json:"storage,omitempty"`
}
type settingsProfile struct {
	ID            string         `json:"id"`
	Generation    string         `json:"generation"`
	Name          string         `json:"name"`
	Provider      string         `json:"provider"`
	Kind          string         `json:"kind"`
	Allowed       bool           `json:"allowed"`
	Rotate        bool           `json:"rotate"`
	Auth          settingsHealth `json:"auth"`
	Harness       settingsHealth `json:"harness"`
	APIKeyPresent bool           `json:"apiKeyPresent"`
}
type settingsDefaults struct {
	Provider       string `json:"provider"`
	ProfileID      string `json:"profileId"`
	Model          string `json:"model"`
	Effort         string `json:"effort"`
	ServiceTier    string `json:"serviceTier"`
	Permissions    string `json:"permissions"`
	ApprovalPolicy string `json:"approvalPolicy"`
	Harness        string `json:"harness"`
}
type settingsEnv struct {
	ID        string `json:"id"`
	ProfileID string `json:"profileId"`
	Name      string `json:"name"`
	Present   bool   `json:"present"`
	Enabled   bool   `json:"enabled"`
	Sensitive *bool  `json:"sensitive,omitempty"`
	Value     string `json:"value,omitempty"`
}

func (e settingsEnv) isSensitive() bool { return e.Sensitive == nil || *e.Sensitive }
func settingsBool(value bool) *bool     { return &value }
func settingsCredentialName(name string) bool {
	upper := strings.ToUpper(name)
	for _, hint := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "CREDENTIAL", "PRIVATE_KEY", "AUTH", "COOKIE", "DATABASE_URL", "CONNECTION_STRING"} {
		if strings.Contains(upper, hint) {
			return true
		}
	}
	return upper == "DSN" || strings.HasSuffix(upper, "_DSN")
}

type goodqaChoices struct {
	Desktop   bool `json:"desktop"`
	Browser   bool `json:"browser"`
	Remote    bool `json:"remote"`
	Knowledge bool `json:"knowledge"`
	Hive      bool `json:"hive"`
	Tickets   bool `json:"tickets"`
	Projects  bool `json:"projects"`
	Decisions bool `json:"decisions"`
}
type settingsGoodQA struct {
	Generation        string        `json:"generation"`
	Enabled           bool          `json:"enabled"`
	Endpoint          string        `json:"endpoint"`
	CredentialPresent bool          `json:"credentialPresent"`
	Capabilities      goodqaChoices `json:"capabilities"`
	AllowedTools      []string      `json:"allowedTools"`
}
type consoleSettings struct {
	Schema       int               `json:"schema"`
	Profiles     []settingsProfile `json:"profiles"`
	Defaults     settingsDefaults  `json:"defaults"`
	Cascade      []policyStep      `json:"cascade"`
	ReviewLadder []policyStep      `json:"reviewLadder"`
	Environment  []settingsEnv     `json:"environment"`
	GoodQA       settingsGoodQA    `json:"goodqa"`
}
type settingsDisk struct {
	Revision uint64            `json:"revision"`
	Settings consoleSettings   `json:"settings"`
	Refs     map[string]string `json:"refs"`
	Retired  map[string]bool   `json:"retired"`
	Pending  map[string]string `json:"pending"`
}
type settingsStore struct {
	mu         sync.Mutex
	disk       settingsDisk
	dir        string
	vault      credentialVault
	app        *app
	knownMu    sync.RWMutex
	known      map[string]bool
	inFlight   map[string]bool
	login      map[string]*settingsLogin
	previews   map[string]*settingsPreview
	docs       map[string]settingsDocument
	write      func(string, []byte) error
	lastDigest string
	uncertain  bool
}

var settingsStores sync.Map
var errSettingsConflict = errors.New("settings changed; reload before applying this operation")
var errSettingsDurability = errors.New("settings durability barrier failed")
var settingsEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func init() { settingsInit = initConsoleSettings; settingsRegister = registerConsoleSettings }
func initConsoleSettings(a *app) error {
	s, e := openSettings(a.dataDir, newCredentialVault())
	if e != nil {
		return e
	}
	s.app = a
	settingsStores.Store(a, s)
	a.runtime = s.runtime
	a.resolvePolicy = s.policy
	a.redact = s.redact
	a.newRedactor = s.stream
	return nil
}
func openSettings(dir string, vault credentialVault) (*settingsStore, error) {
	if err := settingsPrivateDirectory(dir); err != nil {
		return nil, err
	}
	s := &settingsStore{dir: dir, vault: vault, known: map[string]bool{}, inFlight: map[string]bool{}, login: map[string]*settingsLogin{}, previews: map[string]*settingsPreview{}, docs: map[string]settingsDocument{}, write: settingsAtomicWrite}
	s.disk = settingsDisk{Revision: 1, Settings: defaultSettings(), Refs: map[string]string{}, Retired: map[string]bool{}, Pending: map[string]string{}}
	path := filepath.Join(dir, "settings.json")
	data, e := settingsRead(path, 1<<20)
	s.lastDigest = settingsDigest(nil)
	if e == nil {
		s.lastDigest = settingsDigest(data)
		if e = settingsDecode(data, &s.disk); e != nil {
			return nil, errors.New("settings metadata is invalid; restore a private backup")
		}
		if s.disk.Revision == 0 || s.disk.Refs == nil || s.disk.Pending == nil || s.disk.Retired == nil {
			return nil, errors.New("settings metadata has invalid state")
		}
		if e = s.validate(s.disk.Settings, false); e != nil {
			return nil, e
		}
	}
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	// Reconcile only IDs durably recorded by this app, never enumerate a vault.
	s.cleanupLocked()
	return s, nil
}
func defaultSettings() consoleSettings {
	return consoleSettings{Schema: 1, Profiles: []settingsProfile{{ID: "global-codex", Generation: "global-codex-v1", Name: "Existing Codex sign-in", Provider: "codex", Kind: "global", Allowed: true}, {ID: "global-claude", Generation: "global-claude-v1", Name: "Existing Claude sign-in", Provider: "claude", Kind: "global", Allowed: true}}, Defaults: settingsDefaults{Provider: "codex", ProfileID: "global-codex", Model: "gpt-6.1-sol", Effort: "high", ServiceTier: "normal", Permissions: "full_access", ApprovalPolicy: "never", Harness: "agent_harness"}, Cascade: []policyStep{}, ReviewLadder: []policyStep{}, Environment: []settingsEnv{}, GoodQA: settingsGoodQA{Generation: freshID()}}
}
func settingsDecode(data []byte, out any) error {
	if e := settingsUniqueJSON(data); e != nil {
		return e
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return errors.New("extra data")
	}
	return nil
}
func settingsPrivateDirectory(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("settings directory must be absolute")
	}
	for path := dir; ; path = filepath.Dir(path) {
		if f, e := os.Lstat(path); e == nil {
			if !f.IsDir() || f.Mode()&os.ModeSymlink != 0 {
				return errors.New("private settings path contains a symlink or non-directory")
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return errors.New("private settings directory unavailable")
	}
	for path := dir; ; path = filepath.Dir(path) {
		f, e := os.Lstat(path)
		if e != nil || !f.IsDir() || f.Mode()&os.ModeSymlink != 0 {
			return errors.New("settings parent must be a real directory")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	return os.Chmod(dir, 0700)
}
func settingsRead(path string, limit int64) ([]byte, error) {
	if e := settingsCheckParents(path); e != nil {
		return nil, e
	}
	f, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0 || f.Size() > limit {
		return nil, errors.New("settings target must be a bounded regular file")
	}
	h, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer h.Close()
	f2, e := h.Stat()
	if e != nil || !os.SameFile(f, f2) {
		return nil, errors.New("settings target changed")
	}
	data, e := io.ReadAll(io.LimitReader(h, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > limit {
		return nil, errors.New("settings file grew beyond its bound")
	}
	return data, nil
}
func settingsAtomicWrite(path string, data []byte) error {
	return settingsAtomicWriteMode(path, data, 0600)
}
func settingsAtomicWriteMode(path string, data []byte, mode os.FileMode) error {
	if e := settingsCheckParents(path); e != nil {
		return e
	}
	if f, e := os.Lstat(path); e == nil && (!f.Mode().IsRegular() || f.Mode()&os.ModeSymlink != 0) {
		return errors.New("unsafe settings target")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if e != nil {
		return errors.New("settings temporary file unavailable")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode.Perm()); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = settingsSyncFile(f)
	}
	ce := f.Close()
	if e != nil {
		return errors.New("settings write failed")
	}
	if ce != nil {
		return errors.New("settings close failed")
	}
	if e = settingsCheckParents(path); e != nil {
		return e
	}
	if e = settingsReplace(name, path); e != nil {
		return errors.Join(errSettingsDurability, errors.New("settings atomic replacement outcome requires reconciliation"))
	}
	if e = settingsSyncParent(filepath.Dir(path)); e != nil {
		return errors.Join(errSettingsDurability, e)
	}
	return nil
}
func settingsCheckParents(path string) error {
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		f, e := os.Lstat(d)
		if os.IsNotExist(e) {
			return e
		}
		if e != nil || !f.IsDir() || f.Mode()&os.ModeSymlink != 0 {
			return errors.New("settings parent changed or contains symlink")
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return nil
}
func (s *settingsStore) persistLocked() error {
	if s.uncertain {
		return errors.New("settings transaction outcome is unknown; restart to reconcile durable metadata before further changes")
	}
	data, e := json.MarshalIndent(s.disk, "", "  ")
	if e != nil {
		return e
	}
	if len(data) > 1<<20 {
		return errors.New("settings metadata exceeds 1 MiB")
	}
	path := filepath.Join(s.dir, "settings.json")
	unlock, e := settingsLock(filepath.Join(s.dir, ".settings-write.guard"))
	if e != nil {
		return e
	}
	defer unlock()
	current, e := settingsRead(path, 1<<20)
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if settingsDigest(current) != s.lastDigest {
		return errSettingsConflict
	}
	data = append(data, '\n')
	if e = s.write(path, data); e == nil {
		s.lastDigest = settingsDigest(data)
		return nil
	}
	if errors.Is(e, errSettingsDurability) {
		s.uncertain = true
		return errors.New("metadata is visible but durability is unknown; retained both credentials until restart reconciliation")
	}
	actual, readErr := settingsRead(path, 1<<20)
	if readErr == nil && settingsDigest(actual) == settingsDigest(data) {
		s.lastDigest = settingsDigest(data)
		return nil
	}
	if (readErr == nil || os.IsNotExist(readErr)) && settingsDigest(actual) == s.lastDigest {
		return e
	}
	s.uncertain = true
	return errors.New("settings commit outcome unknown; retained credentials and stopped writes until restart reconciliation")
}
func (s *settingsStore) profileLocked(id string) (settingsProfile, bool) {
	for _, p := range s.disk.Settings.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return settingsProfile{}, false
}
func secretSlot(profile, name string) string { return profile + ":" + name }
func (s *settingsStore) remember(value string) {
	s.knownMu.Lock()
	s.known[value] = true
	s.knownMu.Unlock()
}
func (s *settingsStore) secretValues() []string {
	s.knownMu.RLock()
	defer s.knownMu.RUnlock()
	v := []string{}
	for x := range s.known {
		v = append(v, x)
	}
	return v
}
func (s *settingsStore) stream() streamRedactor { return makeSecretStream(s.secretValues()) }
func (s *settingsStore) redact(value string) string {
	r := makeSecretStream(s.secretValues())
	r.pending = value
	return r.Flush()
}

func (s *settingsStore) validate(value consoleSettings, assign bool) error {
	if value.Schema != 1 || len(value.Profiles) > 16 || len(value.Environment) > 64 || len(value.Cascade) > 8 || len(value.ReviewLadder) > 8 {
		return errors.New("unsupported settings schema or too many entries")
	}
	seen := map[string]bool{}
	for _, p := range value.Profiles {
		if p.ID == "" && assign {
			continue
		}
		if seen[p.ID] || p.ID == "" || p.Generation == "" || len(p.Name) > 120 || len(p.Name) == 0 {
			return errors.New("invalid or duplicate profile")
		}
		seen[p.ID] = true
		if p.Provider != "codex" && p.Provider != "claude" {
			return errors.New("unknown profile provider")
		}
		if p.Kind != "global" && p.Kind != "api_key" && !(p.Provider == "codex" && p.Kind == "device") && !(p.Provider == "claude" && p.Kind == "subscription") {
			return errors.New("unsupported or unsafe profile authentication type")
		}
		if p.Rotate {
			return errors.New("automatic account rotation is unavailable until actual profile harness readiness is verified; select profiles explicitly")
		}
	}
	d := value.Defaults
	if d.Provider != "codex" && d.Provider != "claude" {
		return errors.New("unknown default provider")
	}
	if !seen[d.ProfileID] {
		return errors.New("default profile must exist")
	}
	for _, p := range value.Profiles {
		if p.ID == d.ProfileID && p.Provider != d.Provider {
			return errors.New("default provider and profile must match")
		}
	}
	if d.Provider == "claude" && d.ServiceTier == "priority" {
		return errors.New("Claude priority tier is unsupported by the installed adapter; use normal")
	}
	if d.Permissions != "full_access" && d.Permissions != "workspace_write" && d.Permissions != "read_only" {
		return errors.New("unsupported permission mode")
	}
	if d.ApprovalPolicy != "never" && d.ApprovalPolicy != "on_request" {
		return errors.New("unsupported approval policy")
	}
	if d.ServiceTier != "normal" && d.ServiceTier != "priority" {
		return errors.New("unsupported service tier")
	}
	if d.Harness != "agent_harness" && d.Harness != "provider_default" {
		return errors.New("unsupported harness")
	}
	if len(d.Model) > 120 || strings.ContainsAny(d.Model, "\x00\r\n") || !oneOf(d.Effort, "", "low", "medium", "high", "xhigh", "max") {
		return errors.New("invalid model or reasoning effort")
	}
	for _, stages := range [][]policyStep{value.Cascade, value.ReviewLadder} {
		for _, stage := range stages {
			if !seen[stage.ProfileID] || len(stage.Model) > 120 || !oneOf(stage.Provider, "codex", "claude") || !oneOf(stage.Effort, "", "low", "medium", "high", "xhigh", "max") {
				return errors.New("invalid ladder stage")
			}
			for _, p := range value.Profiles {
				if p.ID == stage.ProfileID && p.Provider != stage.Provider {
					return errors.New("ladder profile provider mismatch")
				}
			}
		}
	}
	for _, e := range value.Environment {
		if !seen[e.ProfileID] || !safeEnvName(e.Name) {
			return errors.New("environment name is reserved, invalid, or profile missing")
		}
		if e.isSensitive() {
			if e.Value != "" {
				return errors.New("sensitive environment values are write-only; save through the credential field")
			}
		} else {
			if settingsCredentialName(e.Name) {
				return errors.New("credential-like environment names must remain Sensitive and use the OS vault")
			}
			if len(e.Value) > 8192 || strings.ContainsRune(e.Value, '\x00') {
				return errors.New("plain environment value must be bounded and contain no NUL")
			}
		}
	}
	if e := validateGoodQAEndpoint(value.GoodQA.Endpoint, value.GoodQA.Enabled); e != nil {
		return e
	}
	if len(value.GoodQA.AllowedTools) > 128 {
		return errors.New("GoodQA allowlist exceeds 128 explicit tool names")
	}
	toolNames := map[string]bool{}
	for _, name := range value.GoodQA.AllowedTools {
		if !goodqaToolName.MatchString(name) || toolNames[name] {
			return errors.New("invalid or duplicate GoodQA selected tool")
		}
		toolNames[name] = true
	}
	return nil
}
func oneOf(value string, choices ...string) bool {
	for _, x := range choices {
		if x == value {
			return true
		}
	}
	return false
}
func safeEnvName(name string) bool {
	if !settingsEnvName.MatchString(name) {
		return false
	}
	for _, p := range []string{"XDG_", "LD_", "DYLD_", "CODEX_", "CLAUDE_", "OPENAI_", "ANTHROPIC_", "HARNESS_", "GIT_CONFIG"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	if oneOf(name, "HOME", "PATH", "USERPROFILE", "NODE_OPTIONS", "PYTHONPATH", "BASH_ENV", "ENV", "SHELL", "COMSPEC") {
		return false
	}
	return true
}
func (s *settingsStore) save(expected uint64, next consoleSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.disk.Revision {
		return errSettingsConflict
	}
	before := s.disk
	next.Schema = 1
	for i := range next.Profiles {
		p := &next.Profiles[i]
		if p.ID == "" {
			p.ID = freshID()
			p.Generation = freshID()
			if p.Kind == "global" {
				return errors.New("new global profiles are unsupported")
			}
		} else {
			old, ok := s.profileLocked(p.ID)
			if !ok || old.Generation != p.Generation || old.Provider != p.Provider || old.Kind != p.Kind {
				return errors.New("profile identity changed or was retired")
			}
		}
		p.Auth = settingsHealth{}
		p.Harness = settingsHealth{}
		p.APIKeyPresent = false
	}
	for _, old := range before.Settings.Profiles {
		if old.Kind == "global" {
			found := false
			for _, p := range next.Profiles {
				if p.ID == old.ID {
					found = true
				}
			}
			if !found {
				return errors.New("existing default CLI profiles cannot be removed")
			}
		}
	}
	for i := range next.Environment {
		if next.Environment[i].ID == "" {
			next.Environment[i].ID = freshID()
		}
		next.Environment[i].Present = false
	}
	seenEnv := map[string]bool{}
	for _, row := range next.Environment {
		key := secretSlot(row.ProfileID, row.Name)
		if seenEnv[key] {
			return errors.New("duplicate environment variable for profile")
		}
		seenEnv[key] = true
	}
	if next.GoodQA.Endpoint != before.Settings.GoodQA.Endpoint {
		next.GoodQA.Generation = freshID()
		next.GoodQA.AllowedTools = []string{}
	} else {
		next.GoodQA.Generation = before.Settings.GoodQA.Generation
	}
	next.GoodQA.CredentialPresent = false
	if e := s.validate(next, false); e != nil {
		return e
	}
	if len(next.GoodQA.AllowedTools) > 0 {
		catalog, e := s.goodqaCatalogLocked()
		if e != nil {
			return e
		}
		known := map[string]bool{}
		for _, tool := range catalog.Tools {
			known[tool.Name] = true
		}
		for _, name := range next.GoodQA.AllowedTools {
			if !known[name] {
				return errors.New("GoodQA tool was not discovered for current endpoint and credential")
			}
		}
	}
	// Clone maps before changing them so a failed write truly preserves memory.
	s.disk.Refs = cloneSettingsMap(before.Refs)
	s.disk.Retired = map[string]bool{}
	for k, v := range before.Retired {
		s.disk.Retired[k] = v
	}
	s.disk.Pending = cloneSettingsMap(before.Pending)
	for _, old := range before.Settings.Profiles {
		found := false
		for _, p := range next.Profiles {
			if p.ID == old.ID {
				found = true
			}
		}
		if !found {
			s.disk.Retired[old.ID] = true
			for slot, id := range s.disk.Refs {
				if strings.HasPrefix(slot, old.ID+":") {
					delete(s.disk.Refs, slot)
					s.disk.Pending[id] = "retired"
				}
			}
		}
	}
	for slot, id := range s.disk.Refs {
		if profile, name, ok := strings.Cut(slot, ":"); ok && profile != "goodqa" && name != "api_key" {
			present := false
			for _, row := range next.Environment {
				if row.ProfileID == profile && row.Name == name && row.isSensitive() {
					present = true
					break
				}
			}
			if !present {
				delete(s.disk.Refs, slot)
				s.disk.Pending[id] = "retired"
			}
		}
		if strings.HasPrefix(slot, "goodqa:") && next.GoodQA.Generation != before.Settings.GoodQA.Generation {
			delete(s.disk.Refs, slot)
			s.disk.Pending[id] = "retired"
		}
	}
	s.disk.Settings = next
	s.disk.Revision++
	if e := s.persistLocked(); e != nil {
		s.disk = before
		return e
	}
	for id, task := range s.login {
		if p, ok := s.profileLocked(task.ProfileID); !ok || p.Generation != task.Generation {
			task.cancel()
			task.State = "cancelled"
			task.Reason = "profile removed"
			delete(s.login, id)
		}
	}
	s.cleanupLocked()
	return nil
}
func cloneSettingsMap(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
func (s *settingsStore) cleanupLocked() {
	if s.uncertain {
		return
	}
	for id := range s.disk.Pending {
		if s.inFlight[id] {
			continue
		}
		referenced := false
		for _, ref := range s.disk.Refs {
			if ref == id {
				referenced = true
				break
			}
		}
		if referenced {
			delete(s.disk.Pending, id)
			continue
		}
		// An OS advisory lock spans the complete native write and metadata
		// commit, including another console process's startup reconciliation.
		release, e := s.transactionLock(id)
		if e != nil {
			continue
		}
		guard, e := settingsLock(filepath.Join(s.dir, ".settings-write.guard"))
		if e != nil {
			release()
			continue
		}
		path := filepath.Join(s.dir, "settings.json")
		data, e := settingsRead(path, 1<<20)
		var durable settingsDisk
		if e != nil || settingsDecode(data, &durable) != nil || durable.Pending[id] == "" {
			guard()
			release()
			continue
		}
		for _, ref := range durable.Refs {
			if ref == id {
				referenced = true
				break
			}
		}
		if referenced {
			guard()
			release()
			continue
		}
		// A readable rename is insufficient after a previous uncertain write.
		// Reestablish both file and namespace durability before retiring a key.
		if e = settingsDurableReadback(path); e != nil {
			s.uncertain = true
			guard()
			release()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e = s.vault.Delete(ctx, id)
		cancel()
		guard()
		release()
		if e == nil {
			delete(s.disk.Pending, id)
		}
	}
}
func (s *settingsStore) writeSecret(ctx context.Context, revision uint64, profile, generation, name, value string, remove bool) error {
	if !remove && !validSecret(value) {
		return errors.New("API keys and sensitive values require 8–8192 bytes without NUL or line breaks; save short non-secret environment flags with Sensitive turned off")
	}
	s.mu.Lock()
	if revision != s.disk.Revision {
		s.mu.Unlock()
		return errSettingsConflict
	}
	if e := s.secretTargetLocked(profile, generation, name); e != nil {
		s.mu.Unlock()
		return e
	}
	slot := secretSlot(profile, name)
	old := s.disk.Refs[slot]
	id := freshID()
	var release func()
	if remove {
		id = ""
	} else {
		var e error
		release, e = s.transactionLock(id)
		if e != nil {
			s.mu.Unlock()
			return e
		}
		defer func() {
			if release != nil {
				release()
			}
		}()
		s.disk.Pending[id] = "staged"
		if e := s.persistLocked(); e != nil {
			delete(s.disk.Pending, id)
			s.mu.Unlock()
			return e
		}
		s.inFlight[id] = true
	}
	s.mu.Unlock()
	if !remove {
		if e := s.vault.Put(ctx, id, value); e != nil {
			s.mu.Lock()
			delete(s.inFlight, id)
			release()
			release = nil
			s.cleanupLocked()
			_ = s.persistLocked()
			s.mu.Unlock()
			return errVault
		}
		s.remember(value)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, id)
	if revision != s.disk.Revision || s.secretTargetLocked(profile, generation, name) != nil {
		if id != "" {
			release()
			release = nil
			s.cleanupLocked()
			_ = s.persistLocked()
		}
		return errSettingsConflict
	}
	beforeRefs := cloneSettingsMap(s.disk.Refs)
	beforePending := cloneSettingsMap(s.disk.Pending)
	beforeRevision := s.disk.Revision
	if id == "" {
		delete(s.disk.Refs, slot)
	} else {
		s.disk.Refs[slot] = id
	}
	if old != "" {
		s.disk.Pending[old] = "retired"
	}
	s.disk.Revision++
	if e := s.persistLocked(); e != nil {
		s.disk.Refs = beforeRefs
		s.disk.Revision = beforeRevision
		s.disk.Pending = beforePending
		return errors.New("secret commit failed; old reference preserved, staged item retained for safe cleanup")
	}
	delete(s.disk.Pending, id)
	if release != nil {
		release()
		release = nil
	}
	if old != "" {
		s.disk.Pending[old] = "retired"
	}
	_ = s.persistLocked()
	s.cleanupLocked()
	_ = s.persistLocked()
	return nil
}

func (s *settingsStore) transactionLock(id string) (func(), error) {
	if !validVaultItem(id) {
		return nil, errors.New("invalid transaction identifier")
	}
	dir := filepath.Join(s.dir, "credential-transactions")
	if e := settingsPrivateDirectory(dir); e != nil {
		return nil, e
	}
	return settingsLock(filepath.Join(dir, id+".lock"))
}
func settingsDurableReadback(path string) error {
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = settingsSyncFile(f); e != nil {
		return e
	}
	return settingsSyncParent(filepath.Dir(path))
}
func (s *settingsStore) secretTargetLocked(profile, generation, name string) error {
	if profile == "goodqa" {
		if generation != s.disk.Settings.GoodQA.Generation || name != "credential" {
			return errSettingsConflict
		}
		return nil
	}
	p, ok := s.profileLocked(profile)
	if !ok || p.Generation != generation {
		return errSettingsConflict
	}
	if name == "api_key" {
		if p.Kind != "api_key" {
			return errors.New("profile is not an API-key profile")
		}
		return nil
	}
	if !safeEnvName(name) {
		return errors.New("reserved environment name")
	}
	for _, e := range s.disk.Settings.Environment {
		if e.ProfileID == profile && e.Name == name {
			if !e.isSensitive() {
				return errors.New("this environment row is plain; save its value through settings instead of the credential endpoint")
			}
			return nil
		}
	}
	return errors.New("save the environment row before its secret")
}
func (s *settingsStore) readSecret(ctx context.Context, id string) (string, error) {
	v, e := s.vault.Get(ctx, id)
	if e != nil {
		return "", errVault
	}
	if !validSecret(v) {
		return "", errVault
	}
	s.remember(v)
	return v, nil
}
func (s *settingsStore) envelope() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, _ := json.Marshal(s.disk.Settings)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	profiles := []settingsProfile{}
	for _, p := range s.disk.Settings.Profiles {
		p.APIKeyPresent = s.disk.Refs[secretSlot(p.ID, "api_key")] != ""
		p.Auth = settingsHealth{State: "unknown", Reason: "Use official sign-in or inspect supported usage; no credentials are read for this view", Storage: "provider managed"}
		p.Harness = settingsHealth{State: "unverified", Reason: "Actual role and hook execution has not been verified for this profile"}
		for _, task := range s.login {
			if task.ProfileID == p.ID && task.Generation == p.Generation && task.State == "complete" {
				p.Auth.State = "signed_in"
				p.Auth.Reason = "Official login and isolated supported auth status confirmed sign-in; entitlement and quota remain separate"
			}
		}
		if p.Kind == "api_key" {
			p.Auth.Storage = s.vault.Name()
			if !p.APIKeyPresent {
				p.Auth.State = "signed_out"
				p.Auth.Reason = "API key not saved"
			}
		}
		profiles = append(profiles, p)
	}
	out["profiles"] = profiles
	env := append([]settingsEnv{}, s.disk.Settings.Environment...)
	for i := range env {
		sensitive := env[i].isSensitive()
		env[i].Sensitive = settingsBool(sensitive)
		env[i].Present = !sensitive || s.disk.Refs[secretSlot(env[i].ProfileID, env[i].Name)] != ""
		if sensitive {
			env[i].Value = ""
		}
	}
	out["environment"] = env
	good := s.disk.Settings.GoodQA
	good.CredentialPresent = s.disk.Refs["goodqa:credential"] != ""
	out["goodqa"] = good
	out["revision"] = s.disk.Revision
	out["effectiveReviewLadder"] = s.effectiveReviewStagesLocked(s.disk.Settings.Defaults.Provider, s.disk.Settings.Defaults.ProfileID)
	reason := ""
	if e := s.vault.Available(); e != nil {
		reason = e.Error()
	}
	out["vault"] = map[string]any{"available": reason == "", "backend": s.vault.Name(), "reason": reason, "cleanupPending": len(s.disk.Pending)}
	out["capabilities"] = []map[string]any{{"name": "global_toml_mutation", "available": false, "reason": "A comment-preserving TOML editor is not installed; app defaults remain effective"}, {"name": "account_rotation", "available": false, "reason": "Requires real per-profile harness readiness and explicit quota-safe dispatch"}, {"name": "claude_console_oauth_profiles", "available": false, "reason": "Console sign-in without API key uses shared external storage"}}
	return out
}
func registerConsoleSettings(mux *http.ServeMux, a *app) {
	value, ok := settingsStores.Load(a)
	if !ok {
		return
	}
	s := value.(*settingsStore)
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.envelope()) })
	mux.HandleFunc("POST /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ExpectedRevision uint64          `json:"expectedRevision"`
			Settings         json.RawMessage `json:"settings"`
		}
		if e := decodeJSON(w, r, &in); e != nil {
			settingsError(w, e)
			return
		}
		var fields map[string]json.RawMessage
		if settingsUniqueJSON(in.Settings) != nil || json.Unmarshal(in.Settings, &fields) != nil {
			settingsError(w, errors.New("invalid settings"))
			return
		}
		for _, key := range []string{"revision", "vault", "capabilities", "effectiveReviewLadder"} {
			delete(fields, key)
		}
		data, _ := json.Marshal(fields)
		var next consoleSettings
		if e := settingsDecode(data, &next); e != nil {
			settingsError(w, errors.New("invalid settings fields"))
			return
		}
		if e := s.save(in.ExpectedRevision, next); e != nil {
			settingsError(w, e)
			return
		}
		writeJSON(w, 200, s.envelope())
	})
	mux.HandleFunc("POST /api/settings/secrets", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ExpectedRevision  uint64 `json:"expectedRevision"`
			ProfileID         string `json:"profileId"`
			ProfileGeneration string `json:"profileGeneration"`
			Name              string `json:"name"`
			Value             string `json:"value"`
			Remove            bool   `json:"remove"`
		}
		if e := decodeJSON(w, r, &in); e != nil {
			settingsError(w, e)
			return
		}
		if e := s.writeSecret(r.Context(), in.ExpectedRevision, in.ProfileID, in.ProfileGeneration, in.Name, in.Value, in.Remove); e != nil {
			settingsError(w, e)
			return
		}
		s.mu.Lock()
		rev := s.disk.Revision
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"present": !in.Remove, "revision": rev})
	})
	s.registerProfileRoutes(mux)
	s.registerDocumentRoutes(mux)
	s.registerGoodQARoutes(mux)
}
func settingsError(w http.ResponseWriter, e error) {
	status := 400
	if errors.Is(e, errSettingsConflict) {
		status = 409
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": "settings_failed", "message": publicError(e)}})
}
func settingsDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func settingsRevision(rev uint64) string { return strconv.FormatUint(rev, 10) }
