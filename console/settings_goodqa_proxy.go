package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const goodqaFrameLimit = 1 << 20

type goodqaTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}
type goodqaCatalog struct {
	Generation    string       `json:"generation"`
	Endpoint      string       `json:"endpoint"`
	CredentialRef string       `json:"credentialRef"`
	Tools         []goodqaTool `json:"tools"`
}
type goodqaProxySnapshot struct {
	Schema            int      `json:"schema"`
	DataDir           string   `json:"dataDir"`
	Revision          uint64   `json:"revision"`
	ProfileID         string   `json:"profileId"`
	ProfileGeneration string   `json:"profileGeneration"`
	Generation        string   `json:"generation"`
	Endpoint          string   `json:"endpoint"`
	CredentialRef     string   `json:"credentialRef"`
	AllowedTools      []string `json:"allowedTools"`
}

var goodqaToolName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func init() { settingsHelperMain = runSettingsHelper }
func runSettingsHelper(args []string, in io.Reader, out, diagnostics io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "--goodqa-proxy" {
		return false, nil
	}
	flags := flag.NewFlagSet("goodqa-proxy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "private admitted snapshot")
	digest := flags.String("sha256", "", "snapshot digest")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return true, errors.New("invalid GoodQA helper arguments")
	}
	snapshot, e := loadGoodQASnapshot(*path, *digest)
	if e != nil {
		return true, e
	}
	if e = baselineAdmitted(snapshot.DataDir); e != nil {
		return true, e
	}
	return true, serveGoodQAProxy(context.Background(), snapshot, newCredentialVault(), in, out, diagnostics)
}
func loadGoodQASnapshot(path, digest string) (goodqaProxySnapshot, error) {
	var snapshot goodqaProxySnapshot
	if !filepath.IsAbs(path) || !validSettingsDigest(digest) {
		return snapshot, errors.New("invalid GoodQA snapshot reference")
	}
	data, e := settingsRead(path, 65536)
	if e != nil || settingsDigest(data) != digest || settingsDecode(data, &snapshot) != nil {
		return snapshot, errors.New("GoodQA snapshot changed or is invalid")
	}
	if snapshot.Schema != 1 || snapshot.Revision == 0 || !filepath.IsAbs(snapshot.DataDir) || snapshot.ProfileID == "" || snapshot.ProfileGeneration == "" || snapshot.Generation == "" || len(snapshot.AllowedTools) == 0 || len(snapshot.AllowedTools) > 128 {
		return snapshot, errors.New("GoodQA snapshot authority is incomplete")
	}
	if e = validateGoodQAEndpoint(snapshot.Endpoint, true); e != nil {
		return snapshot, e
	}
	if snapshot.CredentialRef != "" && !validVaultItem(snapshot.CredentialRef) {
		return snapshot, errors.New("GoodQA credential reference malformed")
	}
	seen := map[string]bool{}
	for _, name := range snapshot.AllowedTools {
		if !goodqaToolName.MatchString(name) || seen[name] {
			return snapshot, errors.New("invalid GoodQA tool allowlist")
		}
		seen[name] = true
	}
	relative, e := filepath.Rel(filepath.Join(snapshot.DataDir, "mcp"), path)
	if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return snapshot, errors.New("GoodQA snapshot outside private settings scope")
	}
	return snapshot, nil
}

func (s *settingsStore) goodqaPolicyLocked(profile settingsProfile) (string, string, string, error) {
	g := s.disk.Settings.GoodQA
	if !g.Enabled || len(g.AllowedTools) == 0 {
		return "", "", "", nil
	}
	catalog, e := s.goodqaCatalogLocked()
	if e != nil {
		return "", "", "", e
	}
	known := map[string]bool{}
	for _, tool := range catalog.Tools {
		known[tool.Name] = true
	}
	for _, name := range g.AllowedTools {
		if !known[name] {
			return "", "", "", errors.New("GoodQA tools changed; discover and explicitly select current names")
		}
	}
	active := []string{}
	for _, name := range g.AllowedTools {
		if goodqaToolEnabled(g, name) {
			active = append(active, name)
		}
	}
	if len(active) == 0 {
		return "", "", "", nil
	}
	snapshot := goodqaProxySnapshot{Schema: 1, DataDir: s.dir, Revision: s.disk.Revision, ProfileID: profile.ID, ProfileGeneration: profile.Generation, Generation: g.Generation, Endpoint: g.Endpoint, CredentialRef: s.disk.Refs["goodqa:credential"], AllowedTools: active}
	sort.Strings(snapshot.AllowedTools)
	data, _ := json.Marshal(snapshot)
	dir := filepath.Join(s.dir, "mcp")
	if e = settingsPrivateDirectory(dir); e != nil {
		return "", "", "", e
	}
	digest := settingsDigest(data)
	path := filepath.Join(dir, "goodqa-snapshot-"+digest+".json")
	if e = settingsWriteImmutable(path, data); e != nil {
		return "", "", "", e
	}
	binary, e := os.Executable()
	if e != nil {
		return "", "", "", errors.New("console executable unavailable")
	}
	binary, e = filepath.EvalSymlinks(binary)
	if e != nil {
		return "", "", "", e
	}
	name, e := goodqaMCPServerName(digest)
	if e != nil {
		return "", "", "", e
	}
	config := stdioMCPConfig{Servers: map[string]stdioMCPServer{name: {Type: "stdio", Command: binary, Args: []string{"--goodqa-proxy", "--config", path, "--sha256", digest}}}}
	raw, _ := json.Marshal(config)
	configPath := filepath.Join(dir, "goodqa-client-"+settingsDigest(raw)+".json")
	if e = settingsWriteImmutable(configPath, raw); e != nil {
		return "", "", "", e
	}
	// The tool identity omits Revision, which exists to revoke the old proxy.
	unrevised := snapshot
	unrevised.Revision = 0
	identity, _ := json.Marshal(unrevised)
	return configPath, settingsDigest(raw), settingsDigest(identity), nil
}
func settingsWriteImmutable(path string, data []byte) error {
	existing, e := settingsRead(path, goodqaFrameLimit)
	if e == nil {
		if string(existing) != string(data) {
			return errors.New("immutable MCP snapshot changed")
		}
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	return settingsAtomicWrite(path, data)
}
func (s *settingsStore) goodqaCatalogLocked() (goodqaCatalog, error) {
	var catalog goodqaCatalog
	data, e := settingsRead(filepath.Join(s.dir, "goodqa-catalog.json"), goodqaFrameLimit)
	if e != nil || settingsDecode(data, &catalog) != nil || catalog.Generation != s.disk.Settings.GoodQA.Generation || catalog.Endpoint != s.disk.Settings.GoodQA.Endpoint || catalog.CredentialRef != s.disk.Refs["goodqa:credential"] {
		return catalog, errors.New("discover GoodQA tools before selecting an allowlist")
	}
	return catalog, nil
}

// A sent call keeps its admission snapshot. Each new call must still be allowed.
func goodqaCheckAuthority(snapshot goodqaProxySnapshot, name string, admission bool) error {
	release, e := settingsReadLock(filepath.Join(snapshot.DataDir, ".settings-write.guard"))
	if e != nil {
		return errors.New("GoodQA settings busy; no upstream request sent")
	}
	defer release()
	data, e := settingsRead(filepath.Join(snapshot.DataDir, "settings.json"), goodqaFrameLimit)
	var disk settingsDisk
	if e != nil || settingsDecode(data, &disk) != nil {
		return errors.New("GoodQA authority metadata unavailable")
	}
	g := disk.Settings.GoodQA
	if disk.Revision != snapshot.Revision || !g.Enabled || g.Generation != snapshot.Generation || g.Endpoint != snapshot.Endpoint || disk.Refs["goodqa:credential"] != snapshot.CredentialRef {
		return errors.New("GoodQA admission stale or revoked; resolve a new policy snapshot")
	}
	found := false
	for _, p := range disk.Settings.Profiles {
		if p.ID == snapshot.ProfileID && p.Generation == snapshot.ProfileGeneration && p.Allowed {
			found = true
		}
	}
	if !found {
		return errors.New("GoodQA profile disabled or removed")
	}
	if admission {
		for _, selected := range snapshot.AllowedTools {
			if !goodqaToolEnabled(g, selected) {
				return errors.New("GoodQA snapshot exceeds current explicit tool authority")
			}
		}
	}
	if !admission {
		original, current := false, false
		for _, n := range snapshot.AllowedTools {
			if n == name {
				original = true
			}
		}
		for _, n := range g.AllowedTools {
			if n == name {
				current = true
			}
		}
		if !original || !current || !goodqaToolEnabled(g, name) {
			return errors.New("GoodQA tool not explicitly allowed")
		}
	}
	return nil
}
