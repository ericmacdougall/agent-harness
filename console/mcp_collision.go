package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func envEntry(env []string, name string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(env[i], "="); ok && strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
func policyMCPNames(policy resolvedPolicy) ([]string, error) {
	config, err := validateMCPConfig(policy.MCPConfigPath, policy.MCPConfigSHA256)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for name := range config.Servers {
		names = append(names, name)
	}
	return names, nil
}
func guardNativeMCP(provider, binary string, env []string, cwd string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	if provider == "codex" {
		return guardCodexMCP(binary, env, cwd, names)
	}
	if provider == "claude" {
		return guardClaudeMCP(env, cwd, names)
	}
	return errors.New("unknown native MCP provider")
}
func guardCodexMCP(binary string, env []string, cwd string, names []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "mcp", "list", "--json")
	command.Env = env
	command.Dir = cwd
	out := &cappedBuffer{limit: 1 << 20}
	command.Stdout = out
	command.Stderr = &cappedBuffer{limit: 4096}
	if command.Run() != nil || len(out.data) >= out.limit {
		return errors.New("native Codex MCP configuration could not be verified before helper admission")
	}
	if settingsUniqueJSON(out.data) != nil {
		return errors.New("native Codex MCP metadata is invalid")
	}
	var servers []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(out.data, &servers) != nil || servers == nil || len(servers) > 256 {
		return errors.New("native Codex MCP metadata has unsupported shape")
	}
	for _, server := range servers {
		for _, name := range names {
			if server.Name == name {
				return errors.New("native MCP name collision; existing server preserved and helper refused")
			}
		}
	}
	return nil
}
func nativeJSON(path string) (map[string]any, bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, false, errors.New("native MCP configuration is unreadable or exceeds bounds")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, errors.New("native MCP configuration cannot be opened")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, errors.New("native MCP configuration changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(data) > 1<<20 || settingsUniqueJSON(data) != nil {
		return nil, false, errors.New("native MCP JSON configuration is invalid")
	}
	after, err := f.Stat()
	if err != nil || !opened.ModTime().Equal(after.ModTime()) || opened.Size() != after.Size() {
		return nil, false, errors.New("native MCP configuration changed during inspection")
	}
	var parsed map[string]any
	if json.Unmarshal(data, &parsed) != nil || parsed == nil {
		return nil, false, errors.New("native MCP configuration is not an object")
	}
	return parsed, true, nil
}
func checkMCPNames(config map[string]any, names []string) error {
	for _, key := range []string{"mcpServers", "managedMcpServers"} {
		if raw, exists := config[key]; exists {
			servers, ok := raw.(map[string]any)
			if !ok {
				return errors.New("native MCP server metadata has unsupported shape")
			}
			for _, name := range names {
				if _, exists := servers[name]; exists {
					return errors.New("native MCP name collision; existing server preserved and helper refused")
				}
			}
		}
	}
	return nil
}
func guardClaudeMCP(env []string, cwd string, names []string) error {
	home := envEntry(env, "HOME")
	if home == "" {
		home = envEntry(env, "USERPROFILE")
	}
	if !filepath.IsAbs(home) {
		return errors.New("native Claude home unavailable for MCP inspection")
	}
	configDir := envEntry(env, "CLAUDE_CONFIG_DIR")
	if configDir == "" {
		configDir = filepath.Join(home, ".claude")
	}
	if !filepath.IsAbs(configDir) {
		return errors.New("native Claude config directory must be absolute")
	}
	systemDir := "/etc/claude-code"
	if runtime.GOOS == "darwin" {
		systemDir = "/Library/Application Support/ClaudeCode"
	}
	if runtime.GOOS == "windows" {
		systemDir = filepath.Join(envEntry(env, "ProgramFiles"), "ClaudeCode")
	}
	return guardClaudeMCPFiles(home, configDir, cwd, systemDir, names)
}
func guardClaudeMCPFiles(home, configDir, cwd, systemDir string, names []string) error {
	ancestors := []string{}
	for path := cwd; ; path = filepath.Dir(path) {
		ancestors = append(ancestors, path)
		if filepath.Dir(path) == path {
			break
		}
		if len(ancestors) > 128 {
			return errors.New("native project ancestry exceeds inspection bound")
		}
	}
	files := []string{filepath.Join(home, ".claude.json"), filepath.Join(configDir, ".claude.json"), filepath.Join(configDir, "managed-settings.json"), filepath.Join(systemDir, "managed-settings.json")}
	for _, path := range ancestors {
		files = append(files, filepath.Join(path, ".mcp.json"))
	}
	for _, path := range files {
		config, exists, err := nativeJSON(path)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err = checkMCPNames(config, names); err != nil {
			return err
		}
		if raw, exists := config["projects"]; exists {
			projects, ok := raw.(map[string]any)
			if !ok {
				return errors.New("native Claude project MCP metadata malformed")
			}
			for _, ancestor := range ancestors {
				if scoped, ok := projects[ancestor].(map[string]any); ok {
					if err = checkMCPNames(scoped, names); err != nil {
						return err
					}
				}
			}
		}
	}
	if _, exists, err := nativeJSON(filepath.Join(systemDir, "managed-mcp.json")); err != nil {
		return err
	} else if exists {
		return errors.New("native managed MCP configuration exclusive; existing servers preserved, helper injection refused")
	}
	return nil
}
