package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (s *settingsStore) runtime(provider, profile string) (string, []string, error) {
	s.mu.Lock()
	if s.uncertain {
		s.mu.Unlock()
		return "", nil, errors.New("settings outcome unknown; restart to reconcile before launching work")
	}
	if profile == "" {
		profile = "global-" + provider
		if provider == s.disk.Settings.Defaults.Provider {
			profile = s.disk.Settings.Defaults.ProfileID
		}
	}
	p, ok := s.profileLocked(profile)
	if !ok || !p.Allowed || p.Provider != provider {
		s.mu.Unlock()
		return "", nil, errors.New("profile is disabled, removed, or belongs to another provider")
	}
	revision := s.disk.Revision
	refs := map[string]string{}
	plain := map[string]string{}
	if id := s.disk.Refs[secretSlot(p.ID, "api_key")]; id != "" {
		refs["api_key"] = id
	}
	for _, e := range s.disk.Settings.Environment {
		if e.ProfileID == profile && e.Enabled {
			if !e.isSensitive() {
				plain[e.Name] = e.Value
				continue
			}
			if id := s.disk.Refs[secretSlot(profile, e.Name)]; id != "" {
				refs[e.Name] = id
			}
		}
	}
	s.mu.Unlock()
	binary, e := discoverBinary(provider)
	if e != nil {
		return "", nil, e
	}
	env := map[string]string{}
	for _, entry := range os.Environ() {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if provider == "codex" && (strings.HasPrefix(k, "CLAUDE_") || strings.HasPrefix(k, "ANTHROPIC_")) {
			continue
		}
		if provider == "claude" && (strings.HasPrefix(k, "CODEX_") || strings.HasPrefix(k, "OPENAI_")) {
			continue
		}
		if p.Kind != "global" && (strings.HasPrefix(k, "CODEX_") || strings.HasPrefix(k, "CLAUDE_") || strings.HasPrefix(k, "OPENAI_") || strings.HasPrefix(k, "ANTHROPIC_")) {
			continue
		}
		env[k] = v
		if len(v) >= 4 && (strings.Contains(k, "API_KEY") || strings.Contains(k, "ACCESS_TOKEN") || strings.Contains(k, "AUTH_TOKEN")) {
			s.remember(v)
		}
	}
	if p.Kind != "global" {
		home, e := s.profileHome(p)
		if e != nil {
			return "", nil, e
		}
		if provider == "codex" {
			env["CODEX_HOME"] = home
		} else {
			env["CLAUDE_CONFIG_DIR"] = home
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for name, value := range plain {
		env[name] = value
	}
	for name, id := range refs {
		value, e := s.readSecret(ctx, id)
		if e != nil {
			return "", nil, e
		}
		if name == "api_key" {
			if provider == "codex" {
				env["OPENAI_API_KEY"] = value
				env["CODEX_API_KEY"] = value
			} else {
				env["ANTHROPIC_API_KEY"] = value
			}
		} else {
			env[name] = value
		}
	}
	if p.Kind == "api_key" && refs["api_key"] == "" {
		return "", nil, errors.New("save an API key in this profile before starting work")
	}
	env["HARNESS_SETTINGS_REVISION"] = settingsRevision(revision)
	names := []string{}
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)
	out := []string{}
	for _, k := range names {
		out = append(out, k+"="+env[k])
	}
	return binary, out, nil
}
func (s *settingsStore) policy(provider, profile, stage string) (resolvedPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !oneOf(stage, "main", "plan_review", "code_review", "final_review") {
		return resolvedPolicy{}, errors.New("unknown policy stage")
	}
	d := s.disk.Settings.Defaults
	if provider == "" {
		provider = d.Provider
	}
	if profile == "" {
		profile = "global-" + provider
		if provider == d.Provider {
			profile = d.ProfileID
		}
	}
	p, ok := s.profileLocked(profile)
	if !ok || !p.Allowed || p.Provider != provider {
		return resolvedPolicy{}, errors.New("selected profile is unavailable")
	}
	policy := resolvedPolicy{Revision: settingsRevision(s.disk.Revision), Provider: provider, ProfileID: profile, ServiceTier: "default", Permissions: map[string]string{"full_access": "danger-full-access", "workspace_write": "workspace-write", "read_only": "read-only"}[d.Permissions], ApprovalPolicy: map[string]string{"never": "never", "on_request": "on-request"}[d.ApprovalPolicy], Cascade: append([]policyStep{}, s.disk.Settings.Cascade...), ReviewStages: append([]policyStep{}, s.disk.Settings.ReviewLadder...)}
	policy.ReviewStages = s.effectiveReviewStagesLocked(provider, profile)
	if d.Provider == provider {
		policy.Model = d.Model
		policy.Effort = d.Effort
		if d.ServiceTier == "priority" {
			policy.ServiceTier = "priority"
		}
	}
	if provider == "claude" && policy.ServiceTier == "priority" {
		return resolvedPolicy{}, errors.New("Claude priority tier is unsupported by this adapter; select normal")
	}
	if d.Harness == "agent_harness" {
		policy.HarnessInstructions = consoleHarnessInstructions
	}
	var err error
	policy.MCPConfigPath, policy.MCPConfigSHA256, err = s.goodqaPolicyLocked(p)
	if err != nil {
		return resolvedPolicy{}, err
	}
	return policy, nil
}

func (s *settingsStore) effectiveReviewStagesLocked(provider, profile string) []policyStep {
	if len(s.disk.Settings.ReviewLadder) > 0 {
		return append([]policyStep{}, s.disk.Settings.ReviewLadder...)
	}
	reviewProfile := "global-codex"
	if provider == "codex" {
		reviewProfile = profile
	} else if s.disk.Settings.Defaults.Provider == "codex" {
		reviewProfile = s.disk.Settings.Defaults.ProfileID
	}
	return []policyStep{{Provider: "codex", ProfileID: reviewProfile, Model: "gpt-6.1-sol", Effort: "high"}}
}
func (s *settingsStore) profileHome(p settingsProfile) (string, error) {
	if !validVaultItem(p.ID) {
		return "", errors.New("invalid managed profile identifier")
	}
	root := filepath.Join(s.dir, "profiles", p.ID)
	if e := settingsPrivateDirectory(root); e != nil {
		return "", e
	}
	if e := s.provisionHarness(root, p); e != nil {
		return "", e
	}
	return root, nil
}
