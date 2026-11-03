package main

import (
	"errors"
	"strings"
)

type policyStep struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profileId"`
	Model     string `json:"model"`
	Effort    string `json:"effort"`
}
type resolvedPolicy struct {
	MCPConfigPath       string       `json:"mcpConfigPath,omitempty"`
	MCPConfigSHA256     string       `json:"mcpConfigSHA256,omitempty"`
	MCPIdentity         string       `json:"mcpIdentity,omitempty"`
	Revision            string       `json:"revision"`
	Provider            string       `json:"provider"`
	ProfileID           string       `json:"profileId"`
	Model               string       `json:"model"`
	Effort              string       `json:"effort"`
	ServiceTier         string       `json:"serviceTier"`
	Permissions         string       `json:"permissions"`
	ApprovalPolicy      string       `json:"approvalPolicy"`
	HarnessInstructions string       `json:"harnessInstructions"`
	Cascade             []policyStep `json:"cascade"`
	ReviewStages        []policyStep `json:"reviewStages"`
}
type policyResolver func(provider, profile, stage string) (resolvedPolicy, error)

func defaultPolicy(provider, profile, stage string) (resolvedPolicy, error) {
	if provider != "codex" && provider != "claude" {
		return resolvedPolicy{}, errors.New("unknown provider")
	}
	policy := resolvedPolicy{Revision: "builtin-v1", Provider: provider, ProfileID: profile, ServiceTier: "default", HarnessInstructions: consoleHarnessInstructions}
	if provider == "codex" {
		policy.Model = "gpt-6.1-sol"
		policy.Effort = "high"
	}
	return policy, nil
}

type streamRedactor interface {
	Push(string) string
	Flush() string
}
type plainStream struct{}

func (plainStream) Push(value string) string { return value }
func (plainStream) Flush() string            { return "" }
func (a *app) policyFor(provider, profile, stage string) (resolvedPolicy, error) {
	a.mu.Lock()
	resolver := a.resolvePolicy
	a.mu.Unlock()
	if resolver == nil {
		return defaultPolicy(provider, profile, stage)
	}
	return resolver(provider, profile, stage)
}

func (a *app) clean(value string) string {
	if a.redact != nil {
		value = a.redact(value)
	}
	a.coreSecretMu.Lock()
	defer a.coreSecretMu.Unlock()
	for _, secret := range a.coreSecrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func applyThreadPolicy(params map[string]any, policy resolvedPolicy) {
	if policy.Model != "" {
		params["model"] = policy.Model
	}
	if policy.ServiceTier != "" {
		params["serviceTier"] = policy.ServiceTier
	}
	if policy.Effort != "" {
		params["config"] = map[string]any{"model_reasoning_effort": policy.Effort}
	}
	if policy.Permissions == "danger-full-access" || policy.Permissions == "workspace-write" || policy.Permissions == "read-only" {
		params["sandbox"] = policy.Permissions
	} else if policy.Permissions != "" {
		params["permissions"] = policy.Permissions
	}
	if policy.ApprovalPolicy != "" {
		params["approvalPolicy"] = policy.ApprovalPolicy
	}
	params["developerInstructions"] = policy.HarnessInstructions
}

func applyTurnPolicy(params map[string]any, policy resolvedPolicy, cwd string) {
	if policy.Model != "" {
		params["model"] = policy.Model
	}
	if policy.Effort != "" {
		params["effort"] = policy.Effort
	}
	if policy.ServiceTier != "" {
		params["serviceTier"] = policy.ServiceTier
	}
	if policy.ApprovalPolicy != "" {
		params["approvalPolicy"] = policy.ApprovalPolicy
	}
	switch policy.Permissions {
	case "danger-full-access":
		params["sandboxPolicy"] = map[string]any{"type": "dangerFullAccess"}
	case "workspace-write":
		params["sandboxPolicy"] = map[string]any{"type": "workspaceWrite", "writableRoots": []string{cwd}, "networkAccess": false}
	case "read-only":
		params["sandboxPolicy"] = map[string]any{"type": "readOnly", "networkAccess": false}
	default:
		if policy.Permissions != "" {
			params["permissions"] = policy.Permissions
		}
	}
}
func claudePermission(mode string) string {
	switch mode {
	case "danger-full-access":
		return "bypassPermissions"
	case "workspace-write":
		return "acceptEdits"
	case "read-only":
		return "plan"
	}
	return mode
}
