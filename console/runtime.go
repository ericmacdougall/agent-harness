package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type authGenerationState struct {
	mu         sync.RWMutex
	generation map[string]uint64
	fenced     map[string]bool
	transition sync.Map
}

var authGenerations sync.Map

func (a *app) setAuthTransition(provider, profile string, complete bool) uint64 {
	value, _ := authGenerations.LoadOrStore(a, &authGenerationState{generation: map[string]uint64{}, fenced: map[string]bool{}})
	state := value.(*authGenerationState)
	key := provider + "\x00" + profile
	// Publish the boundary before waiting for admitted writes to drain. New
	// readers fail immediately; the write lock then orders the generation bump
	// after every byte write that was admitted before the boundary.
	state.transition.Store(key, true)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.generation[key]++
	state.fenced[key] = !complete
	if complete {
		state.transition.Store(key, false)
	}
	return state.generation[key]
}

func (a *app) authTransitioning(provider, profile string) bool {
	value, _ := authGenerations.LoadOrStore(a, &authGenerationState{generation: map[string]uint64{}, fenced: map[string]bool{}})
	state := value.(*authGenerationState)
	pending, _ := state.transition.Load(provider + "\x00" + profile)
	active, _ := pending.(bool)
	return active
}

// authAdmission holds the profile generation read lock through the provider
// byte write. A transition takes the write lock, so it either follows a fully
// admitted old-generation write or fences that write before it reaches stdin.
func (a *app) authAdmission(provider, profile string, generation uint64) inputAdmission {
	return func() (func(), error) {
		value, _ := authGenerations.LoadOrStore(a, &authGenerationState{generation: map[string]uint64{}, fenced: map[string]bool{}})
		state := value.(*authGenerationState)
		key := provider + "\x00" + profile
		if pending, _ := state.transition.Load(key); pending == true {
			return nil, refused("provider authentication transition is active")
		}
		state.mu.RLock()
		pending, _ := state.transition.Load(key)
		if pending == true || state.fenced[key] || state.generation[key] != generation {
			state.mu.RUnlock()
			return nil, refused("provider authentication generation changed")
		}
		return state.mu.RUnlock, nil
	}
}

func (a *app) resolveRuntimeCaptured(policy resolvedPolicy) (string, []string, string, uint64, error) {
	binary, env, err := a.runtime(policy.Provider, policy.ProfileID)
	if err != nil {
		return "", nil, "", 0, err
	}
	value, _ := authGenerations.LoadOrStore(a, &authGenerationState{generation: map[string]uint64{}, fenced: map[string]bool{}})
	state := value.(*authGenerationState)
	state.mu.RLock()
	key := policy.Provider + "\x00" + policy.ProfileID
	generation := state.generation[key]
	pending, _ := state.transition.Load(key)
	if pending == true || state.fenced[key] {
		state.mu.RUnlock()
		return "", nil, "", 0, errors.New("provider authentication outcome requires reconciliation before launching work")
	}
	defer state.mu.RUnlock()
	marker := ""
	stable := []string{binary, policy.MCPConfigSHA256, fmt.Sprintf("auth-generation=%d", generation)}
	for _, value := range env {
		if strings.HasPrefix(value, "HARNESS_SETTINGS_REVISION=") {
			marker = strings.TrimPrefix(value, "HARNESS_SETTINGS_REVISION=")
		} else {
			stable = append(stable, value)
		}
	}
	if policy.Revision != "builtin-v1" && marker != policy.Revision {
		return "", nil, "", 0, errors.New("settings changed before provider dispatch; retry before sending")
	}
	sort.Strings(stable)
	sum := sha256.Sum256([]byte(strings.Join(stable, "\x00")))
	return binary, env, hex.EncodeToString(sum[:]), generation, nil
}

// conversationIdentity names the credentials and tools behind a conversation. It
// leaves out the settings revision and the MCP config hash that embeds it: a save
// revokes the old GoodQA proxy on purpose, but that alone changes neither account
// nor tools, and the next process picks up the new config.
func conversationIdentity(binary string, env []string, policy resolvedPolicy) string {
	tools := policy.MCPIdentity
	if tools == "" {
		tools = policy.MCPConfigSHA256
	}
	stable := []string{binary, tools}
	for _, value := range env {
		if !strings.HasPrefix(value, "HARNESS_SETTINGS_REVISION=") {
			stable = append(stable, value)
		}
	}
	sort.Strings(stable)
	sum := sha256.Sum256([]byte(strings.Join(stable, "\x00")))
	return hex.EncodeToString(sum[:])
}

func (a *app) resolveRuntime(policy resolvedPolicy) (string, []string, string, error) {
	binary, env, fingerprint, _, err := a.resolveRuntimeCaptured(policy)
	return binary, env, fingerprint, err
}
