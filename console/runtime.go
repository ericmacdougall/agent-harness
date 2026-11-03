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
}

var authGenerations sync.Map

func (a *app) authGeneration(provider, profile string) uint64 {
	value, _ := authGenerations.LoadOrStore(a, &authGenerationState{generation: map[string]uint64{}})
	state := value.(*authGenerationState)
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.generation[provider+"\x00"+profile]
}

func (a *app) advanceAuthGeneration(provider, profile string) uint64 {
	value, _ := authGenerations.LoadOrStore(a, &authGenerationState{generation: map[string]uint64{}})
	state := value.(*authGenerationState)
	state.mu.Lock()
	defer state.mu.Unlock()
	key := provider + "\x00" + profile
	state.generation[key]++
	return state.generation[key]
}

func (a *app) resolveRuntime(policy resolvedPolicy) (string, []string, string, error) {
	binary, env, err := a.runtime(policy.Provider, policy.ProfileID)
	if err != nil {
		return "", nil, "", err
	}
	marker := ""
	stable := []string{binary, policy.MCPConfigSHA256, fmt.Sprintf("auth-generation=%d", a.authGeneration(policy.Provider, policy.ProfileID))}
	for _, value := range env {
		if strings.HasPrefix(value, "HARNESS_SETTINGS_REVISION=") {
			marker = strings.TrimPrefix(value, "HARNESS_SETTINGS_REVISION=")
		} else {
			stable = append(stable, value)
		}
	}
	if policy.Revision != "builtin-v1" && marker != policy.Revision {
		return "", nil, "", errors.New("settings changed before provider dispatch; retry before sending")
	}
	sort.Strings(stable)
	sum := sha256.Sum256([]byte(strings.Join(stable, "\x00")))
	return binary, env, hex.EncodeToString(sum[:]), nil
}
