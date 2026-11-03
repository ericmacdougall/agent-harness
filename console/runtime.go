package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

func (a *app) resolveRuntime(policy resolvedPolicy) (string, []string, string, error) {
	binary, env, err := a.runtime(policy.Provider, policy.ProfileID)
	if err != nil {
		return "", nil, "", err
	}
	marker := ""
	stable := []string{binary, policy.MCPConfigSHA256}
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
