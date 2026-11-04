package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type settingsPayload struct {
	Files     map[string]string `json:"files"`
	Sources   map[string]string `json:"sources"`
	HookState string            `json:"hookState"`
}

// Provision an explicit allowlist of harness payloads, never a config/auth tree.
// The manifest owns exact bytes; user edits stop subsequent automatic launches.
func (s *settingsStore) provisionHarness(root string, p settingsProfile) error {
	manifest := filepath.Join(root, "harness-payload.json")
	if data, e := settingsRead(manifest, 1<<20); e == nil {
		var m settingsPayload
		if settingsDecode(data, &m) != nil {
			return errors.New("profile harness manifest invalid")
		}
		for relative, digest := range m.Files {
			if filepath.IsAbs(relative) || strings.Contains(relative, "..") {
				return errors.New("profile harness path invalid")
			}
			data, e := settingsRead(filepath.Join(root, relative), 1<<20)
			if e != nil || settingsDigest(data) != digest {
				return errors.New("profile harness payload was edited; reconcile its instruction, role or hook changes before launch")
			}
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	home, _ := os.UserHomeDir()
	sourceRoot := filepath.Join(home, ".codex")
	if p.Provider == "claude" {
		sourceRoot = filepath.Join(home, ".claude")
	}
	m := settingsPayload{Files: map[string]string{}, Sources: map[string]string{}, HookState: "unverified"}
	put := func(relative string, data []byte) error {
		path := filepath.Join(root, relative)
		if e := settingsPrivateDirectory(filepath.Dir(path)); e != nil {
			return e
		}
		if _, e := os.Lstat(path); e == nil {
			return errors.New("profile contains unmanaged harness files; reconcile before provisioning")
		}
		if e := settingsAtomicWrite(path, data); e != nil {
			return e
		}
		m.Files[relative] = settingsDigest(data)
		return nil
	}
	copyKnown := func(relative string) error {
		source := filepath.Join(sourceRoot, relative)
		data, e := settingsRead(source, 1<<20)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		m.Sources[source] = settingsDigest(data)
		return put(relative, data)
	}
	guide := "AGENTS.md"
	if p.Provider == "claude" {
		guide = "CLAUDE.md"
	}
	text := consoleHarnessInstructions + "\n"
	if data, e := settingsRead(filepath.Join(sourceRoot, guide), 1<<20); e == nil {
		text += "\n" + string(data)
		m.Sources[filepath.Join(sourceRoot, guide)] = settingsDigest(data)
	}
	if e := put(guide, []byte(text)); e != nil {
		return e
	}
	for _, relative := range []string{"skills/agent-harness/SKILL.md", "skills/agent-harness/references/owner-workflow.md", "skills/agent-harness/references/testing-and-evals.md", "skills/agent-harness/references/delivery.md"} {
		if e := copyKnown(relative); e != nil {
			return e
		}
	}
	config := "cli_auth_credentials_store = \"keyring\"\n"
	if p.Provider == "codex" {
		for _, name := range []string{"harness_owner", "harness_reviewer", "harness_red_team", "harness_click_tester", "harness_fixer", "harness_rescue"} {
			relative := "agents/" + name + ".toml"
			if e := copyKnown(relative); e != nil {
				return e
			}
			if _, ok := m.Files[relative]; ok {
				config += fmt.Sprintf("\n[agents.%s]\ndescription = %s\nconfig_file = %s\n", name, strconv.Quote(strings.ReplaceAll(name, "_", " ")), strconv.Quote(relative))
			}
		}
	} else {
		for _, name := range []string{"task-owner", "red-team", "fixer", "click-tester"} {
			if e := copyKnown("agents/" + name + ".md"); e != nil {
				return e
			}
		}
	}
	// Helpers come only from the known installed Codex harness and no receipts,
	// backups, sessions, bridge state or broad environment files are considered.
	helperRoot := filepath.Join(home, ".codex", "agent-harness")
	for _, name := range []string{"wal.py", "process.py", "report_file.py", "git_safety.py", "github_identity.py", "usage_guard.py", "publish_feature.py", "integrate_local.py", "deliver.py", "watch-tests.py"} {
		data, e := settingsRead(filepath.Join(helperRoot, name), 1<<20)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if e = put(filepath.Join("agent-harness", name), data); e != nil {
			return e
		}
	}
	if p.Provider == "codex" {
		if data, e := settingsRead(filepath.Join(sourceRoot, "hooks.json"), 1<<20); e == nil {
			if _, events, e := settingsHookGroups(data); e == nil {
				selected := map[string]any{}
				python := ""
				for _, candidate := range []string{"/opt/homebrew/bin/python3.15", "/usr/local/bin/python3", "/usr/bin/python3", "python3"} {
					if found, e := exec.LookPath(candidate); e == nil {
						python = found
						break
					}
				}
				if python != "" {
					for event, value := range events {
						groups, _ := value.([]any)
						out := []any{}
						for _, item := range groups {
							group, _ := item.(map[string]any)
							handlers, _ := group["hooks"].([]any)
							kept := []any{}
							for _, handler := range handlers {
								h, _ := handler.(map[string]any)
								command, _ := h["command"].(string)
								if !strings.Contains(command, filepath.Join(helperRoot, "wal.py")) || !strings.HasSuffix(command, "wal.py hook") {
									continue
								}
								h["command"] = settingsShellArg(python) + " " + settingsShellArg(filepath.Join(root, "agent-harness", "wal.py")) + " hook"
								kept = append(kept, h)
							}
							if len(kept) > 0 {
								group["hooks"] = kept
								out = append(out, group)
							}
						}
						if len(out) > 0 {
							selected[event] = out
						}
					}
				}
				if len(selected) > 0 {
					raw, _ := json.MarshalIndent(map[string]any{"hooks": selected}, "", "  ")
					if e = put("hooks.json", raw); e != nil {
						return e
					}
					m.HookState = "review_required"
				}
			}
		}
		if e := put("config.toml", []byte(config)); e != nil {
			return e
		}
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	return settingsAtomicWrite(manifest, raw)
}
func settingsShellArg(value string) string {
	if runtime.GOOS == "windows" {
		return strconv.Quote(value)
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
