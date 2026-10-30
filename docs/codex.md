# Codex-native Agent Harness

This edition uses Codex's [global `AGENTS.md`](https://learn.chatgpt.com/docs/agent-configuration/agents-md), [skills](https://learn.chatgpt.com/docs/build-skills), [custom subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents), and [lifecycle hooks](https://learn.chatgpt.com/docs/hooks). It is a user-wide working agreement plus small local helpers, not a scheduler or proof that every model will follow every step.

## Install

Requirements: current local Codex with custom agents and hooks, Git, Python 3.11+, and macOS or Linux. The installer parses the existing and generated TOML before any write. On Python 3.10 and older, the Codex installer refuses to run; the unrelated Claude installer still supports Python 3.10. From a clone of this repo:

```sh
python3.11 install_codex.py                  # preview managed paths
python3.11 install_codex.py --apply          # merge and install
python3.11 -m unittest tests.test_install_codex -v
```

The installer puts a marked block in `~/.codex/AGENTS.md`, the skill in `~/.codex/skills/agent-harness`, role profiles in `~/.codex/agents`, the WAL writer in `~/.codex/agent-harness/wal.py`, and four managed entries in `~/.codex/hooks.json`. It also creates a private `~/.agent-harness/codex-wals` directory and selects a custom `agent-harness` permission profile in `~/.codex/config.toml`. That profile extends Codex's workspace policy and adds write access only for the private WAL path and workspace `.git` metadata, so agents can make recoverable local commits. It leaves unrelated model, plugin, and hook settings intact. If a different default permission profile or legacy sandbox configuration is already set, the installer stops before writing; merge the policy manually. The profile does not grant network access for pushing.

Originals are saved in a mode `0700` timestamped directory under `~/.codex/agent-harness/backups`, with a manifest. A caught write failure attempts rollback; crashes and concurrent edits may require restoring the private backup manually. Reinstalling updates the marked blocks and managed hook entries without duplicating them. The permission profile applies to new sessions; a session-level override can select a different policy and may block WAL notes or Git commits. Avoid `codex exec --ephemeral` for a task that needs subagents: in the live trial it could not create the owner's thread record.

If Codex appends unrelated TOML sections between the generated permission profile and its end marker, reinstallation moves those sections outside the managed block while preserving their bytes and parsed settings. The original file remains in the private backup. The installer refuses an edited managed profile, bare settings that could attach to it, managed permission descendants, or any move that changes TOML meaning. Reformatting the generated profile itself, including changing its line endings, requires a manual merge. A valid but unusual TOML `nan` value may also be refused by the conservative parsed-value comparison.

**Start a new Codex session and use `/hooks` to review and trust the installed user hook definition.** Codex skips untrusted non-managed hooks, including these, until their current hash is trusted. The installer does not bypass that safety check. If a hook changes in an update, review and trust it again. The global instructions and skill can still guide work when hooks are skipped, but automatic WAL entries are then absent. Existing Codex sessions may retain earlier instructions; restart them to load this setup.

## Operating model

Small localized reversible fixes stay in the main checkout with one focused check and a brief WAL. Substantive changes get a scope brief, one owner for each related area, recoverable feature commits, independent plan and exact-head review, proportionate red-team and live UI/API checks, and main-agent integration. The main agent keeps the user informed. A remote outage blocks publication, not local testing and delivery. The [skill](../codex/skills/agent-harness/SKILL.md) holds the workflow and loads [owner](../codex/skills/agent-harness/references/owner-workflow.md), [testing](../codex/skills/agent-harness/references/testing-and-evals.md), or [delivery](../codex/skills/agent-harness/references/delivery.md) detail as needed. Codex's native agent tools perform delegation; the role TOMLs select reviewer and rescue models where available.

The hook records session starts, prompt length, local tool name and input length, and subagent starts. It does not store prompt text or tool arguments. The model must add semantic notes for scope, decisions, checks, and handoff. The session or subagent start hook supplies the private WAL path; use:

```sh
python3 ~/.codex/agent-harness/wal.py note --wal ~/.agent-harness/codex-wals/SESSION_ID/main.jsonl --event intent --note 'Scoped intent without private values'
```

If the hook is unavailable, `python3 ~/.codex/agent-harness/wal.py start-manual` creates a private manual WAL. Keep WALs out of Git and review them before sharing. A hook can observe supported local tool paths but may not see hosted or specialized calls. Hook metadata proves a call was attempted; it does not establish test quality or model compliance. Custom agent instructions ask reviewers not to edit, but a role file does not give them a separate read-only sandbox; the parent session's permissions apply.

## Checks and recovery

The Codex-specific tests use disposable homes, failure injection at all 14 managed writes, symlink refusal, eight concurrent WAL writers, crash-tail recovery, metadata privacy, idempotent merge of foreign hooks and config, and refusal to override an existing permission policy. Run the full repo suite with `python3.11 -m unittest discover -s tests -v`. The installer uses the same pinned-directory, pinned-file, and rollback primitives as the Claude installer. Current validation results are in [validation.md](validation.md).

To uninstall, remove the marked block from `~/.codex/AGENTS.md`, the four entries invoking `~/.codex/agent-harness/wal.py hook` from `hooks.json`, and the copied role/skill files. Remove the `agent-harness` profile block and its `default_permissions` line from `config.toml`, then select your preferred default. Preserve other hook groups and config. The private WALs and backups can be retained for recovery or removed after reviewing them. Restore an appropriate backup when you need the exact previous content.
