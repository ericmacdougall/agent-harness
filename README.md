# Agent Harness for Claude Code and Codex

Agent Harness installs user-wide guidance for scoped software work, recoverable commits, independent review, testing, and local delivery. Both editions use instructions and small Python helpers; neither is a daemon, CI service, or guarantee that an agent follows every step.

## Quick start

Clone this repository, then choose the edition for your agent:

```sh
git clone https://github.com/ericmacdougall/agent-harness.git
cd agent-harness
```

**Claude Code** requires version **2.1.295+**, Python **3.10+**, and Git on macOS or Linux. Preview, install, then start a new Claude Code session:

```sh
python3 install.py
python3 install.py --apply
```

**Codex** requires a current local Codex with custom agents and hooks, Python **3.11+**, and Git on macOS or Linux. Preview, install, then start a new Codex session and use `/hooks` to review and trust the installed hooks:

```sh
python3.11 install_codex.py
python3.11 install_codex.py --apply
```

Replace `python3.11` with your available Python 3.11+ executable if needed. The Codex installer adds a narrow permission profile for private WAL writes and local Git commits. To explicitly select built-in Full Access for new chats, preview and apply with `--default-full-access`; [Codex setup and limits](docs/codex.md) explains the effect, legacy sandbox conflicts, and separate Browser site permissions. Windows behavior has not been tested.

### Keep substantive Codex work open

Use the main WAL path shown by the session hook to arm a checkpoint before dispatching work. Inspect it with `status`, and record the outcome in the WAL before choosing `complete`, `blocked`, `handoff`, or `paused`.

```sh
session_wal="/path/from/the/session/hook/main.jsonl"
python3 ~/.codex/agent-harness/wal.py continuation --wal "$session_wal" active
python3 ~/.codex/agent-harness/wal.py continuation --wal "$session_wal" status
```

With trusted hooks, Stop can request one automatic continuation per session when the checkpoint is active. It keeps the checkpoint visible after that allowance is spent. This helps catch an early final reply while a test or worker is still running. It requires explicit tracking and does not supervise detached jobs. See [checkpoint and handoff rules](codex/skills/agent-harness/references/delivery.md).

## Capabilities by edition

| | Claude Code | Codex |
| --- | --- | --- |
| Guidance and roles | `~/.claude/CLAUDE.md` and four task roles | `~/.codex/AGENTS.md`, one skill, and six custom roles |
| Private WAL | `~/.claude/wals`; matched write-tool hooks can block on WAL failure | `~/.agent-harness/codex-wals`; hooks record supported lifecycle and tool metadata after trust |
| Review | Claude helper calls Codex Sol when available, with a Claude Opus fallback | Native subagents use the reviewer role; rescue is available for repeated blockers |
| Delivery | Installed two-phase `deliver.py`, guarded Git helpers, and test watcher | The same delivery helpers and watcher installed under `~/.codex/agent-harness`; no Claude installation required |

Both editions send small, reversible fixes through a fast path. Substantive work gets an owner per related scope, a separate worktree, semantic WAL notes, relevant failure-first tests, independent review, and live UI/API checks when applicable. Hook records omit prompt text and tool arguments; the main agent still has to inspect evidence. Publication failures do not prevent verified local delivery. Claude's detailed policy is in [HARNESS.md](HARNESS.md), with roles in [harness/agents](harness/agents) and helpers in [harness/hooks](harness/hooks). Codex's workflow is in its [skill](codex/skills/agent-harness/SKILL.md).

## Claude Code install details

Codex CLI and access to `gpt-6.1-sol`/`gpt-6-astra` enable the preferred Claude review path. Claude Opus and Fable access enable fallbacks. Review and rescue calls can incur model charges.

The installer copies the agents and helpers into `~/.claude`, places a marked block in `~/.claude/CLAUDE.md`, and **merges** its hooks and narrow helper permission rules into `settings.json`. That includes the read-only `commit_policy.py` checks. The `waive` command is deliberately left off the allow list. It also registers the `hook.agent-harness-commit-policy` commit-msg backstop in `~/.gitconfig`, or reports it inactive on Git older than 2.54. Existing model, theme, deny rules, and unrelated hooks are preserved. It backs up files it replaces under `~/.claude/agent-harness-backups`. It validates payloads before writing and attempts to restore replaced files if a write fails; an incomplete rollback reports the affected paths and backup location. Crash recovery still requires the backups. The installer does not enable dangerous permission bypass or set a model. Inspect the preview and start a **new Claude Code session** after installation.

Durable working state: the installer sets `CLAUDE_CODE_TMPDIR` in `settings.json` to `~/.agent-harness/scratch` (mode 0700) when you have not set it. Claude Code then keeps its session scratchpad and background-task output there instead of `/tmp`, which macOS wipes on reboot. Only new sessions use the new path; a session reports a warning at start if its scratchpad is still in `/tmp`. The hooks also create and announce `~/.agent-harness/work/<session-id>/` for scripts, run kits, packets and job state, and warn (never block) when such files are written to `/tmp` or the scratchpad. Set `AGENT_HARNESS_TMP_ADVISORY=0` to silence that warning. Task output can contain command output, including secrets, and it now survives reboots. Exclude `.agent-harness/scratch/**` from cloud backups. The installer creates the root with mode 0700, asks Time Machine to exclude it, and adds a best-effort `.metadata_never_index` marker for Spotlight. To bound secret-bearing output, a session start launches a detached job at most once a day. It finds `tasks/*.output` files older than 14 days that no live process holds open (`/proc` on Linux, `lsof` on macOS), skipping the current session and `.keep` sessions. It deletes only files that an encrypted backup has verified, and with no backup configured it only reports, in `~/.agent-harness/work/.task-output-prune.json`. To configure the backup, write a mode-0600 `~/.agent-harness/task-output-backup.json` such as `{"remote": "lessons-dropbox:Backups/agent-scratch-task-output", "password_command": ["security", "find-generic-password", "-s", "agent-harness-task-output-backup", "-w"]}`. The passphrase stays in the keychain or a secret manager. The job wraps the remote in an env-only rclone crypt layer under `<remote>/<host>/`, copies the files, runs `rclone cryptcheck`, and deletes only verified files whose size and mtime are unchanged. A failed upload or check deletes nothing. If the open check is unavailable, it also deletes nothing. Keep a recovery copy of the passphrase, such as in a password manager, because the backup cannot be read without it. Each host writes under its short hostname, so give hosts distinct names. `AGENT_HARNESS_TASK_OUTPUT_PRUNE=off` disables the job. `python3 ~/.claude/hooks/workdir.py prune` lists other retention candidates (a dry run; `--apply` deletes). It removes scratch session directories after seven idle days and keeps their remaining `tasks/` output unless you pass `--include-task-output`. It removes work directories after 45 idle days, or after 14 once they are marked done. It never removes a directory holding a `.keep` file, or a session whose WAL or transcript changed recently. Pruning never touches WALs or anything under `~/.claude` or `~/.codex`. Setting your own `CLAUDE_CODE_TMPDIR` value, even `/tmp`, is always preserved. `install.py --apply --no-durable-tmp` removes the harness value and is remembered, and `--durable-tmp` turns it back on. To roll back by hand, delete the key, restart sessions and optionally remove `~/.agent-harness/scratch`.

It also installs the pinned [netwatch](https://github.com/ericmacdougall/netwatch) monitor (network health and orphaned dev processes) at `~/.agent-harness/bin/netwatch`, with a SHA-256 check, and registers its per-user service. This step downloads one release archive from GitHub. Pass `--no-netwatch` to skip it; see [operations](docs/operations.md#netwatch-monitor).

Claude Code's `--safe-mode` disables `CLAUDE.md` and hooks, including the WAL gate. Use a normal session when relying on harness enforcement.

To uninstall, follow these steps:

1. Remove the marked block from `CLAUDE.md`.
2. Remove the harness entries from `settings.json`: the hook entries pointing at `~/.claude/hooks/wal.py`, `~/.claude/hooks/commit_policy.py`, `~/.claude/hooks/spec_flow.py`, `~/.claude/hooks/merge_gate.py` or `~/.claude/hooks/command_guard_hook.py`, and the harness permission rules.
3. Run `python3 ~/.claude/hooks/commit_policy.py uninstall-git-hook`.
4. If installed, run `~/.agent-harness/bin/netwatch uninstall`, delete the binary, and pass `--no-netwatch` to any later install.
5. Remove the copied agents and helper scripts. Restore a backup if you want the exact earlier state.

## Operating model

An optional [Harness TUI plugin](docs/tui-plugin.md) opens a compatible local Go
operator in an offline reference view using context supplied by the current
chat. It includes local MCP adapters for Codex/ChatGPT and Claude clients plus
an explicit Chromium action for active browser conversations. Its separate
installer preserves existing agent permissions and global harness settings.

1. The main agent records the initial checkout, scopes the request, asks about consequential ambiguity, and assigns one owner to each nonoverlapping task. Related follow-ups go to the same owner.
2. The owner writes WAL intent and a risk table, reconciles independent planning objections, implements recoverable increments and meaningful failing controls, then runs focused checks.
3. Independent code inspection comes before expensive full validation. The owner repairs findings, runs affected checks and freezes runtime inputs/docs; required full validation runs once at the stable subject, followed by a fresh exact-HEAD PR evidence review. Live testers inspect runnable flows when relevant. Main checks scope, evidence and documentation.
4. The main agent attempts a feature branch push and draft PR. A successful PR is ready for review; the original checkout is synced and checked after an authorized remote merge. If publication fails, feature-worktree verification continues. Guarded scratch integration delivers locally when available and appropriate; otherwise the user receives the remote and original-checkout delivery blockers.

Both editions install `deliver.py`. Its prepare phase verifies reviewed commits and repository identity, publishes the feature and creates or reuses a matching draft PR; it leaves the original checkout unchanged. After an authorized remote merge, finish fetches the pinned target through an isolated transport, fast-forwards with hooks disabled and overwrite/autostash protection, and checks the original before recording delivery. Explicit local-only mode or a definite remote failure uses the scratch integration path. Policy refusals and uncertain outcomes cannot silently become local fallback. Recovery state belongs to the repository Git common directory, independent of `HOME`, and unresolved applies block other integration tools on that original checkout and branch. Historical receipts do not silently sync newer work. Prepare also refuses stale or huge original checkouts and a missing remote base branch before pushing, maps definite `gh pr create` failures to `REMOTE_BLOCKED` with a hint, and lists commit-policy waivers it relied on ([details](docs/operations.md#prepare-preflights-and-failure-verdicts)). See [operations](docs/operations.md#delivery-workflow) for commands, recovery and run-kit requirements.

Both editions enforce one commit message format for agent commits: `<type>(<scope>): <summary>` followed by `Why:`, `What:`, `Testing:` and `Refs:` sections. In ticket-tracked repositories, each commit must name a GoodQA ticket, and that ticket must have been updated about the commit before publication. A PreToolUse hook checks each `git commit` before it runs, including commits made over `ssh` on dev2/T2. It also checks `gh pr create`. A git `commit-msg` config hook (Git 2.54+) runs alongside each repository's own hooks. `deliver.py prepare` and `peer_review.py pr` refuse non-compliant ranges, and `deliver.py finish` comments the delivered SHA on each ticket. Rules live in one file, `commit_policy.json`. The only exception path is a reasoned waiver recorded in the WAL. See [commit message policy](docs/operations.md#commit-message-policy).

Untracked repos may reference local ledger tickets. `harness tickets` keeps tickets in hidden git refs of the repository, offline and on this machine only. In a repository that no ticket system tracks (no remote URL or push URL matches), or a remote-less one listed in `ledger.allowed_repos`, a commit may cite `Refs: Ledger <slug>#<8+ hex>`. The policy resolves the ref with the local `harness` binary and fails closed if it cannot. Tracked repositories still need GoodQA tickets. See [the local ledger](docs/ledger.md).

When `peer_review.py` cannot produce a reviewed result it prints a stable reason code, an exact next step and a reminder that native evidence is not a helper receipt; it also finds the reviewer CLIs in documented install locations and lints review packets for run evidence and the exact HEAD. See [review helper reliability](docs/operations.md#review-helper-reliability).

A command guard (`command_guard.py`, behind the fail-closed launcher `command_guard_hook.py`) blocks shell commands that delete, move or empty Claude, Codex and harness logs and state, or that print secrets and configuration (for example `rclone config show`), in both editions; deletes of logs need a verified Dropbox backup and a single-use `approve-delete`. See [command guard](docs/operations.md#command-guard).

Both editions also gate PR merges: a PreToolUse hook (`merge_gate.py`) blocks `gh pr merge`, `gh api` merge calls (REST and GraphQL) and wrapped forms unless every required and reported check on the exact head SHA is green, the merge command carries that head SHA, and the check state could be read; the only override is a recorded single-use waiver. See [merge gate](docs/operations.md#merge-gate).

Work is spec-driven. Each ticket gets a spec with `AC-n` acceptance criteria and negative cases, reviewed adversarially and for acceptance by two different models, agents or people. The spec and its reviews are attached to the ticket. Proof for each criterion (a `REALLY_TESTED` WAL entry, commits and redacted logs) and the click-tester's identity, time window and logs are attached as the work proceeds. `spec_flow.py done` marks a ticket done only when every criterion has evidence, both reviews accepted the current spec, the click-test passed and someone independent signed off. Otherwise it lists what is missing. A Claude Code PreToolUse hook applies the same gate to GoodQA status changes; on Codex and Cursor the check is run by hand. It ships in warn mode. See [spec-driven tickets](docs/operations.md#spec-driven-tickets).

When a repo shows blockchain work (Solidity, Foundry, Hardhat, Anchor, Substrate, XRPL, ledger over NATS), specs and review prompts also carry a risk checklist, test scaffolds and follow-up prompts; see [blockchain domain gates](docs/operations.md#blockchain-domain-gates).

Both editions also install the opt-in `usage_guard.py` for finite command receipts, resource checks, full-run gates and advisory reuse. PLAN and CODE_INSPECTION are separate from PR signoff. The review helper validates structured provider errors before verdict text, caps provider launches, warns on large packets and shares cooldowns only among callers using the same private state directory and opaque provider/auth-pool alias. It does not intercept arbitrary shell/native model calls or enforce distributed account budgets. Missing final receipts remain unknown; reconciliation appends evidence rather than inventing success. Tiny reversible fixes keep the direct fast path. See [usage guard operations](docs/operations.md#usage-guard) for declarations, commands and limits.

The helpers are not a sandbox for repository code, tests, hooks or merge drivers. The main agent must invoke them and inspect the evidence. A tracked Codex checkpoint can request one continuation, while verification remains the main agent’s responsibility. The dependency-free watcher provides a usable test loop in either edition.

## Evidence and limits

[Validation notes](docs/validation.md) distinguish automated helper tests, prior nine-app exercise, and untested scenarios. A hook cannot prove that a test was meaningful, that a review was independent, or that a UI was clicked. The main agent must inspect the evidence. Agents should not create production accounts or publish secrets; disposable accounts belong only in owned local or staging environments.

This repository contains no account credentials, session logs, app fixtures, or machine-specific settings. The MIT license covers this harness; model and CLI products retain their own terms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs should include a reproducible failure, the affected agent edition and version, and evidence that a fix works without breaking the fast path or local delivery.
