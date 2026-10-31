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

## Capabilities by edition

| | Claude Code | Codex |
| --- | --- | --- |
| Guidance and roles | `~/.claude/CLAUDE.md` and four task roles | `~/.codex/AGENTS.md`, one skill, and six custom roles |
| Private WAL | `~/.claude/wals`; matched write-tool hooks can block on WAL failure | `~/.agent-harness/codex-wals`; hooks record supported lifecycle and tool metadata after trust |
| Review | Claude helper calls Codex Sol when available, with a Claude Opus fallback | Native subagents use the reviewer role; rescue is available for repeated blockers |
| Delivery | Installed `publish_feature.py`, `integrate_local.py`, and `watch-tests.py` helpers | Main agent uses native tools and Git to publish and integrate; no Claude delivery helpers are installed |

Both editions send small, reversible fixes through a fast path. Substantive work gets an owner per related scope, a separate worktree, semantic WAL notes, relevant failure-first tests, independent review, and live UI/API checks when applicable. Hook records omit prompt text and tool arguments; the main agent still has to inspect evidence. Publication failures do not prevent verified local delivery. Claude's detailed policy is in [HARNESS.md](HARNESS.md), with roles in [harness/agents](harness/agents) and helpers in [harness/hooks](harness/hooks). Codex's workflow is in its [skill](codex/skills/agent-harness/SKILL.md).

## Claude Code install details

Codex CLI and access to `gpt-6.1-sol`/`gpt-6-astra` enable the preferred Claude review path. Claude Opus and Fable access enable fallbacks. Review and rescue calls can incur model charges.

The installer copies the agents and helpers into `~/.claude`, places a marked block in `~/.claude/CLAUDE.md`, and **merges** its hooks and three narrow helper permission rules into `settings.json`. Existing model, theme, deny rules, and unrelated hooks are preserved. It backs up files it replaces under `~/.claude/agent-harness-backups`. It validates payloads before writing and attempts to restore replaced files if a write fails; an incomplete rollback reports the affected paths and backup location. Crash recovery still requires the backups. The installer does not enable dangerous permission bypass or set a model. Inspect the preview and start a **new Claude Code session** after installation.

Claude Code's `--safe-mode` disables `CLAUDE.md` and hooks, including the WAL gate. Use a normal session when relying on harness enforcement.

To uninstall, remove the marked block from `CLAUDE.md`, remove the four hook entries pointing at `~/.claude/hooks/wal.py` and the three harness permission rules from `settings.json`, then remove the copied agents and helper scripts. Restore a backup if you want the exact earlier state.

## Operating model

1. The main agent records the initial checkout, scopes the request, asks about consequential ambiguity, and assigns one owner to each nonoverlapping task. Related follow-ups go to the same owner.
2. The owner writes WAL intent and a risk table, asks Sol to challenge the plan, implements and commits small recoverable increments, then supplies a self-contained final review packet.
3. An independent reviewer and click tester inspect the actual branch. The owner or fixer addresses findings and retests. The main agent checks scope, test quality, final HEAD and documentation.
4. The main agent attempts a feature branch push and PR, then merges a verified commit into the recorded local checkout. If publication fails, local work continues and the user receives the remote error.

For Claude Code, the `publish_feature.py` helper never force-pushes or pushes the original branch. The `integrate_local.py` helper checks expected source and destination commits, requires a clean checkout, runs allowlisted dependency preparation and checks, and aborts failed merges when source Git state can be verified safe for an automatic abort. See [docs/operations.md](docs/operations.md) for exact commands and limits. Codex uses its [native delivery workflow](codex/skills/agent-harness/references/delivery.md).

## Evidence and limits

[Validation notes](docs/validation.md) distinguish automated helper tests, prior nine-app exercise, and untested scenarios. A hook cannot prove that a test was meaningful, that a review was independent, or that a UI was clicked. The main agent must inspect the evidence. Agents should not create production accounts or publish secrets; disposable accounts belong only in owned local or staging environments.

This repository contains no account credentials, session logs, app fixtures, or machine-specific settings. The MIT license covers this harness; model and CLI products retain their own terms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs should include a reproducible failure, the affected agent edition and version, and evidence that a fix works without breaking the fast path or local delivery.
