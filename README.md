# Agent Harness for Claude Code

A user-wide Claude Code workflow for parallel software tasks with recoverable work, independent review, live testing, and local delivery. It is opinionated instruction text plus small Python helpers. It is **not** a daemon, scheduler, CI service, or guarantee that an agent will obey every instruction. The hooks enforce WAL metadata before matched write tools; the remaining process gates require the main agent to follow the instructions and report evidence.

## What it does

- Sends small, reversible fixes through a fast path. Substantive work gets one background task owner per related scope, an isolated Git worktree, a scope brief, a decision log, and periodic user updates.
- Creates private per-session and per-agent write-ahead logs under `~/.claude/wals`. Hook records contain timestamps, tool names and hashes, not prompt text or tool arguments. Agents add human-readable intent, decisions, evidence and handoffs.
- Runs a read-only Codex Sol review of the plan and final PR packet. If Codex is unavailable, a fresh Claude Opus review is attempted. Repeated material blockers can be escalated by the main agent to Astra, then Fable if Astra fails before editing.
- Requires relevant failure-first tests, adversarial review, and a real click/API pass for runnable work before the main agent accepts it. Test depth follows risk; statistical eval gates apply to stochastic systems, not every bug fix.
- Publishes a verified feature branch to `origin` when possible, then guardedly merges into the user's original checkout after approved checks. A remote outage is reported and does not prevent local delivery.
- Includes a dependency-free test watcher and asks for an immediately usable run/test/watch/log/stop handoff.

The detailed policy is in [HARNESS.md](HARNESS.md); agent roles are in [harness/agents](harness/agents), and the small CLI helpers are in [harness/hooks](harness/hooks).

## Install

Requirements: Claude Code **2.1.295+**, Python **3.10+**, Git, macOS or Linux. Codex CLI and access to `gpt-6.1-sol`/`gpt-6-astra` enable the preferred review path. Claude Opus and Fable access enable the fallbacks. Review and rescue calls can incur model charges. Windows behavior has not been tested.

```sh
git clone https://github.com/ericmacdougall/agent-harness.git
cd agent-harness
python3 install.py           # preview
python3 install.py --apply   # install
python3 -m unittest discover -s tests -v
```

The installer copies the agents and helpers into `~/.claude`, places a marked block in `~/.claude/CLAUDE.md`, and **merges** its hooks and three narrow helper permission rules into `settings.json`. Existing model, theme, deny rules, and unrelated hooks are preserved. It backs up files it replaces under `~/.claude/agent-harness-backups`. It validates payloads before writing and attempts to restore replaced files if a write fails; an incomplete rollback reports the affected paths and backup location. Crash recovery still requires the backups. The installer does not enable dangerous permission bypass or set a model. Inspect the preview and start a **new Claude Code session** after installation.

Claude Code's `--safe-mode` disables `CLAUDE.md` and hooks, including the WAL gate. Use a normal session when relying on harness enforcement.

To uninstall, remove the marked block from `CLAUDE.md`, remove the four hook entries pointing at `~/.claude/hooks/wal.py` and the three harness permission rules from `settings.json`, then remove the copied agents and helper scripts. Restore a backup if you want the exact earlier state.

## Operating model

1. The main agent records the initial checkout, scopes the request, asks about consequential ambiguity, and assigns one owner to each nonoverlapping task. Related follow-ups go to the same owner.
2. The owner writes WAL intent and a risk table, asks Sol to challenge the plan, implements and commits small recoverable increments, then supplies a self-contained final review packet.
3. An independent reviewer and click tester inspect the actual branch. The owner or fixer addresses findings and retests. The main agent checks scope, test quality, final HEAD and documentation.
4. The main agent attempts a feature branch push and PR, then merges a verified commit into the recorded local checkout. If publication fails, local work continues and the user receives the remote error.

The `publish_feature.py` helper never force-pushes or pushes the original branch. The `integrate_local.py` helper checks expected source and destination commits, requires a clean checkout, runs allowlisted dependency preparation and checks, and aborts failed merges. See [docs/operations.md](docs/operations.md) for exact commands and limits.

## Evidence and limits

[Validation notes](docs/validation.md) distinguish automated helper tests, prior nine-app exercise, and untested scenarios. A hook cannot prove that a test was meaningful, that a review was independent, or that a UI was clicked. The main agent must inspect the evidence. Agents should not create production accounts or publish secrets; disposable accounts belong only in owned local or staging environments.

This repository contains no account credentials, session logs, app fixtures, or machine-specific settings. The MIT license covers this harness; model and CLI products retain their own terms.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs should include a reproducible failure, the affected Claude Code version, and evidence that a fix works without breaking the fast path or local delivery.
