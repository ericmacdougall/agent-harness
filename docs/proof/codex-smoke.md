# Codex-native live smoke, 2026-10-30

Environment: macOS, Codex CLI 0.164.0-alpha.11.1, Python 3.15.0, and a disposable one-page Git fixture. This proof is about observed behavior in this environment. It does not prove that a model will follow every instruction in future sessions.

## Fast path

A project-level adaptation of the global guidance and skill was loaded in a disposable checkout. A real `codex exec` corrected one character in a heading, inspected its diff, and ran a focused check. The JSON event stream contained zero subagent starts. Because the user-wide Codex installation was absent at this point, that run used a temporary manual note and does not prove installed hook coverage.

## Substantive path

An initial `codex exec --ephemeral` run attempted an owner handoff but the CLI could not create a subagent thread record. The agent continued locally; this is why the Codex setup guide cautions against ephemeral mode for delegated work.

The persistent-session rerun used the new permission profile through a trusted fixture project. It wrote redacted semantic notes to a private per-session WAL, started owner and reviewer subagents, created an isolated feature worktree, and committed the page feature and a focused test in two recoverable commits. The main agent reported scope and progress, obtained independent diff and red-team reviews, and integrated the result into the original fixture checkout. The focused Node check passed nine theme, preference, and storage cases. The baseline and a deliberately broken toggle failed that check. No remote was configured; the agent reported that and completed local delivery.

The CLI process could not bind a local server or use its browser tools, so it accurately reported live browser behavior as unverified. Separately, the main Codex app served that same fixture and opened it in its in-app browser. The accessibility state showed the dark-mode control move from unchecked to checked after a click, remain checked after reload, and return to unchecked after Tab and Space. Screenshots showed the dark and light surfaces and a visible focus ring. The temporary browser tab and server were closed.

## Installed disposable-home and sandbox check

`install_codex.py --apply --home <disposable-home>` produced all managed files. With `CODEX_HOME` pointed at that installed directory, `codex debug prompt-input` exited 0 and its model-visible prompt contained the global Agent Harness policy, skill name, owner role, and permission profile. `codex sandbox -P agent-harness` permitted a write inside the private WAL directory and `git init` in the fixture workspace. A probe write to an unrelated protected user Codex directory failed with `Operation not permitted`. No user-wide installation or hook trust was changed by this disposable test.

Synthetic installer and WAL tests cover idempotence, other users' settings, failure rollback, concurrency, malformed tails, and prompt/argument privacy. See the current suite and review outcomes in [validation](../validation.md). Hooks still require a separate `/hooks` trust review after user-wide installation; the CLI live fixture used a bypass only for the locally reviewed test hook definition.

## User-wide installed smoke

After the repaired code passed local tests and hosted CI, the installer applied the same source under the user's `~/.codex`. All 11 copied role, skill, and WAL payloads matched the repository byte-for-byte. The merged config selected the `agent-harness` workspace profile, four managed hook commands appeared exactly once, and the private WAL directory was mode `0700`. `codex doctor --summary --no-color` exited 0 with config, authentication, and sandbox checks passing; it reported optional MCP and terminal/desktop environment warnings, with no failed checks.

The CLI's `/hooks` browser showed four new user hooks needing review. After inspecting the installed command and source, the current definitions were trusted there; the event list then showed them active. A fresh ordinary `codex --ask-for-approval never exec --skip-git-repo-check --json -C /private/tmp 'Reply READY. Do not edit files or call tools.'` exited 0 and returned `READY.` without the hook-trust bypass. Its session-specific private WAL contained `SessionStart` and `UserPromptSubmit` records and was mode `0600`. This verifies installed hook discovery and trust for that fresh session; it does not prove every future tool path is intercepted or every model follows the semantic-note guidance.
