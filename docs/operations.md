# Operations and safety boundaries

## Components

| Component | Role |
| --- | --- |
| `HARNESS.md` | User-wide workflow instructions installed as a marked block in `CLAUDE.md`. |
| `harness/agents/*.md` | Task owner, click tester, fixer and red-team roles. |
| `wal.py`, `wal_note.py` | Private metadata and human-readable WAL entries. |
| `peer_review.py` | Read-only Sol plan/PR review with blind Opus fallback. |
| `rescue.py` | Main-approved Astra rescue with Fable fallback on a clean worktree. |
| `publish_feature.py` | Guarded feature branch push to `origin`. |
| `integrate_local.py` | Guarded local merge into the starting checkout. |
| `watch-tests.py` | Polling test runner for source edits. |

No background process is installed. Claude Code runs hooks, and the main agent invokes the other helpers when appropriate.

## WAL behavior

The `SessionStart` hook creates a private session log. `UserPromptSubmit` logs the prompt length and SHA-256 digest but not its text. `SubagentStart` creates a separate agent log. `PreToolUse` logs metadata before matched write-capable tools. Prompt and pretool hooks use `onFailure: block`; this is a safety gate, so a broken hook can stop those actions. Agents add semantic entries with:

```sh
python3 ~/.claude/hooks/wal_note.py --wal ~/.claude/wals/SESSION_ID/main.jsonl --event intent --note 'Brief intent without secrets'
```

WALs may still contain sensitive information if an agent writes it despite the policy. Keep `~/.claude/wals` private, review it before sharing, and do not commit it.

## Review and rescue

```sh
python3 ~/.claude/hooks/peer_review.py plan --repo /absolute/worktree --packet /absolute/plan.md --output /absolute/plan-review.md
python3 ~/.claude/hooks/peer_review.py pr --repo /absolute/worktree --packet /absolute/pr-packet.md --output /absolute/pr-review.md
```

Exit 0 means a reviewer returned PASS, 3 means BLOCK, and 2 means no valid review. The reviewer reads the packet and repository. Do not include secrets or personal data in either. A PASS is advisory evidence, not proof that checks were run or that every defect was found.

The main agent can invoke `rescue.py` after repeated material findings, only in a clean rescue worktree and with a self-contained packet. A successful rescue still needs main-agent verification and final review.

## Publication and local integration

```sh
python3 ~/.claude/hooks/publish_feature.py --repo /absolute/feature-worktree --branch feat/example --original-branch main --expected-head FULL_FEATURE_SHA
python3 ~/.claude/hooks/integrate_local.py --repo /absolute/original-checkout --original-branch main --expected-head FULL_ORIGINAL_SHA --source feat/example --expected-source-head FULL_FEATURE_SHA --check 'python3 -m unittest discover -s tests -v'
```

The publication helper pushes only `refs/heads/feat/example` to the same ref on `origin`; it does not create a PR. The main agent creates or updates the PR separately when available. On missing/auth-failed remote, the helper returns `BLOCKED_REMOTE` (exit 4); continue local verification and integration.

The integration helper allows a small fixed set of test/build commands and lockfile installs, parsed as argv without a shell. It merges into a clean, unchanged original checkout and aborts on conflict or failing checks. It does **not** validate reviewer reports or decide whether a check command is sufficient; that belongs to the main agent. It does not push the original branch. If the original checkout is dirty or changed, preserve it and resolve the conflict with the user.

## Test watcher

```sh
python3 ~/.claude/tools/watch-tests.py --root /absolute/checkout --once -- python3 -m unittest discover -s tests -v
python3 ~/.claude/tools/watch-tests.py --root /absolute/checkout -- python3 -m unittest discover -s tests -v
```

The watcher polls common source extensions. It is a local convenience, not CI. Stop the second command with Ctrl-C.

## Design limits

The policy is intentionally risk-scaled. The small fix path skips worktrees and review loops. A normal code task gets only relevant tests and documents. The agents must not infer that the presence of a test or a reviewer PASS proves quality. Independent checks, reviewer availability, UI tool access and remote permissions vary by environment; handoffs must say exactly what ran and what did not.

Claude Code settings can change between versions. The hook structure follows the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks), and worktree agents follow the [subagent](https://code.claude.com/docs/en/sub-agents) and [worktree](https://code.claude.com/docs/en/worktrees) guides. Check these references when upgrading Claude Code.
