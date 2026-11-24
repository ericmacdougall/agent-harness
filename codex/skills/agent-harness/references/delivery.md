# Delivery and handoff

Main first checks scope, exact reviewed HEAD, actual tests/live evidence, reviewer findings and affected docs. Preserve a changed original checkout; ask about a consequential conflict without resetting it. Fast-path fixes still finish directly.

Use `python3 ~/.codex/agent-harness/deliver.py`. It and its Git/process dependencies are installed independently of Claude. In a durable private directory such as `~/.agent-harness/work/<task-or-thread>/` (never `/tmp`, which a reboot wipes before a later resume needs the same kit), write a private mode-0600 JSON run kit with useful `run`, `test`, `watch`, and relevant `logs`/`stop` instructions, and a private reviewed PR body without secrets. Verify the commands. Keep the original path, branch and captured HEAD in the owner ledger.

```sh
python3 ~/.codex/agent-harness/deliver.py prepare --task OWNER_TASK --source /absolute/feature --original /absolute/original --original-branch main --expected-source-head FULL_REVIEWED_SHA --expected-original-head FULL_CAPTURED_SHA --kit-file ~/.agent-harness/work/TASK/kit.json --pr-title 'Reviewed scope' --pr-body-file ~/.agent-harness/work/TASK/pr-body.md
```

Prepare verifies matching supported GitHub identities before pushing the exact feature commit and creating/reusing the matching draft PR. Save its generation and state path. `PR_READY` leaves the original checkout unchanged pending repository review and authorized remote merge. The helper never merges a remote PR. After that merge:

```sh
python3 ~/.codex/agent-harness/deliver.py finish --task OWNER_TASK --generation GENERATION --original /absolute/original --original-branch main --mode remote --check 'python3 -m unittest discover -s tests -v'
```

Finish verifies PR identity, fetches a pinned target through isolated transport with maintenance/commit-graph writes disabled and negotiation tips for available original/source history, uses hook-disabled protected fast-forward with overwrite/autostash protection, and checks the actual original before a durable delivery receipt. Once the exact PR is proved merged, its feature worktree may be removed or reused. If main advances concurrently, the helper fetches that observed tip only to prove ancestry, still delivers the pinned tested target, and reports `remote_observed_head`. A non-descendant tip keeps recovery blocked. Select the repository's real approved checks; repeat `--check`, or use an approved lockfile preparation with `--prepare` when needed.

A definite `REMOTE_BLOCKED` permits `finish --mode local`; explicit local-only work starts with `prepare --local-only` then local finish. Local delivery requires worktrees sharing Git metadata and leaves publication outstanding. Policy refusals and `REMOTE_UNCERTAIN` do not authorize fallback. Continue independent feature work while blocked, report the safe error and avoid credential loops or another remote. Query-only `prepare --reconcile-only --task OWNER_TASK --original /absolute/original --original-branch main` settles an uncertain exact remote outcome without publishing, creating a PR or changing the checkout. Temporary absence cannot settle a possible push/create. A possible create requires positive matching PR evidence; only durably known pre-create stages can settle an absent PR. Definite publisher preflight failure before any push permits fallback; a rejected push or bounded/invalid owned listing settles `POLICY_BLOCKED`, allowing a new reviewed generation without local fallback. Unrelated fork PRs sharing a branch name are ignored. A new reviewed source/run kit requires `--new-generation` after the old generation is settled; stale generations cannot mutate the current task.

An existing generation stuck specifically in `PUBLISHING` can explicitly
reauthorize its identical publication with `prepare --resume-publication
--resume-reason "why this same write is authorized" --generation GENERATION`,
alongside all original prepare arguments, expected source/original HEADs and the
same run kit. This is a write operation. The flag cannot change generation,
source, branch, repository or kit, and cannot combine with reconciliation-only
or local-only modes. A matching remote commit reconciles without another push;
a different commit or failed lookup refuses. A confirmed absent ref permits
one audited retry of the same ordinary nonforce pinned push. Absence never
proves the first request failed or that its publisher is dead. A late original
request can still complete the identical write; a newer/divergent remote ref
cannot be overwritten by force. Ordinary Git may fast-forward a concurrently
created ancestor ref, preserving its history; this is not atomic create-only.

Each attempt records a private `publication-resume-*.json` beside the generation
journal with its reason and frozen scope. Known publishers retain an inherited
generation lease through their native process lifetime, so a busy lease refuses
another attempt even after its coordinator exits. The lease does not prove all
descendants or server requests ended. Legacy generations lacking that lease
can use the explicit identical-write authorization without inventing liveness
or failure evidence. Retry errors remain uncertain and never create a local
fallback merely because the latest attempt did not push. Inspect the exact
remote result and generation before another explicit attempt. This flag never
retries `PR_CREATING` or `REMOTE_UNCERTAIN`: uncertain PR creation still requires
positive matching-PR reconciliation.

Local and remote applies share original-scope recovery barriers under the Git common directory, independent of HOME/session. Failed applies preserve refs and journals and report observed HEAD. Only explicit typed proof that no own reservation began permits a same-generation pre-apply retry; missing journals alone prove nothing. Fresh generations can retry an older resolved local tuple while retaining its history. Use `integrate_local.py --resolve-journal KEY` only for a confirmed clean tested baseline; `RESOLVED` does not prove delivery. After all actual barriers are resolved, an unbound interrupted workflow can use `finish --resolve-baseline FULL_CONFIRMED_SHA --task OWNER_TASK --original /absolute/original --original-branch main --check '<real-check>'`; `RESOLVED_BASELINE` requires a new generation and fresh delivery proofs. Never infer a failed child succeeded. An `ALREADY_DELIVERED` repeat proves historical target ancestry in the current clean original; it does not sync newer remote work. Deliberately reconcile later remote history after local delivery.

The handoff names original checkout/current HEAD and delivered commit, or the ready feature checkout/commit and specific blocker. Provide a working start/preview URL or CLI/API sample, safe seed/test-account setup, exact test/watch commands, results/log location and stop command. For repos without a watcher, verify `python3 ~/.codex/agent-harness/watch-tests.py --root <checkout> --once -- <test-command>`, then omit `--once` for continuous watching; Ctrl-C stops it. Never invent a UI or an unused service. Tell dependent owners their new base after integration.

Update affected README, architecture/how-it-works, contributing/standards, ERD, service/deployment, OpenAPI/MCP and developer/customer docs with verified facts. Skip irrelevant boilerplate. Record source/date/confidence for unstable external facts and redact private data. The helper cannot judge whether run instructions are useful or an agent followed review policy; main must inspect proof. The continuation checkpoint records workflow state without attesting to proof.

For substantive work, run `python3 ~/.codex/agent-harness/wal.py continuation --wal <main-WAL> active` before dispatch. The installed Codex Stop hook allows one automatic continuation per session by default. For authorized autonomous work, set a total budget from one to four with `active --max-continuations 4` before the first pass. A configured budget is fixed for the session. Generated prompts and checkpoint status changes preserve the budget and spent passes. Use `status` to inspect the limit and remaining passes. An active checkpoint remains visible after its passes run out. Quick work has no checkpoint to arm.

Codex marks a continuation with `stop_hook_active` on the same native turn. With an explicit budget, that follow-up can spend another pass only after this checkpoint continued that turn and Codex supplies a different assistant response. The checkpoint saves bounded digests for deduplication. Response text stays in hook input, and the digests grant no authority or proof of progress. [Native Codex repeat Stop test](https://github.com/openai/codex/blob/d2c035639366e0bf2c316aa2065c24aabc12bcdc/codex-rs/core/tests/suite/hooks.rs#L1302-L1393)

On a user interrupt, the hook pauses the checkpoint and preserves its remaining passes. For an explicit pause request in chat, set `paused` before yielding. Resume with `active` when authorized. The marker for the latest interrupt also fences delayed callbacks from its turn when Codex supplied a valid turn ID. Use `blocked` when an external condition prevents further progress. The hook can continue an active Codex workflow at a Stop event. An idle chat requires a separate wake.

Before setting `complete`, verify the requested outcome and record exact source and evidence in the WAL. For `blocked`, record the concrete external condition and finish independent authorized work. For `handoff`, record and verify who or what will pick up the work, how it will wake, and what it checks next. A background job alone does not establish a handoff. The hook does not inspect transcripts, supervise detached jobs, bypass approval, or guarantee runtime delivery when hooks are unavailable or untrusted.

The local Stop decision is made at its final interrupt-marker read, after durably spending the allowance. Codex owns cancellation of a live turn. A later interrupt can mark the checkpoint paused for subsequent checks, but the hook cannot retract an already issued response or provide a hard-cancel guarantee if the client dies abruptly. Hook protocol tests exercise the durable pause and lock contention. They do not establish native Codex interrupt/Stop ordering.

## Commit policy at delivery

- `deliver.py prepare` checks only when it creates a new generation. It checks the owner's commits (head minus baseline minus `origin/<remote-branch>`, the remote base: see below), the PR title and body, and ticket freshness.
  - `BLOCKED_COMMIT_POLICY` (exit 2) means you should fix the commits, the PR text or the ticket comments and re-run.
  - `TICKETS_UNVERIFIED` (exit 6) means GoodQA was unreachable. Retry, or record a `tickets` waiver for that head.
  - Neither result creates state.
- `deliver.py finish` comments on each referenced ticket with the stage (merged or local only), the delivered SHA and the checks.
  - Exit 5 means the delivery succeeded but a ticket comment is pending. Re-run finish, which is idempotent. Do not start recovery.
- After a deploy, post evidence with `commit_policy.py notify --stage deployed`.

## Remote base branch and scoped Go checks

- `--remote-branch <name>` (on `prepare` and `finish`) names the branch on `origin` that PRs target and finish applies, when it is not named like `--original-branch` (for example local `main` delivering to `release/owned-sandbox`). Resolution order: the flag, then the original branch's configured `origin` upstream (`branch.<b>.remote`/`.merge`), then the local branch name. A prepared generation keeps the base it was prepared against (a stored value wins over a changed upstream, and `finish` needs no flag); a different explicit `--remote-branch` is refused with `BLOCKED_POLICY` reason `REMOTE_BRANCH_MISMATCH`, and a source branch equal to the base is refused (`SOURCE_IS_BASE`). Output (`PR_READY`, `LOCAL_READY`) reports `remote_branch` and `remote_branch_source` (`flag`, `upstream`, `local`, or `prepared` on resume); a base taken from the upstream also prints a warning. Pinned merged commit, ancestry, clean-checkout and journaled-apply checks are unchanged.
- `approved_check` also accepts scoped `go vet <pkg...>` and `go test [-race|-count=1|-v] <pkg...>`, where each package is a relative `./` pattern (`./pkg`, `./pkg/...`, `./...`) made of `[A-Za-z0-9_][A-Za-z0-9_.-]*` segments; flags after packages, other flags, absolute, `..` or shell-metacharacter patterns are refused. A fleet `testrun` receipt is not accepted in place of a check.
