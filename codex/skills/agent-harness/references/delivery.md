# Delivery and handoff

Main first checks scope, exact reviewed HEAD, actual tests/live evidence, reviewer findings and affected docs. Preserve a changed original checkout; ask about a consequential conflict without resetting it. Fast-path fixes still finish directly.

Use `python3 ~/.codex/agent-harness/deliver.py`. It and its Git/process dependencies are installed independently of Claude. Write a private mode-0600 JSON run kit with useful `run`, `test`, `watch`, and relevant `logs`/`stop` instructions, and a private reviewed PR body without secrets. Verify the commands. Keep the original path, branch and captured HEAD in the owner ledger.

```sh
python3 ~/.codex/agent-harness/deliver.py prepare --task OWNER_TASK --source /absolute/feature --original /absolute/original --original-branch main --expected-source-head FULL_REVIEWED_SHA --expected-original-head FULL_CAPTURED_SHA --kit-file /private/kit.json --pr-title 'Reviewed scope' --pr-body-file /private/pr-body.md
```

Prepare verifies matching supported GitHub identities before pushing the exact feature commit and creating/reusing the matching draft PR. Save its generation and state path. `PR_READY` leaves the original checkout unchanged pending repository review and authorized remote merge. The helper never merges a remote PR. After that merge:

```sh
python3 ~/.codex/agent-harness/deliver.py finish --task OWNER_TASK --generation GENERATION --original /absolute/original --original-branch main --mode remote --check 'python3 -m unittest discover -s tests -v'
```

Finish verifies PR identity, fetches a pinned target through isolated transport, uses hook-disabled protected fast-forward with overwrite/autostash protection, and checks the actual original before a durable delivery receipt. Select the repository's real approved checks; repeat `--check`, or use an approved lockfile preparation with `--prepare` when needed.

A definite `REMOTE_BLOCKED` permits `finish --mode local`; explicit local-only work starts with `prepare --local-only` then local finish. Local delivery requires worktrees sharing Git metadata and leaves publication outstanding. Policy refusals and `REMOTE_UNCERTAIN` do not authorize fallback. Continue independent feature work while blocked, report the safe error and avoid credential loops or another remote. Query-only `prepare --reconcile-only --task OWNER_TASK --original /absolute/original --original-branch main` settles an uncertain exact remote outcome without publishing, creating a PR or changing the checkout. A new reviewed source/run kit requires `--new-generation` after the old generation is settled; stale generations cannot mutate the current task.

Local and remote applies share original-scope recovery barriers under the Git common directory, independent of HOME/session. Failed applies preserve refs and journals and report observed HEAD. Use `integrate_local.py --resolve-journal KEY` only for a confirmed clean tested baseline; `RESOLVED` does not prove delivery. After all actual barriers are resolved, an unbound interrupted workflow can use `finish --resolve-baseline FULL_CONFIRMED_SHA --task OWNER_TASK --original /absolute/original --original-branch main --check '<real-check>'`; `RESOLVED_BASELINE` requires a new generation and fresh delivery proofs. Never infer a failed child succeeded. An `ALREADY_DELIVERED` repeat proves historical target ancestry in the current clean original; it does not sync newer remote work. Deliberately reconcile later remote history after local delivery.

The handoff names original checkout/current HEAD and delivered commit, or the ready feature checkout/commit and specific blocker. Provide a working start/preview URL or CLI/API sample, safe seed/test-account setup, exact test/watch commands, results/log location and stop command. For repos without a watcher, verify `python3 ~/.codex/agent-harness/watch-tests.py --root <checkout> --once -- <test-command>`, then omit `--once` for continuous watching; Ctrl-C stops it. Never invent a UI or an unused service. Tell dependent owners their new base after integration.

Update affected README, architecture/how-it-works, contributing/standards, ERD, service/deployment, OpenAPI/MCP and developer/customer docs with verified facts. Skip irrelevant boilerplate. Record source/date/confidence for unstable external facts and redact private data. The helper cannot judge whether run instructions are useful or an agent followed review policy; main must inspect proof. No global Stop hook blocks ordinary progress or substitutes for compliance.
