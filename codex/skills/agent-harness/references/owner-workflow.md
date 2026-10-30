# Owner workflow

## Scope and plan

The main agent gives one owner a branch and isolated Git worktree for a coherent feature. Keep vendor directories, virtual environments, build output, credentials, and caches out of copies and commits. Use shared package-manager content caches; install from the lockfile in the worktree when needed. Reuse the owner for related follow-ups. The owner records a WAL intent, assumptions, risk table, planned checks, and rollback before editing.

For the plan review, give `harness_reviewer` the brief, relevant repo paths, proposed design, negative cases, and an exact question. Ask it to challenge scope, failure modes, and unsafe assumptions, then reconcile findings. A second cooperative round is useful for disputed architecture. Do not loop on the same unchanged packet. If the only gap is missing live evidence, obtain it instead of asking the reviewer again.

## Implementation and handoff

Commit recoverable increments on the feature branch. Keep the WAL current with decisions, commands/results, review findings, commits, and next steps; omit private values. For behavior claims, note `PENDING_REAL_TEST <id>` before editing and `REALLY_TESTED <id>` only after observing the named check. At handoff, list unmatched IDs and their effect on readiness.

Prepare a self-contained PR packet: scope; base and exact HEAD; changed interfaces; commands, toolchain, exit codes, nonzero case counts and concise failure-first evidence; live steps and results; migration/rollback; risks; documentation; and readable log paths. The reviewer must inspect the actual diff and identify the reviewed commit. If using the installed `peer_review.py` helper for a PR gate, pass `--expected-head <full-committed-HEAD>` from a clean worktree. Refresh the packet and rerun affected checks when HEAD changes. The owner proposes only documentation changes supported by inspected facts.

If two real repair rounds fail on the same material finding, main may pause the owner and assign `harness_rescue` a fresh worktree from a clean committed branch. Give it the failing review, exact acceptance check, and remaining scope. Main inspects any rescue commit, reruns affected checks, obtains a fresh review, and keeps the user updated. Use an available independent model fallback only before rescue edits; do not have two agents edit the same checkout.
