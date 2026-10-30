---
name: agent-harness
description: Coordinate and verify substantive software builds or changes with scoped ownership, WALs, independent review, live testing, and local delivery. Skip for quick localized fixes and non-code answers.
---

# Substantive software work

Use native Codex subagents when available. The main agent remains accountable for scope, integration, proof, and the user-facing result. Work with the user's sparse request as a starting point, not a complete product specification. Keep the smallest viable scope that achieves the intended outcome, while covering material security, reliability, accessibility, migration, and operations risks. Push back on a shortcut that would break an essential invariant. Ask the user about consequential unresolved choices after checking the repo and available sources; record assumptions and decisions in the WAL.

## Scope and ownership

Before delegation, record the original checkout path, branch, HEAD, dirty state, and remote. Write a concise scope brief and owner ledger in the session WAL: outcome and flows; explicit requirements versus assumptions; interfaces and likely files; domain invariants and adversarial angles; acceptance and negative cases; owner, branch, worktree, dependencies, and next checkpoint. For related follow-ups, send the delta to the same owner. Use a separate owner only for genuinely independent work. Avoid overlapping edits. Keep the user informed at assignment, review, live test, blocker, and handoff.

Give the owner the scope brief and require it to challenge likely edge cases before implementation. See [owner-workflow.md](references/owner-workflow.md) for worktree, plan, commit, review, and rescue mechanics. A custom `harness_owner` agent is available; if native delegation is unavailable, follow the same workflow in the main thread and state that limitation.

## Plan, proof, and review

For nontrivial code changes, have an independent `harness_reviewer` (Sol) challenge the plan in a fresh context before implementation; reconcile concrete objections. If Sol is unavailable, use a fresh blind Opus CLI review when available, or disclose the missing independent review. The owner commits coherent increments and maintains its own WAL. Before PR readiness, use a fresh reviewer context to inspect the exact diff and self-contained evidence. Run a proportionate adversarial review with `harness_red_team`. A reviewer PASS is advisory, not a substitute for the main agent inspecting scope and tests. If the same material finding survives two genuine fix-and-review rounds, decide whether `harness_rescue` on a clean separate worktree is worth the cost; use a blind Fable fallback only if available and the rescue has not edited files. Keep the branch and reviewer reports recoverable.

Pick tests that could falsify the changed behavior. Demonstrate a failure against the prior implementation or a controlled broken variant where practical; require nonempty assertions and fixtures. Add deterministic edge cases, integration, contract, migration, and end-to-end checks as applicable. For a runnable UI or service, assign `harness_click_tester` before PR, use disposable local or staging accounts, route failures to the owner or `harness_fixer`, and retest. Use the [testing-and-evals.md](references/testing-and-evals.md) guide for delayed responses, chaos, stochastic systems, and production gates. Stop optional testing once the material risk is resolved; never call a simulation a live test.

## Delivery

The main agent checks the final branch HEAD, scope, tests, live evidence, independent findings, security, and affected docs. Attempt to push the verified feature branch and create or update a PR when a configured remote and account permit it. Do not force-push or switch remotes silently. If publication fails, report the error and continue local integration. Merge only into the recorded original checkout after checking its state; preserve user changes and resolve conflicts rather than resetting them. Tell dependent owners when to rebase. Give the user a usable start/preview command or URL, test/watch command, and stop/log path when relevant. See [delivery.md](references/delivery.md) for the handoff and documentation checklist.
