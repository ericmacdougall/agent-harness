# Claude Code shipping proposal

## Purpose

Optimize for **verified outcomes running in their intended environment**, not for the number of agents launched, reviews completed, branches pushed, or process artifacts produced. Claude Code main is the integrator and release owner, not a message relay between owners and reviewers.

This proposal operationalizes the November 7–8 reset. It does not weaken security, data-loss, provenance, exact-head evidence, or deployment checks. It removes duplicate work and gives every review and guard a stopping rule.

## 1. Work-in-progress limit

- At most **three product streams** are active. The reset order is GoodQA browser + lead gen, ParentProof 1.0.11, then Lessons. Agent Fabric is the single named migration exception while the approved Kimi-derived slices land. Everything else is paused with a ticket and next checkpoint.
- A stream is active from pickup until it is merged, deployed where applicable, independently live-checked, cleaned up, and its owner ledger is closed. Opening a PR does not free a slot.
- Do not create a new owner because a new message arrived. Resume the existing owner for related work. Before spawning, inspect the owner ledger, branches, worktrees, active agents, and existing PRs.
- Each stream has exactly one accountable owner, one branch, one integration target, and one next observable checkpoint. Competing implementations of the same problem are cancelled or compared once by main; they are not developed in parallel indefinitely.

### Stream card

Every active stream maintains this small durable record:

```text
Outcome and user-visible done state:
Owner / branch / worktree:
Target checkout, PR, and deployment:
Current stage: implementation | validation | review | merge | deploy | live-check
Next observable checkpoint and blocker:
Validation evidence and reviewed HEAD:
Rollback / feature flag:
Cleanup and ticket state:
```

Main updates this record at each transition. Status updates describe changed evidence, not repeated “still running” messages.

## 2. Definition of shipped

“Shipped” requires all applicable items:

1. The exact reviewed change is merged into the intended default branch.
2. The intended deployment is running that commit, or an explicitly documented next-installer artifact contains it.
3. An independent live check proves the user-facing outcome, including health and one meaningful flow. A local test, reviewer assertion, PR number, or HTTP 200 alone is not the outcome.
4. Rollback/feature-flag state and remaining risks are recorded.
5. Ticket, PR, owner ledger, and WAL name the actual commit and live evidence.
6. Temporary servers, emulators, test accounts, worktrees, review clones, and branches owned by the stream are cleaned up under the existing safety guards.

Anything earlier is `implementation`, `validation`, `PR_READY`, `merged`, or `deployed`—not shipped.

## 3. Review stopping rule

For each coherent change:

1. Run focused failure-first checks and the risk-appropriate regression suite.
2. Request **one independent adversarial review** against a frozen exact head.
3. Repair material findings and request **one delta review** limited to those findings and affected call sites.
4. After that delta, ship when validation and deployment gates pass.

- **Security and data-loss findings always block.** If one remains after the delta, narrow scope, roll back the risky part, or ask the user one focused question; never ticket it away.
- Other findings may become `TICKETED:` records only when the reviewer supplies the finding ID, category, and a related open non-duplicate GoodQA ticket. Related means a reviewed commit names the ticket in a `Follow-up: GoodQA <project>#<n>` line; a ticket the commits cite in `Refs:` is the branch's own work ticket and is refused. A finding whose text is about data loss, deletion, security, auth, credentials, tokens, privacy, permissions, injection, bypasses or migration/rollback stays BLOCK whatever category it is given. The report and FINAL receipt bind those records to the exact head. Mixed, unlabelled, stale, malformed, or unverified findings cannot become `PASS-WITH-TICKETS`.
- A fresh pure cross-harness PR PASS can authorize only its exact repository, PR, and head. Use `peer_review.py pr --github-repo <owner/repo> --pr <n>` with the normal exact-head arguments; a validated PASS creates the one-shot merge authorization after FINAL settlement. Same-harness, advisory, BLOCK, ticketed, stale, forged, unsettled, or wrong-head evidence does not authorize a merge.
- Do not invent another review round for taste, speculative refactors, or an unchanged packet. New scope or new evidence of security/data-loss risk is a new change, not permission for an endless loop on the old one.
- In `enforce` mode, an explicitly requested reviewer model/effort above the effective target is refused, not silently rewritten. The repository's current `warn` mode only reports that decision; do not describe it as enforcement. Select the intended rung or record the limitation before launch.

## 4. Right-size specs and evidence

- Ordinary specs keep independent adversarial and acceptance reviews.
- Use `Review-policy: single-adversarial (small: <auditable reason>)` only for a genuinely small change, or `single-adversarial (feature-flag: <flag and rollout evidence>)` for a properly gated change. Missing, ambiguous, or stale metadata returns to two reviews. The single reviewer must still be independent and adversarial. A spec that touches auth, login, credentials, tokens, sessions, permissions, security, encryption, privacy, data, databases, schemas, deletion, backup/restore or migration is refused single review at lint and attach, whatever its basis says.
- `kimi_review.py --mode spec-plan` may produce the constrained exact-packet plan artifact. Default Kimi output and legacy `KIMI_ADVISORY` reports remain advisory and cannot sign off a spec or PR.
- A real human turn containing `<pasted_content>` can be cited with its real `user:<session>/<uuid>` and verbatim excerpt. This proves the user supplied the text, not that the pasted report is correct. Agent, tool, system, fabricated, or cross-block text remains invalid.
- `git commit -F - <<'EOF'` is the supported one-command heredoc shape. The hook checks the actual message bytes, including Testing and ticket references. Dynamic substitution, unterminated heredocs, and same-command mutable-file races remain blocked.
- A small reversible fast-path change needs a short WAL intent/result and focused check, not a synthetic spec, worktree, two-model review, or PR bureaucracy.

## 5. Main’s job at each checkpoint

Claude Code main should spend most turns integrating and releasing:

- Choose the next shippable checkpoint and remove its blocker.
- Inspect the actual diff and evidence rather than relaying an owner’s summary.
- Merge when gates pass; do not wait for another reviewer merely because one is available.
- Deploy to the already authorized target, independently verify live behavior, and report the exact commit and result.
- Close the owner, delete merged branches, and remove owned temporary resources.
- Start the next stream only after a slot is genuinely free.

For UI/service work, use the owned real browser/staging path when available. If it is unavailable, record that limitation and use the smallest truthful alternative; do not claim a click-test that did not happen.

## 6. Resource and infrastructure gates

Before launching owners or heavy checks:

- Check disk, memory, load, active alerts, provider availability, and existing dev servers/emulators. Use current readings, not cached wallet/quota/disk claims.
- Keep the reset targets visible: Mac free-space target at least 60 GB, t2-dev cleanup target about 98 GB, active alerts below 20 actionable items, and a login-shell-independent release environment on the mini.
- Do not start a heavy build on a host below its configured floor. Clean owned artifacts first or move the job to the designated healthy host. Never delete unpushed or unique work to satisfy a disk target.
- Bind development servers to localhost by default. Track every spawned process with its owner, PID/start token, worktree, and stop command.
- On quota/auth failure, checkpoint durable state and stop the affected launch wave. Do not resume a dozen agents automatically after login; reconcile the three active streams first.
- New review/model spend must serve an active stream’s next checkpoint. No speculative swarm, broad mutation campaign, or duplicate architecture effort without a measured need.

## 7. Cleanup and branch hygiene

- `git worktree remove <path>` is allowed only for a clean, registered linked worktree whose exact HEAD is present on a live allowlisted remote. Dirty, unique untracked/ignored, unpublished, stale-remote, symlinked, forced, compound, nested, current, or primary-checkout cases remain blocked. The check runs before the command, so an ignored file (such as a new `.env`) written between the check and the removal is deleted: git refuses untracked files but not ignored ones. Stop anything still writing into the worktree before removing it.
- Main may stop its own processes with literal PIDs when the normal ownership proof passes. Local `netwatch orphans --kill --pid` now applies that proof; remote kills require the remote spawn ledger or the audited foreign route. Broad patterns, foreign PIDs, protected daemons, ancestors, and mixed owned/foreign lists remain blocked.
- Completed helper handoffs do not immediately trigger dropped-owner blocking. Main acknowledges consumed owner handoffs through the existing `ah` flow; genuinely unacknowledged owner handoffs still alert.
- Enable delete-branch-on-merge. Do not push scratch/rescue branches without a PR or a named retention reason. Keep backups in external bundles/storage, not GitHub refs that pin obsolete history.
- A successful live check includes cleanup evidence. “Stopped coding” is not the end of resource ownership.

## 8. Decisions Claude Code may make—and when to stop

Without another prompt, main may implement, test, review, merge, deploy to an already authorized target, ticket non-blocking remnants, narrow implementation details, and clean resources covered by verified ownership/push proofs.

Stop and ask one focused question only for:

- a new consequential product requirement or a conflict with a user decision;
- a remaining security/data-loss blocker;
- destructive action outside verified cleanup proofs;
- new paid spend, credential/permission widening, external-support action, or irreversible architecture;
- a deployment target that has not been authorized.

Do not invent requirements from old tickets. Record the source of each consequential requirement and distinguish explicit user decisions from assumptions. If evidence contradicts an assumption, update the brief and acceptance checks instead of spending a review round defending it.

## 9. Measure whether the harness is helping

Report weekly per shipped stream:

- elapsed time from pickup to live evidence;
- main turns spent on implementation/integration versus relay/process;
- review rounds and provider spend;
- guard blocks, false positives, and time spent satisfying them;
- active owners at peak and quota interruptions;
- branches/worktrees/processes left after completion;
- production incidents and escaped security/data-loss findings.

A guard added after an incident must name that incident, its threat boundary, its negative controls, and its expected operational cost. Review or remove it when evidence shows it mostly blocks routine safe work. Never measure success by the number of gates added.

## 10. Truthful status and safe alternatives

- Never narrow a user-stated target without a sourced user decision. If an assumption is necessary, label it as an assistant assumption in the brief and every later status report; never attribute it to the user.
- Build status lists from current WAL `REALLY_TESTED`, commit, deployment, ticket and live-check records. Do not write “done,” “live,” “hook-enforced,” or “nothing shipped” from memory. Until a diagnosis is reproduced, call it provisional and name the next falsifying check.
- When account creation or password handling is unsafe for an agent, include the viable alternative in the first refusal: emailed approval, a device code, or vault-mediated credentials the agent never sees. Do not route the same forbidden act through another model.
- A person-only route required by the user's token is a priority product/API gap. File it with the exact route and expected token capability; do not convert it into a user chore.
- Review externally authored installers before execution. Enumerate MCP/OAuth registrations, services, login items, browser extensions, PATH changes and other background effects; install only the reviewed pieces.
- Never run a destructive rollback or test script against production. Use a disposable local or staging target. For integrations, test the exact transport that will be used—REST, MCP, browser or another channel—and preserve actionable, redacted error bodies.

## 11. Follow-up contracts, not silent omissions

The incident review also identified features that need their own threat and evidence contracts. Do not claim they are fixed by this process change or rush them through as blanket guard exemptions:

- session-directory process ownership, an audited Windows stop route, and portable cross-host approvals;
- narrow path-and-operation routes for ordinary task-local JSON/JSONL output and installer-owned mutations, without weakening WAL/receipt integrity or hook protection;
- a legacy ticket-close route bound to merge SHA, deployment and independent live `REALLY_TESTED` evidence;
- an owner cap with clear owner identity and exception semantics, plus fleet-wide dropped-owner coverage;
- `ah status --since` and a single ready-and-merge command with exact-head, concurrency and deployment semantics;
- auth/delete/money/device/release domain checklists with precise triggers and overrides, signed task relays, and reliable wakeup-versus-human transcript classification.

GoodQA token self-grant, real-browser lead generation, ticket-filer throttles, ParentProof release floors/self-update/artifact retention, exposed-token rotation, and host cleanup belong to their product or operational owners. Track them there rather than hiding them in a harness PR.

## Immediate operating loop

1. Freeze the active stream list and owner ledger.
2. Pick the oldest stream closest to live evidence.
3. Finish its validation, one review + one delta, merge, deployment, and independent live check.
4. Clean up and close the stream.
5. Only then refill the slot.

The default answer to “should I start another agent/review/spec/branch?” is **no unless it directly advances an active stream to its next observable shipping checkpoint**.
