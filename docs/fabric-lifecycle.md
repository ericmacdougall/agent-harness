# Initiative lifecycle in Agent Fabric (phase 2 design note)

Status: design only. No Fabric code changes yet. Tracked in GoodQA goodqa#15962, which is PENDING: its own gates need the user's agreement before any code is written. Phase 1, the harness, is goodqa#15952.

Sources:
- user, queue 2026-11-14T04:40:36Z #f500ab254868: "the harness/fabric/sytems need to operate like that"
- user, queue 2026-11-14T04:40:13Z #69c80ac14ad8: "it starts as pending - and requires us to agree on acceptence gates/definition of done -- that you [coordinator] agree can be meaured/tested/computed without external forces -- so you can drive it to 'ready' and i can agree its 'done'"

Phase 1 delivers only the harness side. Recording Fabric separately is a TARGET_MISMATCH split, not a narrowing.

## What phase 1 leaves open

- **The ledger is per host.** `~/.agent-harness/mission/goals.json` lives on the Mac. A host with no ledger, such as t2-dev today, gets spawn-hook context only and is never denied (ASSUMPTION A6). Work dispatched there is not checked against goals.
- **Bash and Fabric launches are only warned about.** A `claude` or `codex` started through Bash or a Fabric dispatcher is checked for a `[goal:]` tag in warn mode only (ASSUMPTION A3). Fabric dispatch does not go through `tier_gate.py` at all.
- **Evidence lives in local WALs.** READY is computed from WAL rows that main attached on the Mac. A Fabric run on another host has no attached row.

## Design

1. **One shared lifecycle record per initiative.** Fabric keeps the lifecycle object in its replicated state, keyed by goal id, with the same shape as `goals.json` `lifecycle`:
   - `state`, `gates`, `gates_sha`, `ask`, `proposed_at`
   - `agreed{source,at,gates_sha}`
   - `ready{at,ask}`
   - `done{source,at}`
   
   Every transition is an append-only, hash-chained event with the same tool actions as `mission_coverage.py` (propose, agree, activate, ready, done, migrate). The Mac ledger is one writer of that record, not a second source of truth: `mission_coverage.py` mirrors each lifecycle audit row as a Fabric event. Fabric refuses an event whose `lc_sha` chain does not continue from the last one.
2. **The same rules, the same code.** Fabric imports `lifecycle.py` instead of reimplementing it: gate form, `agreement_check`, `done_problem`, `gate_status`, `effective_state` and `spawn_verdict`. The user's words are resolved where the transcript lives (the Mac). The resolved result (source string, verified time, bound question hash) is carried in the event. Other hosts accept it only when signed by the Mac host key. That is the same trust model as Mission Control's signed approvals (`mc_turn`).
3. **The dispatch gate.** The Fabric dispatcher runs `spawn_verdict` before it starts any owner-type run. The rules are the same as phase 1:
   - ACTIVE, READY or LEGACY runs.
   - PENDING runs only as `:scoping`, with the 1-per-goal and 2-per-session quotas held in Fabric state under its own lock.
   - Anything else is refused.

   This closes the Bash and Fabric gap: a Fabric run cannot start without a goal. The rollout matches phase 1: warn first, and enforce only after the warn log is clean and the user agrees. The draft amendment AC-2a (build on a PENDING goal while its gate proposal is registered) applies only if the user agrees to it.
4. **Evidence from any host.** A Fabric run's terminal record (`REALLY_TESTED`, deploy) is published as a Fabric evidence event that names its gate and `gates_sha`. Main attaches it with `attach --gate` from a Fabric reference instead of a WAL id. `gate_status` applies the same qualification rules: main attached it, the revision is current, it is newer than the agreement, the verdict is explicit PASS, kind and name match, live tests are no older than the newest deploy, and a newer FAIL disqualifies.
5. **DONE stays with the user.** No Fabric path sets DONE. Only a `done` event carrying the user's resolved words, signed as in point 2, can.
6. **Display.** Mission Control already reads the lifecycle per initiative (phase 1). In phase 2 it reads the Fabric record, so every host shows the same state.

## Candidate gates for goodqa#15962 (to propose to the user, not agreed)

- A Fabric owner dispatch without a goal tag, or tagged with a PENDING goal without `:scoping`, is refused in enforce mode and logged in warn mode. Check: a dispatcher test with synthetic dispatches.
- A lifecycle event that breaks the `lc_sha` chain, or an unsigned user-source result from a non-Mac host, is rejected. Check: a Fabric state test.
- An evidence event produced on t2-dev and attached by main counts toward READY on the Mac. Check: a live test across the two hosts.
- Mission Control on the Mac and the state CLI on t2-dev show the same lifecycle state for every goal. Check: a live test.

## Risks

- **Split brain between the Mac ledger and Fabric state.** Mitigation: the Mac ledger mirrors events, Fabric enforces chain continuity, and a mismatch reads UNVERIFIED (treated as PENDING) on both sides.
- **Host-key compromise lets a host forge the user's words.** This is the same limit as the documented same-user threat model in `caller_identity.py`.
