# Plan: console K4 start and K12+ UI work

Ticket: GoodQA work-tracker-automatic#35574 (also #35692 for the three skipped baseline tests)
Spec: plans/CONSOLE-UI-SPEC.md (reviewed at spec sha b035b064...). Kernel plan: plans/CONSOLE-KERNEL.md. Research: plans/CONSOLE-ARCH-RESEARCH.md.

## State on 2026-11-04

- Baseline B is already on main as PR #36 (squash a6a33e9). K4 branches from main, not from the K1a to K3 stack.
- K1a (4c2883f), K2 (253c080), K3 (40e7f33) are pushed, stacked, unmerged. Their `go test -race ./internal/...` on dev2 (go 1.26 toolchain): `legacyimport` ok 30 s, `eventlog` ok 52 s, `kernel` exceeded the default 10 minute timeout at 3,000-seed model runs; rerun with `-timeout 50m` is recorded in the ticket.
- K1a to K3 must be rebased onto main before they merge, because main now holds `console/go.mod` and the baseline workflow. That rebase is a separate step owned by the kernel branch owner and is not part of K4.

## K4 increments (process lifecycle, catalog A1 to A8, A11)

1. Done, 742ffd6: `processTree` primitive (A5, A6, A3 and A4 at the primitive level) with six real-process tests and four failing variants.
2. Wire `processTree` into `claude.go` (stdout, Wait, stop-on-exit when no final seen, cancel), `rpc.go` (Codex, group stop before reap) and `settings_profiles.go` (login helper). Replace `terminateProcess` callers; keep `configureProcess`. Tests: A3 overflow or malformed frame stops the tree, A4 exit without a final stops the tree and exit after a final leaves background work, using a stub provider script.
3. A7 and A8: credential change refuses further sends including automatic continuations; unrelated settings save neither refuses a conversation nor reuses a revoked GoodQA proxy (this also targets the skipped `TestClaudeSurvivesRevisionOnlyToolConfigChange`).
4. A1, A2, A11: lock-order tests with timeouts (login overlapping publication on another profile, no provider write under the kernel or app lock, slow process work and a stalled fsync do not block reads).
5. Adapter identity computation (revision-free conversation identity, separate from the client cache key).

Each increment is a commit on `claude/console-k4-process-20261105` with failing-first evidence (a failing control or a broken variant, named in the commit Testing line). Heavy suites (`go test -race ./...` and repeated runs) run on dev2; short process tests may run locally. The three skipped tests are not unskipped by K4; they return with K5b and later as the baseline README says.

## Plan review result for K4 (native red-team a7cb68a15bec81a77, 2026-11-04): BLOCK on wiring

Increment 1 (742ffd6) stays as a committed, unwired primitive. Increment 2 does not start until the primitive is redesigned. Findings that bind the redesign:

- High: the stop-on-exit decision runs at reap, before the reader has consumed a final frame, so a leader that prints its final and exits can have its background work killed. Decide only after the stream is consumed or the drain bound passes, and hold the pgid until then (observe exit without reaping: `waitid` with `WNOWAIT` on Linux, kqueue `NOTE_EXIT` on darwin, then decide, then reap).
- High: the drain timer closes the read end and drops buffered bytes. Use a pump goroutine that reads continuously into a bounded buffer; apply the drain bound to the pump; make EOF distinguishable from a forced close. Test a 64 KB burst with a slow consumer and a descendant holding the pipe.
- High: `reaped` is set after `cmd.Wait` returns, up to `WaitDelay` after the real reap, so a stale-pgid signal is possible in that window (A5). The WNOWAIT design closes it. Replace the near-vacuous race assertion with a recorder that checks leader state at signal time.
- High: Windows cannot meet A5 or A3 with `taskkill` after reap, and runs it under the lock. Use a Job Object with kill-on-close, or mark A5 unmet on Windows; call taskkill by absolute path outside the lock; add a `GOOS=windows go vet` gate.
- Medium: `stopOnExit` runs under `t.mu` and would take `a.mu`: require a lock-free flag and add the lock-order test before wiring.
- Medium: no stderr-holder test; `ErrWaitDelay` must be normalised; the login helper merges stdout and stderr and uses `CommandContext`, so it needs a merged-pipe option and `Terminate`-driven cancel.
- Low: define `Terminate` returning false as "group possibly alive and unsupervised" and test the callers' reaction.
- Plan gaps: run the full existing console suite on dev2 before and after each wiring commit; split wiring into Claude, Codex, login; lock-order tests (A1, A2, A11) come with or before wiring.

New stop conditions: stop and report if the final-versus-reap ordering needs the WNOWAIT or zombie-hold redesign (this is that redesign, so it is a reported checkpoint, not an auto-repair); stop if the existing console suite regresses at any wiring commit. Revised order: primitive redesign, lock-order tests, Claude wiring, Codex wiring, login, A7 and A8, identity.

## Residual findings carried from the spec reviews

Both round-3 reviewers returned ACCEPT with these items. They bind the slice that owns them and are folded into the spec, with a fresh re-review, when K12 starts:

- AC-3 vocabulary: only `ControlOutcome{confirmed|rejected|unconfirmed}`; assert the exact set.
- Principal rule: default-deny. Every API command is user-principal unless on an explicit agent-allowed list, with a registry-wide `TestChildPrincipalRefused` so a new command cannot be missed. Memory and instruction edits, cost ceiling, polling opt-in, shortcut remap, kill, pause, discard and fork are user-principal.
- `PolicyBound` replay: either the admission-relevant enums are in the fact or an append-only per-revision settings snapshot store is bound by digest; define the order of store write and fact, and that a revision change does not alter a running turn.
- AC-12 names `SettingsChanged{defaults}` and `LadderChanged`, with a test of the fact kind written.
- One-time code: the opener must not expose a redeemable secret in argv; use a handle plus a verifier from a 0600 file, state the same-uid threat model, and test `ps` for the code.
- Git hardening adds `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL` set to null, `core.attributesFile`, `protocol.ext.allow=never`, a smudge-filter canary fixture; define protected branch; dirty-includes-ignored is intended and has a typed override.
- Fork: never binds the parent provider conversation; rollover with an unknown receipt needs the discard step and the quota warning says so; use 10,000 seeds after K10, 3,000 before.
- Local effects follow INV7 in local form: an intent record before the effect and an idempotent repeat; add a crash test between intent and removal.
- Dependencies: K14 needs K8 (or shows digest only until then); K15 needs K7 and K1b; state that K12 builds on the CONSOLE-API.md contract and can merge before K11 only behind the data-directory guard.
- Acceptance reviewer: raise the "constantly self-loop/check/manage" reading as an ask to the user with the recommended answer (event-driven display plus a named list of supervisory actions, each through `Decide`); add `TestUncheckedProfileNeverSelected` and `TestEnvOffExcludedFromChildEnv` with failing controls; give G3 (todo display), G6 (child budget and spawn approval), G7 (typed answers) and G8 (trace ids) a named UI test in K13, K14 or K7, list the Hermes search index as out of scope, add a device-key add-profile flow test; use a fake settings store for `TestStaleSettingsRevisionRefused` in K12; make the fork action conditional on the kernel amendment; state that click-tests before K10 use dev-marker data; name the AC-1 client-authority test and the AC-5 remap and AC-12 bypass-confirmation tests; say whether the TUI (AC-19) includes settings.
- Minor: INV5 reconnect test, keyed digests with a named key source, cost ceiling unit, cookie attributes (HttpOnly, SameSite=Strict, still Host and Origin checked), split-key redaction canary and its stated limit, p95 latency pinned to dev2, shortcut remap test, a direct "CLI feel" check (slash commands, streaming render, keyboard-only task).

## Stop conditions (from the kernel plan, applied here)

- Stop and report if the same finding class returns after two genuine repairs in a slice.
- Stop and report if K2 falsifier 3, 4 or 5 fails or the log cannot run under `console.lock`.
- K12a spike failure on selection isolation or keyboard operation triggers the K20b reversal path and a report; do not start K13.
- No slice merges without its own inspection; K4 merges through the main agent.

## Safety

No test reads the real Keychain, `~/.claude`, `~/.codex` or user settings; hooks and settings editors are tested on fixtures only. No deletion commands appear in shells or in test corpora fed to a shell; process tests kill only pids they created.
