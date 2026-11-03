# Console kernel acceptance catalog

Every entry is a defect found in the console 0.2 review record, and each becomes a named regression test in the slice that owns it. A slice is not done until its entries pass and each has shown a failing control. The kernel plan is [CONSOLE-KERNEL.md](CONSOLE-KERNEL.md).

**Layer:** `reducer` means a pure test against `Decide` and `Reduce`. `log` means real storage with fault injection. `adapter` means a real child process or real lock timing. `api` means through the HTTP or Go API with fake providers. `ui` means the click-test.

**Evidence:** `run` means reproduced by execution. `source` means the reviewer read it in source only, so the reproducer must be run first and may not reproduce.

## Baseline measurement

Seeded restore-versus-live property test against `7048366`, 1,000 seeds on a Linux runner with pinned Go 1.27.3, using the repository's test at `111631d`. It ran in report mode, so the run shows findings rather than a pass or fail.

18 raw divergence classes, which trace to 4 root causes. Grouping is my reading of the classes and of journal traces for the reappearing-tab case, not a separate proof.

| Root cause | Raw classes | Seeds (largest class) | Entries |
|---|---|---|---|
| Restart does not rebuild request identity, so `requests[lastRequest]` is lost | 8 | 751 | R1 |
| Restart trims by creation order, dropping unresolved tabs and letting trimmed tabs reappear after others close | 7 | 98 | R2, R3 |
| Pause overwrites `unknown` | 1 | 151 | R4 |
| Live `unknown` from an auth transition is never journaled, so restart shows `disconnected` | 2 | 82 | R5 |

Three of the four match review blockers (R1 and R4 share one, R2 with R3 is another), and R5 had only been listed as a lesser item. No receipt moved out of a terminal state in this run, and no restart was refused. Its limits: Claude questions, reviews and checkpoints were not driven, and queue coverage was thin, so this measures restart drift rather than all lifecycle defects.

This test stays as a regression, moved to the real API in K5. Acceptance is zero divergence at 10,000 seeds.

## Restart and projection

| ID | Scenario that must hold | Source | Evidence | Layer | Slice |
|---|---|---|---|---|---|
| R1 | Restart keeps the last request's identity and receipt, with intent or accepted shown as unknown | 7048366 F2, property | run | reducer, api | K1, K5b, K6 |
| R2 | Restart never drops an unresolved tab or one with a retained payload, however many tabs exist | 7048366 F1 | run | reducer, api | K1, K5b, K8 |
| R3 | A trimmed resolved tab does not reappear when other tabs close (view rule `visibleSessions`) | property | run | reducer | K1 |
| R4 | Pause or Stop on a read-only or unknown session changes nothing, and that session cannot then be closed | 7048366 F2 | run | reducer, api | K1, K7 |
| R5 | Every authority field shown live survives restart unchanged, except the enumerated restart rule table in the plan | property, F9 | run | reducer | K1 |
| R6 | A bookkeeping record such as a cwd change cannot hide an unresolved receipt | 20094e5 F2, red-team B7 | run | reducer | K1 |
| R7 | Changing cwd is refused while the last request is unresolved | 20094e5 F2, red-team B7 | run | reducer | K1 |
| R8 | Closing is refused while the last request is unresolved, for both providers, after a failed interrupt or none | 20094e5 F1, red-team B3 | run | reducer, api | K1, K7 |
| R9 | Reconnect and restart make no provider call. A start with an explicit launch argument creates a session as a user action, tested separately | INV5 | new | api | K5b, K6 |

## Terminal state and late frames

| ID | Scenario that must hold | Source | Evidence | Layer | Slice |
|---|---|---|---|---|---|
| T1 | A late completion cannot move a failed reviewer back to a passable state, for both providers | 20094e5 F5 | run | reducer | K1, K9 |
| T2 | A permission request after a Claude final cannot reopen the session, and cannot be answered | 9de77a5 P2 | source | reducer, api | K1, K7 |
| T3 | A completion or content frame for another turn cannot finalize this one | pre-9de repairs, `TestIdentity*` | run | reducer | K1, K6 |
| T4 | A Claude result with no exact active request stays unknown | `claude_finality` tests | run | reducer, api | K1, K5b |
| T5 | A native final can never be overwritten by a later unknown or abandoned | discard plan F2 | source | reducer | K1 |
| T6 | Every illegal receipt transition refuses and changes nothing | INV1 | new | reducer | K1 |

## Guards on every path and provider

| ID | Scenario that must hold | Source | Evidence | Layer | Slice |
|---|---|---|---|---|---|
| G1 | Resume needs prior durable finality on both providers | 9de77a5 P1 | source | reducer, api | K1, K7 |
| G2 | Pause then a new send cannot replace an unresolved turn, whichever provider, including a rejected interrupt | d628205 P1 | source | reducer, api | K1, K7 |
| G3 | Pause while turn/start is unanswered interrupts the turn that binds, never a guessed one | red-team B4 | run | reducer, adapter | K1, K7 |
| G4 | Direct child Resume is refused after any auth or permission boundary. `resumable=true` is never capability proof | user rule, existing tests | run | reducer, api | K1, K7 |
| G5 | Auth boundary fences parent, child, queued writes and late publication, including failed login and same-profile re-login | auth repairs `b8b6c87` | run | reducer, adapter | K1, K4, K7 |

## Persist before publish

| ID | Scenario that must hold | Source | Evidence | Layer | Slice |
|---|---|---|---|---|---|
| P1 | An uncertain store outcome revokes active request authority and questions; a later permission request cannot be answered | b975857 P1 | source | log, api | K2, K7, K8 |
| P2 | A failed checkpoint write cannot receive a successful acknowledgement on retry | d628205 P2 | source | log, api | K2, K9 |
| P3 | A retry of an admission with an unknown commit outcome is not acknowledged, and the draft is kept | red-team B1 | run | log, api | K2, K8 |
| P4 | An uncertain dispatch commit never makes restart refuse the whole console | red-team B2 | run | log | K2, K8 |
| P5 | A partial append followed by a retry leaves a readable log; a crash mid-append loses only the unacknowledged fact | discard plan F4, F15 | run | log | K2 |
| P6 | Failed intent persistence leaves no task or delivery state behind | F10 | source | reducer | K1 |
| P7 | A refused or rejected send leaves the session usable: new send or visible reason, never stuck idle | F8, F7 | source | reducer, api | K1, K5b, K6 |

## Adapter: lock order, processes, identity

| ID | Scenario that must hold | Source | Evidence | Layer | Slice |
|---|---|---|---|---|---|
| A1 | A login on one profile overlapping publication on another cannot hang the console | 20094e5 F3, red-team RT5 | run | adapter | K4, rerun K5b-K7 |
| A2 | No provider write happens while holding the kernel or app lock | 20094e5, red-team RT4 | run | adapter | K4, rerun K5b-K7 |
| A3 | Overflow or malformed frames stop the whole provider tree | red-team B5 | run | adapter | K4 |
| A4 | Claude exit without a final stops its tree; exit after a final leaves background work | 7048366 F4 | run | adapter | K4 |
| A5 | No signal lands after the leader is reaped, on Unix or Windows | F5 | source | adapter | K4 |
| A6 | Wait cannot hang on a descendant holding a pipe, and leader death is seen without stream EOF | F6 | source | adapter | K4 |
| A7 | A stored credential change refuses further sends on Claude and Codex, including automatic continuations | 20094e5 F4, red-team B6 | run | adapter, reducer, api | K4, K5b, K6 |
| A8 | An unrelated settings save neither refuses a conversation nor reuses a revoked GoodQA proxy, on both providers | 7048366 F3, #35597 | run for Claude, source for Codex | adapter | K4 |
| A9 | A reviewer cancelled during turn/start is interrupted once it binds | F11 | source | adapter | K9 |
| A10 | A parent auth change cancels a reviewer on another profile | red-team RT12 | run | adapter | K9 |
| A11 | Slow process work and a stalled fsync do not block reads or run under the kernel or settings locks | F13, plan review | source | adapter | K4, rerun K5b-K7 |

## Discard (user requirements)

| ID | Scenario that must hold | Source | Layer | Slice |
|---|---|---|---|---|
| D1 | Discard is explicit and confirmed, never automatic | user | api, ui | K7 |
| D2 | One durable fact holds the turn's identity, reason and time. Earlier facts stay. No success, verdict or pass is minted | user | reducer | K1, K7 |
| D3 | A late final, question, checkpoint or verdict cannot reopen, complete or pass the turn | user | reducer, api | K1, K7 |
| D4 | Double activation and a lost-response retry produce one fact, and the first reason stands | user, discard plan F7 | reducer, log | K1, K2 |
| D5 | Escape or Cancel while pending neither dismisses the request nor sends it twice. A hung request can be retried | user, discard plan F6 | ui | K7, K11 |
| D6 | A final arriving first wins, and discard is then refused | user | reducer | K1 |
| D7 | A write failure fails closed, leaves the turn unresolved, and a later native final still resolves it | user | log, api | K2, K7 |
| D8 | Restart before commit: still unresolved, and discard still works. After commit: abandoned, read-only, closable | user, discard plan F4 | log, api | K2, K7 |
| D9 | Keyboard reach, focus return, and an accessible name | user, discard plan F6 | ui | K7, K11 |
| D10 | A dispatching queue entry for the discarded turn can be released and the tab closed, with no restart | discard plan F1 | reducer, api | K1, K8 |
| D11 | No other path can mutate a discarded session: returning Pause, direct API, auth transition, queue failure, cwd | discard plan F3 | reducer, api | K1, K7 |
| D12 | The record holds the post-discard task state | discard plan F5 | reducer | K1 |

## Effects, log health, evolution and import (from the plan review)

| ID | Scenario that must hold | Layer | Slice |
|---|---|---|---|
| E1 | A write admitted before a later discard or auth boundary does not reach the provider (fence) | reducer, adapter | K1, K5b |
| E2 | Crash matrix: for each fact with an effect, a crash after commit and before the effect leaves the state named by the restart rule | log, api | K2, K5b-K8 |
| E3 | Definitely not written gives refused; possibly written or past deadline gives unknown | adapter | K5b, K6 |
| E4 | `TurnBound` with a pending interrupt emits it live and never during replay | reducer | K1 |
| E6 | A write held between recheck and syscall is drained by a revoker, or the group is killed and the outcome is unknown | adapter | K5b |
| E7 | Stop-work is available during a hung write, after a later boundary, and when latched | adapter, api | K5b, K7 |
| E8 | An fsync stall cannot trigger an acknowledgement deadline, and a running accepted turn has no timer | adapter | K5b |
| E5 | Local effects resume on open and are idempotent; provider effects never retry | log, api | K2, K3 |
| H1 | A native final during disk-full is retained and retried, or the log latches. The session never appears running indefinitely | log, api | K2, K5b |
| H2 | Any commit error not known to precede commit latches the log, and every new-work admission and effect recheck refuses | log | K2 |
| H4 | A revoking fact that cannot commit latches the log | log | K2 |
| H5 | `ProcessRestarted` that cannot commit starts the console latched and read-only; a crash loop does not spend the reserve | log | K2 |
| H3 | At quota, the console still starts, records outcomes, discards, releases and closes. A full disk refuses and says so | log | K2 |
| V1 | An invalid transition in a readable log quarantines that session and leaves the console up. An unreadable log refuses clearly | reducer, log | K1, K2 |
| V2 | Golden fixtures keep their meaning across reducer changes for a released `schemaVersion` | reducer | K11 |
| V3 | Live state from decoded facts equals replay, including omitted fields and time precision | reducer, log | K1, K2 |
| S1 | No secret, prompt, question text or attachment byte in the database, WAL or free pages, including through adapter mapping | log, api | K2, K5b-K8 |
| S2 | A noisy provider's late frames coalesce and cannot consume the quota | reducer, log | K1, K2 |
| I1 | A held `console.lock` refuses import with nothing changed | log | K3 |
| I2 | Each row of the import mapping, including no-request sessions, rejected, orphan and corrupt queue files, and missing `DirectoryIdentity` | log | K3 |
| I3 | An imported unknown turn can be discarded and its tab closed | api | K10 |
| I4 | A crash at each import step, including between commit and rename, recovers without loss | log | K3 |
| I7 | Legacy attachment references survive import, and kernel cleanup never treats them as orphans | log | K3, K8 |
| I8 | A crash at each step of the sentinel swap never leaves a state where an old binary starts empty | log | K3 |
| I9 | Every import row can reach closed; a quarantined session can be discarded and closed | reducer, api | K1, K10 |
| I5 | An old binary refuses the sentinel; rollback restores it; upgrading again refuses and names `--reimport`, which works | log | K3 |
| I6 | The real `6172744` code generates the fixtures | log | K3 |
| O1 | Restored tabs and continue-in-new-session warn that a provider process may still be writing in the directory | ui | K7, K11 |
| O2 | Late frame text enters a transcript only marked as late, is excluded from continuation context, and discard and continue-in-new-session say so | api, ui | K7, K11 |
| X1 | A cross-provider reviewer refuses until K9, then follows the same authority rules | api | K5b, K9 |
| X2 | An unconverted operation, including background paths, on a kernel-owned session refuses visibly and changes nothing; a build before K10 refuses any directory without the marker, across a restart | api | K5a |

## Lesser items from the same reviews

| ID | Item, tested as stated | Source | Evidence | Ticket | Slice |
|---|---|---|---|---|---|
| L1 | A login transition makes only unresolved requests unknown, on both providers | F9 | run (R5) | #35590 | K1, K7 |
| L2 | Worktree removal treats a failed rev-list as zero ahead | F14 | source | #35594 | K7 |
| L3 | Post-reap signal and deferred Pause tests exist, for turn/start failure, completion first and disconnect | F16 | source | #35596 | K4, K7 |
| L4 | A pause-unconfirmed message does not remain on a final turn | F12 | source | none | K7 |
| L5 | Codex inputs keep a misleading reason at an auth transition | red-team RT13 | run | #35601 | K7 |
| L6 | Input held by a child pause cannot be released | red-team RT11 | run | #35602 | K7 |
| L7 | continue-as-new has no gate for a live writer | red-team RT15 | run | #35600 | K7 |
| L8 | Codex child identities survive restart | red-team | source | #35605 | K1, K7 |
| L9 | Any `session_id` overwrites a Claude ProviderID | red-team | source | #35606 | K5 |
| L10 | Capability token in the browser opener's argv | red-team RT16 | argv run, exposure inferred | #35599 | K11 |
| L11 | Mutations equivalent to M1, M7, M15, M21 on the transition table and `Decide` are killed | red-team | run | #35608 | K1 |
| L12 | createSession publishes a client with no owner check | red-team | source | #35603 | K6 |
| L13 | Docs state that external re-login on a global profile is not detected; a probe, if feasible, marks the boundary | red-team | source | #35604 | K7 |
| L14 | A Claude init frame with a different cwd is quarantined, or the promise is removed from the plan | red-team | source | #35607 | K5 |
