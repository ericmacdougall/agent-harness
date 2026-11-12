# Spec: ops_watch: forward foreign critical ring events to the digest and deadman queues

Ticket: GoodQA goodqa#15827
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a daemon pass with no UI; the proof is run_once against fake sinks, plus the live Fabric outage drill that goodqa#15805 AC-5 runs after install)
Sign-off: main
Review-policy: standard

## Outcome

A critical alert that a script writes to the local ring with `ops_watch.py emit` (for example `fabric:live-down:fabd` from fabd-health.sh) now reaches the GoodQA alert digest and the deadman mail, as ops-watch's own critical alerts do, and its clear reaches the digest. A 15.5 hour Fabric outage can no longer stay visible only in `ops_watch status`.

## Scope

- In: `run_once` in harness/hooks/ops_watch.py forwards critical raise and clear rows of a foreign source on this host into `pending_comment` and (critical raises) `pending_deadman`; the queue code shared with `persist()` becomes one function; the forwarded sequence and the forwarded-raised keys are persisted in the ops-watch state.
- Out: the Fabric health check itself (goodqa#15805), a new local-unit check for fabd, re-emitting a raise that fell out of the 1024 slot ring (N3 of the same review, a separate ticket), peers' rings (the ring is a local file), non-critical foreign alerts (they stay in the ring, `status` and the context injection as today), the digest and deadman transports.

## Assumptions (labelled; none is a user decision)

- D1 "Foreign source" = any ring source other than `ops-watch` (the label ops-watch and `ah_kill` use for rows the existing path already handles). Source: ticket:GoodQA goodqa#15827
- D2 First run after install, or a ring whose sequence restarted below the stored one: forward only what is standing now (the latest row per key is a critical raise), never the history, and forward a clear that the old sequence never delivered. Source: inferred: from ticket:GoodQA goodqa#15827 -- idempotent across restarts and no flood of 66 hours of ring history.
- D3 A clear is forwarded only for a key that was forwarded as raised, whatever its flags (an expiry clear from the point-event expiry carries `detail.updated` and still closes the raise); `detail.updated` and `detail.reasserted` on a RAISE row are text refreshes and are never forwarded. Source: ticket:GoodQA goodqa#15827
- D5 A failed, empty or missing-file ring read after a forward is UNKNOWN, never a reset: the position (`fwd_seq`) and the forwarded keys stay unchanged. A real reset needs a positive signal: the ring file was replaced (device and inode differ from the stored ones) or the visible top sequence stayed below the stored position on three consecutive runs; one low read (a torn newest slot) is not one. Source: inferred: from ticket:GoodQA goodqa#15827 -- a read failure must not replay up to 1024 rows of history into the digest and the deadman mail (receipt r1 of PR 227, F1).
- D4 Deadman: critical raises only, at most one mail per key per 6 hours, exactly as for ops-watch's own critical raises (a clear is a digest line, not a mail). Source: file:harness/hooks/ops_watch.py:2098@42a5f99f

## Acceptance criteria

- AC-1: a critical raise written by a foreign source with `emit` reaches `pending_comment` (and the digest post) and, when a deadman sink is configured, `pending_deadman` (one mail). Verify by: `python3 -B -m unittest tests.test_ops_watch_forward`. Source: ticket:GoodQA goodqa#15827
- AC-2: reruns and a fresh `load_state` do not deliver it twice (the forwarded seq is persisted in the state write that holds the queues). Verify by: the same suite. Source: ticket:GoodQA goodqa#15827
- AC-3: a clear of a forwarded-raised key is forwarded to the digest (not mailed) once; a clear for a key that was never forwarded is not. Verify by: the same suite. Source: ticket:GoodQA goodqa#15827
- AC-4: a non-critical foreign event, an `ops-watch` source row, and a text refresh row are not forwarded. Verify by: the same suite. Source: ticket:GoodQA goodqa#15827
- AC-5: first run: only standing criticals are forwarded, not history; a recreated ring (the file replaced) forwards what is standing and the lost clear; an unreadable, empty or truncated read after a forward, and one torn newest slot, resend nothing and never lower the stored position. Verify by: the same suite. Source: inferred: from ticket:GoodQA goodqa#15827 -- see D2: standing criticals only, never the history.
- AC-6: existing ops-watch behaviour does not change. Verify by: `python3 -B -m unittest tests.test_ops_watch tests.test_ops_watch_point_events`. Source: inferred: from ticket:GoodQA goodqa#15827 -- the queue code is shared and must keep its semantics.

## Negative cases

- NEG-1 (AC-2): three consecutive runs deliver one digest line and one mail. Source: ticket:GoodQA goodqa#15827
- NEG-2 (AC-4): `high` and `warning` rows are not forwarded (the digest is not flooded by every foreign alert). Source: ticket:GoodQA goodqa#15827
- NEG-3 (AC-3): a critical raise, a clear, then a new critical raise of the same key is two alerts (two RAISE lines, one CLEAR). Source: inferred: from ticket:GoodQA goodqa#15827 -- re-raise after a clear is a new alert.
- NEG-4 (AC-1): no deadman configured: the digest still receives it and nothing raises. Source: inferred: from ticket:GoodQA goodqa#15827 -- own critical alerts queue the same way.
- NEG-5 (AC-5): the 1024-slot ring is overwritten oldest first; rows older than the stored seq are never replayed. Source: inferred: from ticket:GoodQA goodqa#15827 -- seq is monotonic per ring.
- NEG-6 (AC-1, AC-2): failing-first: the new tests fail against origin/main, and against each broken variant of forward_foreign (tests/mutants_ops_forward.py: forwarding removed, deadman not fed, every severity, clear never or always forwarded, seq not advanced, refreshes forwarded, first run history, ops-watch source not excluded, ring reset ignored, lost clear dropped). Source: ticket:GoodQA goodqa#15827
- NEG-7 (AC-2): a crash between queueing and the state write re-forwards (at-least-once) rather than loses; the queues and `fwd_seq` are written in one `save_state`. Source: inferred: from ticket:GoodQA goodqa#15827 -- an outage alert must never be lost.

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: a unittest process)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.01 GB (method: temporary homes)
Network: 0 MB (method: fake sinks only)
Wall time: 5 min (focused tests) plus 2 min for the ops-watch suites
Cap and kill: none needed (no heavy step)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- A duplicate digest line or mail after a lost state file: mitigation, a lost state re-forwards only what is standing (D2), once, and the deadman limit of one mail per key per 6 hours applies.
- A noisy foreign critical flapping: mitigation, one mail per key per 6 hours and the digest's own per-host interval.
- A foreign source that already delivers its own critical alerts now also appears in the digest: accepted; the ring is the one alert channel and the digest is its record.
- The state slot grows: mitigation, forwarded-raised keys are capped at 200 in a 512 KiB slot.
- A malformed foreign row (a non-object detail, a non-string key or source) is skipped (and `emit()` now refuses a non-string host, source or key, and the ring reader skips a stored row that has one, so such a row cannot crash `latest_by_key`) or read as an empty detail; it never stops the alert path and the forwarded seq still advances (found by review H1; tested with string, list and number details).
- Stated limits (review L1 to L4, M1, M2, tracked in the follow-up ticket): a repeated critical raise without a refresh flag is forwarded again (the digest keeps one entry per key and the deadman limit is one mail per key per 6 hours); a recreated ring that grows past the stored sequence before the next run (within one 2 minute pass) loses its early rows; the 200-key bound forgets the oldest standing key; a foreign writer using the `ops-watch` source label is skipped (the ring is unauthenticated local state); the queued copy drops `source`, so a foreign key with the same name as an ops-watch key shares its digest entry and mail throttle; a foreign source must stamp the configured host label (the short hostname, `mac` on the Mac) or its rows are not forwarded.
- A raise that falls out of the 1024-slot ring while standing (N3 of the Fabric review) is not re-forwarded: stated limit, tracked separately.

## Domain checklist

Domains: auth, delete, devices, money, release

The change moves already-written ring rows into two existing queues; it adds no authentication, deletion, device, money or release behaviour.

Domain-gate: pre-account-hijack waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: lookalike-identifier waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: request-device-binding waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: link-expiry-single-use waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: session-fixation waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: rate-limit-enumeration waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: store-billing-exposure waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: backup-before-delete waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: unpushed-work-detection waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: dry-run-diff waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: scope-pinning waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: cross-host-approval-portability waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: idempotent-retry waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: device-identity-binding waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: unattended-recovery waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: grant-durability waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: remote-exec-audit waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: factory-reset-guard waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: idempotency-key waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: double-submit waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: currency-precision waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: refund-reversal-path waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: ledger-reconciliation waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: authorization-vs-capture waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: derived-gate-floor-with-ratchet waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: artifact-inventory-mirrored waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: self-update-e2e waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: transport-proof waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: rollback-not-blocked waived (no such behaviour is added or changed; ring rows move into existing queues)
Domain-gate: staging-exists waived (no such behaviour is added or changed; ring rows move into existing queues)

## Reviews

Spec core sha256: `81f479036fdc08923d609d65e91549d2b703cd9d39f17aea7f4a335d12da81c0`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | current |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | current |
