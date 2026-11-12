# Spec: ops_watch capabilities subcommand for the fabd installer gate

Ticket: GoodQA goodqa#15835
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI probe with no UI; the proof is the real command output in the tests and the live check on t2-dev after install)
Sign-off: main
Review-policy: standard

## Outcome

An installer can ask an installed `ops_watch.py` what it can do (`ops_watch.py capabilities`, one capability per line, exit 0) and refuse to install a service that depends on a feature the host's ops-watch lacks. The fabd installer greps for the exact line `forward-foreign-critical`, so it cannot install on a host where a critical alert would reach only the local ring.

## Scope

- In: a `capabilities` subcommand and a `capabilities()` function in harness/hooks/ops_watch.py listing `emit` and, while the code behind it exists, `forward-foreign-critical`; a test file and a mutant script.
- Out: the installer change itself (the Fabric owner's), any other capability names, versioning of capabilities, the forwarder (goodqa#15827, merged).

## Assumptions (labelled; none is a user decision)

- D1 Output is plain names, one per line, nothing else, so `grep -qx` is exact. Source: ticket:GoodQA goodqa#15835
- D2 The probe is pure: no config, state or ring is read or written, so it works on a host where ops-watch has never run and cannot fail for an environmental reason. Source: inferred: from ticket:GoodQA goodqa#15835 -- an installer gate must not fail or have side effects.
- D3 A capability is listed only while the code behind it exists (the function check), so a partial revert cannot leave a false claim. Source: inferred: from ticket:GoodQA goodqa#15835 -- the gate protects against a missing feature.

## Acceptance criteria

- AC-1: `python3 ops_watch.py capabilities` exits 0, prints the exact line `forward-foreign-critical` and prints nothing on stderr. Verify by: `python3 -B -m unittest tests.test_ops_watch_capabilities`. Source: ticket:GoodQA goodqa#15835
- AC-2: one lowercase name per line, no blank or decorated lines, no duplicates. Verify by: the same suite. Source: ticket:GoodQA goodqa#15835
- AC-3: the probe creates no file under HOME. Verify by: the same suite. Source: inferred: from ticket:GoodQA goodqa#15835 -- see D2: the probe is pure and creates nothing.
- AC-4: the capability is listed only while `forward_foreign` and `queue_events` exist, and the listed capability is real (a foreign critical reaches the forwarder). Verify by: the same suite. Source: inferred: from ticket:GoodQA goodqa#15835 -- see D3: listed only while the code exists.
- AC-5: existing ops-watch behaviour does not change. Verify by: `python3 -B -m unittest tests.test_ops_watch tests.test_ops_watch_point_events tests.test_ops_watch_forward`. Source: inferred: from ticket:GoodQA goodqa#15835 -- the subcommand only adds a parser entry and a pre-check.

## Negative cases

- NEG-1 (AC-1): against the parent commit (no subcommand) the probe fails, so the installer would refuse; a decorated line (`forward-foreign-critical v1`) is not an exact line and fails the test. Source: ticket:GoodQA goodqa#15835
- NEG-2 (AC-3): a variant that loads state or config in the probe fails the no-side-effect test. Source: inferred: from ticket:GoodQA goodqa#15835 -- see D2: the probe is pure and creates nothing.
- NEG-3 (AC-4): a variant that lists the capability without checking the code fails. Source: inferred: from ticket:GoodQA goodqa#15835 -- see D3: listed only while the code exists.
- NEG-4 (AC-1, AC-2): failing-first: the new tests fail against a810795d and against each broken variant (tests/mutants_ops_capabilities.py: not listed, listed without the code check, decorated line, non-zero exit, probe with side effects, duplicate line). Source: ticket:GoodQA goodqa#15835

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.2 GB (method: a unittest process)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.01 GB (method: temporary homes)
Network: 0 MB (method: none)
Wall time: 3 min
Cap and kill: none needed (no heavy step)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- A capability name drifts from what the installer greps: mitigation, the exact name is pinned in the test and the ticket.
- The probe runs on an old installed ops_watch.py that has no subcommand: the installer sees a non-zero exit or no line and refuses, which is the intended failure (install the harness batch first).

## Domain checklist

Domains: auth, delete, devices, money, release

The change adds a read-only CLI probe; it adds no authentication, deletion, device, money or release behaviour.

Domain-gate: pre-account-hijack waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: lookalike-identifier waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: request-device-binding waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: link-expiry-single-use waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: session-fixation waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: rate-limit-enumeration waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: store-billing-exposure waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: backup-before-delete waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: unpushed-work-detection waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: dry-run-diff waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: scope-pinning waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: cross-host-approval-portability waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: idempotent-retry waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: device-identity-binding waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: unattended-recovery waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: grant-durability waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: remote-exec-audit waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: factory-reset-guard waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: idempotency-key waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: double-submit waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: currency-precision waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: refund-reversal-path waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: ledger-reconciliation waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: authorization-vs-capture waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: derived-gate-floor-with-ratchet waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: artifact-inventory-mirrored waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: self-update-e2e waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: transport-proof waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: rollback-not-blocked waived (no such behaviour is added or changed; a read-only CLI probe)
Domain-gate: staging-exists waived (no such behaviour is added or changed; a read-only CLI probe)
