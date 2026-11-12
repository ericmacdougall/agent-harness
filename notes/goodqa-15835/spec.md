# Spec: ops_watch capabilities subcommand for the fabd installer gate

Ticket: GoodQA goodqa#15835
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI probe with no UI; the proof is the real command output in the tests and the live check on t2-dev after install)
Sign-off: main
Review-policy: standard

## Outcome

An installer can ask an installed `ops_watch.py` what it can do (`ops_watch.py capabilities`, one capability per line, exit 0) and refuse to install a service that depends on a feature the host's ops-watch lacks. The fabd installer greps for the exact line `forward-foreign-critical` on the ops_watch.py it probes, so it refuses a host whose PROBED file lacks the forwarder. The probe proves the probed file only: on t2-dev the ops-watch service runs `~/.agent-harness/bin/ops_watch.py` (the copy that last ran `install --apply`), not `~/.claude/hooks/ops_watch.py`, so the installer must probe the file the unit runs, and the t2-dev batch install must re-point the unit (`python3 ~/.claude/hooks/ops_watch.py install --apply`) before the gate means delivery (see Risks and the follow-up ticket).

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
- AC-4: the capability is listed only while `forward_foreign` and `queue_events` exist, and the listed capability is real: a foreign critical emitted to the ring reaches the digest post through `run_once` itself, not only through a direct call of the forwarder (so a partial revert that drops the call from `run_once` fails). The probe also works with HOME unset and no password entry. Verify by: the same suite plus `tests.test_ops_watch_forward`. Source: inferred: from ticket:GoodQA goodqa#15835 -- see D3: listed only while the code exists.
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
- The gate checks the PROBED file, not the file the service runs (found by acceptance review, confirmed read-only on t2-dev: `systemctl --user cat ops-watch.service` runs `~/.agent-harness/bin/ops_watch.py run`, dated Nov 5 and different from the hooks copy; `install()` renders the unit from `Path(__file__)`, so the unit points at whichever copy last ran `install --apply`). Until the unit is re-pointed, updating `~/.claude/hooks` makes the gate pass while the timer keeps running a copy without the forwarder, and fabd criticals would again reach only the local ring. Mitigations, both follow-ups: the fabd installer probes the script from `systemctl --user show -p ExecStart ops-watch.service` (launchd ProgramArguments on the Mac) and requires the timer active; the t2-dev install step runs `python3 ~/.claude/hooks/ops_watch.py install --apply` and the live test checks that the unit's ExecStart path is the hooks copy. The fabd install must not go ahead before one of them is done.
- A host with the default config (comment mode none, no deadman) passes the gate although nothing would be delivered; t2-dev has sinks configured today. The installer may also check `ops_watch.py config` for at least one comment or deadman sink. Stated limit.
- The gate proves capability, not liveness: a host whose ops-watch timer is not installed, disabled or failing still passes it, and fabd criticals would then reach only the local ring. Stated limit; the installer may also check the heartbeat file `~/.agent-harness/logs/ops-watch.last-ok` (at most about 30 minutes old), which is the Fabric owner's decision.
- The capability is a presence check of the functions in the same file, a version marker rather than a proof; the run_once wiring is proved by the tests, not by the probe at run time.
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
