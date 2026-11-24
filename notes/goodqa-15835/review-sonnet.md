# Sonnet acceptance review, goodqa#15835 (agent a5d878417503c1093)

At eddc5be7: BLOCK. Read-only checks on t2-dev: the ops-watch service runs ~/.agent-harness/bin/ops_watch.py (Nov 5 copy), not the hooks copy the fabd installer probes (install.sh:84); install() renders the unit from Path(__file__). The gate would pass while the timer runs a copy without the forwarder. Medium: a host with the default config (no sink) passes the gate.
At 1dde69e0: BLOCK for one bookkeeping item only (code and spec acceptable: Outcome narrowed to the probed file, the unit-copy, sink and liveness limits and both mitigations stated, probe before Path.home(), run_once-driven test, 7 tests OK, mutants fail as intended): the follow-up ticket number was missing. Filed as goodqa#15837 (linked to goodqa#15805) and cited in the spec Risks; the reviewer stated that a delta adding only that number counts as ACCEPT.
Verdict: ACCEPT
