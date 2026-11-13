# Opus adversarial review, goodqa#15835 (agent a0c568dfa08e7eb86)

At eddc5be7: ACCEPT. The probe returns before any config, state or ring access, prints exact lines (emit, forward-foreign-critical) for grep -qx, an old copy fails closed (argparse exit 2). Lows: L1 the capability is a presence check, the run_once wiring is not proved by the probe (done: a run_once-driven test and AC-4 now names the forwarding suite); L2 capability is not liveness (stated limit); L3 Path.home() ran before the capabilities branch (done: moved above it, test with no home, mutant).
Verdict: ACCEPT
