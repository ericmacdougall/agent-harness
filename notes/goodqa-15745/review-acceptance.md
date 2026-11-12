# Acceptance spec review, agent a396ebd9214d3ad34 (general-purpose, opus), goodqa#15745

Round 1: BLOCK with 7 findings (worker serial not parallel, unsourced 10 s target, watch floor and relay, false custody claim, macOS approval under-specified, AC-4 unverifiable and desktop lane open, AC-17 key scope inexpressible) and 8 notes.
Round 2: all 15 earlier findings resolved; BLOCK on N1 (frame retention) and N2 (API cannot check limits it cannot read) plus notes N3 to N6.
Round 3 (final): N1 to N5 resolved. Notes folded in afterwards: worker checks ACTUAL parsed cookies against declared values and AC-18 limits (NEG-17 extended with declares 10 contains 2001 and an oversize real value), AC-9 sentence fixed. N6 (confirm no harness guard refuses the helper opening Chrome's Cookies file) is a pre-build check recorded as an open item, never to be routed around.

VERDICT: ACCEPT

Second acceptance reviewer, agent aa71c2b0206796fc0 (red-team, opus), fresh review: BLOCK on (1) network policy not stated (deny list, per-origin egress, 64 MB budget) and unworkable live-check site, (2) Keychain read method (shortcut via /usr/bin/security defeats the human gate). Both fixed in the spec (AC-8 purego in-process, no child process except osascript, click Allow; AC-15 network policy stated as ASSUMPTION/TARGET_MISMATCH; AC-20 added). Re-check: both BLOCKs resolved, notes 3-10 addressed, residual notes: TARGET_MISMATCH must reach the user as a sourced ask via main (done below), capability gate wording fixed. The reviewer's claim that wildcards exist was corrected by the adversarial reviewer (exact origins only); spec says exact origins only.

VERDICT: ACCEPT
