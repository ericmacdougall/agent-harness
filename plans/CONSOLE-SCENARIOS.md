# Console scenario registration

These are authored regression cases, registered before implementation. They are tuning cases and provide no field reliability estimate. Baseline is public commit7b519cab, which has only the reference launcher and no interactive console. Candidate is the eventual frozen console commit. The endpoint is a complete workflow with correct rendered output, actual provider/fixture state and preserved local work. A failed step fails its whole chain. No skipped cluster is green.

## Ordinary chain, eight consequential steps

1. Start the compiled app under minimal launcher PATH and a quoted cwd. Browser opens the authenticated GUI with current context and a labeled new interactive session.
2. Send one unique request through the real GUI and observe streamed provider output and a real final event.
3. Open a second session, send different input and prove histories/output stay isolated.
4. Expand an owner/subagent tree, navigate by keyboard and inspect selected agent transcript.
5. Pause a running selected turn, prove cancellation, then explicitly resume.
6. Pick a file and change idle cwd, prove the next provider turn receives exactly those selections.
7. Refresh repository state and refuse removal of a dirty or unpushed worktree.
8. Copy a multiline main-chat selection and prove copied text excludes sidebar labels, then close the console cleanly.

## Deep chain, thirty consequential steps

D01 launch without Go/Node runtime; D02 restricted-PATH provider discovery; D03 quoted cwd; D04 exact reference digest; D05 foreign context import without dual writer; D06 session plus/tab switching; D07 first streaming send; D08 interleaved second session; D09 partial message assembly; D10 long Unicode/tool output; D11 actual hierarchy expansion; D12 keyboard tree focus; D13 selected transcript; D14 explicit pending question; D15 answer exact request; D16 pause running work; D17 explicit resume; D18 stop selected owner without shared daemon death; D19 attachment picker; D20 idle cwd rebind; D21 actual branch tracking; D22 safe sync; D23 dirty/unpushed deletion refusal; D24 safe disposable worktree removal; D25 external CLI launch; D26 main-only text copy; D27 browser reconnect; D28 server restart unresolved-send recovery; D29 provider crash/quota/no-progress stop; D30 final actual completion and clean shutdown.

## Negative controls

N01 missing/wrong bearer; N02 foreign Host/Origin; N03 oversized JSON/stream record; N04 stale event cursor; N05 wrong RPC response ID; N06 duplicate send/double control; N07 lost final event; N08 unavailable provider; N09 unsupported provider action; N10 expired/already answered question; N11 active-turn cwd change; N12 dirty/unpushed/current/locked worktree removal; N13 stale expected revision; N14 quoted shell-like cwd/file name; N15 selected symlink or replaced file; N16 model output containing HTML/script/terminal controls; N17 reference data attempts instruction injection; N18 provider start accepted but transport lost; N19 empty/vacuous JS test report; N20 explicit user pause during an automatic continuation.

Each case records exact candidate, command or browser action, observed result, retained artifact and meaningful failing control. Deterministic provider subprocess doubles cover chaos without paid repetition. Real bounded Codex and Claude conversations qualify actual integration separately. Platform builds and native installation/launch proofs are reported separately. Independent held-out cases belong to the tester and are not treated as held-out after owner inspection.

## First core inspection repair controls

Registered deterministic checks cover interrupted approval refusal and exact matching approval acceptance/replay refusal; checkpoint and automatic-send pause during unlocked policy resolution; unavailable review pausing without automatic repair; strict malformed/duplicate/wrong-subject verdict refusal; managed-review disconnect and exact owned-turn cancellation; bounded RPC/Claude input to a non-reading pipe; preserved checkpoint/reviewer identity and no restored-writer send/resume; raw child-transcript API secret redaction; account selection and actual child environment through the launch helper without secret metadata; and a main checkout reviewing a different registered feature-worktree head without changing main. Prior-code failing logs and Go-overlay failing controls are private receipts, distinct from paid/native provider proof.
