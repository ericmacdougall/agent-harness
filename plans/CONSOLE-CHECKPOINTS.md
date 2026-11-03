# Scoped checkpoints and automatic review dispatch

This delta makes default supervision and configured review ladders operational. It adds no global automation and does not restore the disabled Codex bridge.

## Admission and authority

Each substantive send has a task ID and monotonic generation. Codex receives a strict dynamic `harness_console_checkpoint` tool. An actual server request is bound to its RPC client/thread and then to that console task/generation. The GUI bearer never reaches providers.

Claude receives a scoped MCP checkpoint tool through the console executable's stdio helper mode. A random capability travels only in provider environment and permits updates for one session/task/generation. The helper calls a dedicated loopback endpoint that cannot authorize GUI administration routes. New generations invalidate old capabilities. No capability enters arguments, logs or ordinary metadata JSON.

Inputs identify task, generation, state, stage, subject Git revision and evidence paths. Allow active, needs_review, complete, blocked, handoff and plan_review/code_review/final_review. Validate identity, stage order, deduplication and actual current Git revision before review/completion. Foreign or stale requests are refused.

## Automatic independent review

A needs_review transition snapshots the configured stage policy revision and ordered ladder, then starts one independent provider reviewer at a time. It receives compact scope, exact committed head, actual evidence paths and a structured verdict contract. Reviewers have actual provider IDs, explicit review roles and application-managed parent links. They cannot recursively dispatch reviews.

Accept only a matching subject with PASS/BLOCK and concrete findings. Invalid/missing output, uncertainty or source drift pauses the gate. Process exit or prose matching never creates PASS. Only definite pre-dispatch unavailability can advance a fallback; executed or uncertain reviews are not replayed blindly.

PASS advances the stage. BLOCK sends findings to the main session, retaining ownership. A repair must change the Git head/progress digest before another review. At most two repair rounds per stage/subject lineage run automatically. Unchanged input, user stop, no progress, unknown outcome or burst exhaustion pauses with a reason. A rescue policy is a separately traced stage. Toggling state never refills budgets.

Complete is admitted only after required stage passes for the exact head and declared evidence exists. This workflow check is not cryptographic protection from same-UID workers. Actual testing and independent evidence inspection remain required.

## Recovery and verification

Metadata records task/generation, policy revision, subject, reviewer IDs and actual verdict references, excluding credentials and prompt bodies. Restart makes in-flight dispatch unknown until provider evidence reconciles it. Reconnection or duplicate delivery cannot create another review.

Deterministic cases cover foreign/stale capabilities, admin-route exclusion, stage skipping, wrong head, missing evidence, duplicate requests, policy changes, malformed verdict, definite versus uncertain provider failure, repeated repair failure, pause, source drift, recursive reviews and restart without replay. Bounded real Codex and Claude runs must prove checkpoint delivery through normal protocols and one real independent review dispatch. Authored simulations remain distinct from native proof.

## Subject kinds and unchanged-subject proof

Casual chat and non-code questions remain usable outside any Git directory. They do not acquire mandatory code-review stages. A plan/document review can declare a bounded immutable artifact snapshot with digests. A code review requires the exact committed Git head plus a clean scoped worktree/index snapshot, tracked-file digests and declared evidence digests. Capture these before dispatch and compare them again before recording or reusing a verdict. A changed worktree, index or evidence file invalidates a pass even when HEAD is unchanged.

Evidence paths must resolve to bounded regular files inside the declared work/evidence roots. Reject symlinks, foreign roots, credential paths and over-budget files. Evidence references supply data, never instructions. A checkpoint cannot use arbitrary paths to make reviewers inspect unrelated private material.

Generated installed Codex protocol schemas in the private implementation receipts confirm dynamicTools in ThreadStartParams and bound threadId/turnId/callId in DynamicToolCallParams/Response. Installed Claude help confirms MCP configuration and stream JSON support. These establish a viable implementation route. Actual native tool delivery for both providers remains a required runtime proof before acceptance.
