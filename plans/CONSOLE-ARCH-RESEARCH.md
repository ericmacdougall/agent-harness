# Agent-framework research for the conversational agent console

Date: 2026-11-04 (all pages accessed 2026-11-04 via WebFetch, which returns a model-summarized rendering of the page, not raw text; quotes below are the fetcher's quotes of the page).
Scope: what LangGraph, LangChain (agents/middleware), CrewAI, Deep Agents, Hermes (Nous Research), Devin (Cognition) and Temporal contribute to the console design.
Context read: `plans/CONSOLE-KERNEL.md` (accepted, revision 3), `plans/INTERACTIVE-CONSOLE.md`, `plans/CONSOLE-CHECKPOINTS.md` on branch `claude/console-legacyimport-20261103` (read-only).
Convention: **[V]** = verified from the fetched page. **[I]** = my inference or mapping. Where a page did not cover something, that is stated; nothing was filled from memory without a tag.

Our design, for reference [V from plan]: kernel = `Decide(projection,input)->facts+effects` and `Reduce(projection,fact)->projection`, both pure; SQLite event log with revision CAS; receipt table (intent/accepted/final/unknown/rejected/abandoned); restart rule (open receipts become `unknown`, sessions read-only, children quarantined); INV7 (provider effect with no observed result is never retried); owner agents with child trees (`ChildObserved`); pause/resume/stop controls; model cascade (`CascadeSelected`) and review ladder with checkpoints (`ReviewStarted/Outcome`, `CheckpointRecorded`).

## 1. Summary table

| Framework | Concept | URL | Date | Maps to | Verdict and why |
|---|---|---|---|---|---|
| LangGraph | Checkpoint per step, thread_id, store vs checkpointer | docs.langchain.com/oss/python/langgraph/persistence | 11-04 | Event log = checkpoint superset; thread = session; store = memory (K-later) | Reject checkpoints as storage (we have a stronger log). Adopt the thread/store split as vocabulary |
| LangGraph | Time travel: replay re-executes, fork via update_state creates a branch | .../langgraph/use-time-travel | 11-04 | Replay = `Reduce` only (no effects); fork = new session seeded from log prefix | Adopt fork-from-prefix as a new feature (gap G1). Reject their replay semantics (re-fires LLM calls) |
| LangGraph | `interrupt()` + `Command(resume)`; node restarts on resume; side effects after interrupt | .../langgraph/interrupts | 11-04 | `QuestionOpened/Answered/Revoked`; resume values keyed by interrupt id | Adopt keyed multi-interrupt resume and response schema; our fact-based approach already avoids their re-run hazard |
| LangChain | Agent middleware hooks around model/tool steps | .../langchain/middleware/overview | 11-04 | Adapter-side hook points around effects; policy engine | Adopt as adapter structure (defer until K6 wiring) |
| LangChain | Built-ins: model/tool call limits, model fallback, retry, summarization, context editing, HITL, todo | .../middleware/built-in | 11-04 | `ContinuationBudgetChanged`, `CascadeSelected`, admission guards, `write_todos` | Adopt limit semantics (thread vs run limit, exit behavior) for continuation budget; defer summarization/context editing |
| LangChain | Multi-agent patterns and context engineering | .../langchain/multi-agent | 11-04 | Owner/sub-agent tree = "subagents as tools" with isolation | Adopt the isolation tradeoff vocabulary; confirms our tree is the subagent pattern |
| Deep Agents | `write_todos` planning, statuses pending/in_progress/completed in state | docs.langchain.com/oss/python/deepagents/overview | 11-04 | Per-task todo facts (`TodoUpdated`), shown in agent sidebar | Adopt as a kernel fact family (gap G3) |
| Deep Agents | Filesystem offloading of large results; pluggable backends | same | 11-04 | `PayloadReleased`, content-addressed payloads (K8) | Adopt for tool output and transcripts: log holds ref+digest only (consistent with INV6) |
| Deep Agents | `task` tool; sync subagent blocks supervisor until one report returns; async subagents | same | 11-04 | `ChildObserved`, child quarantine on restart | Adopt "one compact report per child" as the child result contract |
| Deep Agents | AGENTS.md memory always loaded; skills load progressively | same | 11-04 | Owner brief + CLAUDE.md load; memory slice | Defer; we already have file-based memory in the harness |
| Deep Agents | `interrupt_on` approve/edit/reject per tool | same | 11-04 | Question kinds: approve, edit-and-approve, reject-with-guidance | Adopt the three decisions as the closed enum of tool-approval answers |
| CrewAI | Flows: `@start/@listen/@router`, state with auto UUID | docs.crewai.com/en/concepts/flows | 11-04 | Owner workflow stages (plan, implement, review) as declared routing | Defer; our ladder is policy-driven, not decorator-driven |
| CrewAI | `@persist`: resume (same id) vs fork (`restore_from_state_id`, fresh id) | same | 11-04 | Resume = reopen log; fork = G1 | Adopt the resume/fork naming split |
| CrewAI | `@human_feedback` with `emit=` LLM-routed outcome | same | 11-04 | Question answer mapped to outcome | Reject LLM-routing of approvals (nondeterministic authority); keep enum answers |
| CrewAI | Crews: hierarchical process with manager agent; callbacks (`step_callback`, `task_callback`) | docs.crewai.com/en/concepts/crews | 11-04 | Supervisor/owner; observation taps | Defer manager-as-agent (our owner is a native agent); adopt callback points as observability taps |
| CrewAI | Short/long/entity memory | same | 11-04 | Memory slice | Defer |
| Hermes | Open-source agent: curated memory with nudges, autonomous skill creation, FTS5 session search | github.com/NousResearch/hermes-agent | 11-04 | Memory + session search across closed sessions | Defer; adopt FTS5-over-sessions idea only for derived search index, never authority |
| Hermes | Parallel isolated subagents with per-subagent provider/model/limits | same | 11-04 | `CascadeSelected` per child; limits per child | Adopt per-child model and limit binding |
| Hermes | `/retry`, `/undo` last turn | same | 11-04 | Discard (`Abandoned`) plus resend as new request | Reject auto-retry (INV7); keep explicit discard + new request |
| Hermes | Function-calling format: `<tool_call>` JSON, `tool` role, `<tool_response>`, `<scratch_pad>` | github.com/NousResearch/Hermes-Function-Calling | 11-04 | Adapter frame parsing for Hermes-family models if ever added | Defer; irrelevant while providers are Codex/Claude CLIs. Note: parse failures must be explicit facts, not guessed |
| Devin | Managed child sessions: coordinator spawns, monitors, messages, sleeps/terminates children; per-child ACU limit; parent woken on child finish/need-input | docs.devin.ai/work-with-devin/advanced-capabilities.md | 11-04 | Owner with sub-agent trees; child budget; event-driven wake instead of polling | Adopt: per-child budget, wake-on-event (matches no paid polling), explicit auto-approve of child spawn |
| Devin | Memory drive: git repo of Markdown, source-linked one-line notes, writes apply to future sessions only, "dreaming" consolidation, excludes task state/secrets | docs.devin.ai/product-guides/memory.md | 11-04 | Memory slice; provenance (`Source:`) per entry | Adopt the exclusion list and "applies to future sessions" rule; defer dreaming |
| Devin | Human takeover of shell/IDE/browser in-session; session event timeline via MCP | docs.devin.ai/get-started/devin-intro | 11-04 | Pause then user acts then Resume; timeline view | Adopt as UX requirement: takeover must be a recorded control fact |
| Temporal | Append-only Event History, durably persisted, doubles as audit log; size limits and Continue-As-New | docs.temporal.io/workflow-execution/event | 11-04 | Event log; log segmentation | Adopt: validates our model; adopt Continue-As-New idea as log compaction/rollover (gap G2) |
| Temporal | Replay returns recorded results, does not re-execute side effects | same | 11-04 | `Reduce` only on replay | Confirms INV2 design |
| Temporal | Activity retry policy, max attempts, non-retryable failures | same | 11-04 | Local effects only; provider effects never retried (INV7) | Adopt for local idempotent effects; reject for provider effects |
| Temporal | Timeouts (schedule-to-start, start-to-close, schedule-to-close), heartbeats with progress payload | docs.temporal.io/encyclopedia/detecting-activity-failures | 11-04 | Effect deadlines; liveness of running turns | Adopt heartbeat as an observation (progress digest) and start-to-close vs heartbeat distinction; our "accepted turn has no timer" needs a progress-heartbeat watchdog (gap G4) |
| Temporal | Signals (async write), Queries (read, no history), Updates (sync, validated, history-writing) | docs.temporal.io/encyclopedia/workflow-message-passing | 11-04 | Commands (Decide with refusal) = Updates; observations = Signals; HTTP GET projection = Queries | Adopt the mapping as API vocabulary (CONSOLE-API) |
| LangSmith (LangChain) | Run = unit of work (span-like), trace, thread, feedback on run | docs.langchain.com/langsmith/observability-concepts | 11-04 | Facts carry `seq`; trace/span ids for effects; review verdicts as feedback | Adopt run/trace/thread naming and trace-id on effects; defer external export (INV6 forbids bodies) |

## 2. Per-framework sections

### 2.1 LangGraph
Sources: persistence (https://docs.langchain.com/oss/python/langgraph/persistence), interrupts (.../interrupts), time travel (.../use-time-travel); accessed 2026-11-04. The durable-execution page (.../durable-execution) returned only the persistence overview on two fetches, so durability modes (exit/async/sync) and the task-wrapping rules are **not verified** here; treat any claim about them as unverified.

1. Checkpoints and threads. [V] "Checkpointers persist a thread's graph state as checkpoints"; a thread is identified by `thread_id`; checkpoints accumulate and the docs suggest pruning or a retention policy; in-memory savers are lost on restart, SQLite/Postgres savers persist. Checkpointer (per-thread) is distinct from store (cross-thread, application data). [I] Our log is strictly stronger: facts, not state snapshots, with receipts. Their retention warning corroborates our "resolved history beyond visible limit" rule; we should segment (G2).
2. Time travel. [V] `get_state_history` lists checkpoints newest first. Replay "re-executes nodes - it doesn't just read from cache"; "LLM calls, API requests, and interrupts fire again and may return different results." `update_state` "does not roll back a thread. ... It creates a new checkpoint that branches". [I] Our replay (Reduce only) is safer and deterministic; we should add fork: new session seeded from a log prefix with a `ForkedFrom{sessionId, seq}` fact, never re-firing effects. This is the useful user feature (try a different instruction from turn N).
3. Interrupts. [V] `interrupt()` pauses, state saved, `Command(resume=...)` resumes with the same thread; "Resuming restarts the node from the beginning"; guidance: idempotent ops before interrupt, side effects after; resume values can be a map from interrupt id to value for parallel interrupts; response schemas validate the resume input. [I] Maps to `QuestionOpened{id,kind}` / `QuestionAnswered`. Adopt: answers keyed by question id (we have it), typed answer schema per `kind` validated in `Decide`. Our design avoids their re-run hazard because the fact is committed before the effect (INV7).
4. Subgraph history. [V] A subgraph by default inherits the parent's checkpointer and is one step; `checkpointer=True` gives its own history. [I] Analogue: child agents are observed inside the parent's session log (`ChildObserved`) rather than own logs; decide explicitly whether a child gets its own fork point (G1).
5. Verdict: adopt fork/keyed-resume/typed-answer; reject checkpoint-snapshot persistence.

### 2.2 LangChain (agents and middleware)
Sources: middleware overview (https://docs.langchain.com/oss/python/langchain/middleware/overview), built-in (.../middleware/built-in), multi-agent (.../langchain/multi-agent); accessed 2026-11-04.

1. Hook model. [V] Middleware "exposes hooks before and after each" step of the model-call/tool-call loop; uses: logging, retries, fallbacks, early termination, rate limits, guardrails, PII detection; it runs inside the compiled LangGraph, so HITL, summarization and retries travel with the agent node. The overview did not name individual hooks. [I] We have no model loop (providers are CLIs), so hooks apply at our effect boundary: pre-dispatch admission (INV4 guards), post-observation filtering. Keep them as `Decide` guards, not plugin code (guards live once).
2. Limits and fallback. [V] Model call limit and tool call limit have `thread_limit` and `run_limit` and `exit_behavior` (end/error/continue); model fallback takes `first_model, additional_models`; tool/model retry has `max_retries, backoff_factor, initial_delay, max_delay, jitter`; tool error middleware converts exceptions to readable messages. [I] Map: `ContinuationBudgetChanged{remaining,progress}` = run_limit; add a per-session thread-level cap (G5). `CascadeSelected` = model fallback, but ours must only advance on definite pre-dispatch unavailability (checkpoint plan), unlike their retry-on-failure; reject their blind retry for provider calls.
3. HITL. [V] `HumanInTheLoopMiddleware(interrupt_on={tool: True})` pauses before tool run, per-call mode, requires a checkpointer. [I] Same as Questions.
4. Summarization and context editing. [V] Summarization triggers by tokens/messages and keeps recent; context editing clears old tool outputs with a placeholder. [I] Console is a UI over provider-owned context; we do not control provider context, only what we show and what we feed to continuation. Defer; note INV rule that late-frame text enters transcripts only marked late.
5. Multi-agent patterns. [V] Subagents ("main agent coordinates subagents as tools", strong isolation but "repeats the full flow", stateless), handoffs, skills, router; "At the center of multi-agent design is context engineering." [I] Our owner/sub-agent tree is the subagents pattern; the review ladder is a router. Use this vocabulary in docs.
6. Todo list. [V] `write_todos` tool via To-do list middleware. See Deep Agents.

### 2.3 Deep Agents (LangChain)
Source: https://docs.langchain.com/oss/python/deepagents/overview, plus the middleware table above; accessed 2026-11-04.

1. Planning. [V] Opt-in `TodoListMiddleware` adds `write_todos`; statuses pending/in_progress/completed; persisted in agent state. [I] Add facts `TodoSet{taskId, items[digest,status]}` (item text is a prompt-derived body, so by INV6 keep only a bounded redacted title or reference); render in sidebar. The harness already has task/generation; todos attach to that.
2. Filesystem and offloading. [V] Virtual filesystem tools (`ls, read_file, write_file, edit_file, glob, grep`); "Built-in offloading and summarization compress conversation history and large intermediate results"; pluggable backends (state, disk, store, composite, sandbox with `execute`). [I] Our K8 content-addressed payload store is the same idea; extend to tool outputs and large transcripts: facts hold `{payloadHash, size, kind}`, bytes live in the CAS directory, `PayloadReleased` frees them.
3. Subagents. [V] Built-in `task` tool; sync subagents "block the supervisor until they return a single report"; each in its own context; async subagents run in parallel. [I] Child result contract: exactly one compact report observation per child (`ChildObserved` plus a bounded outcome), with transcript separate and drill-down on demand.
4. Memory. [V] `AGENTS.md` files passed via `memory`; always loaded, unlike skills which load progressively. [I] Equivalent to CLAUDE.md and owner briefs; no kernel work.
5. HITL. [V] `interrupt_on` lets you "approve, edit, or add guidance before a tool runs". [I] Closed enum for tool approval answers: approve / edit / reject-with-guidance; guidance text is user-written and must be bounded and redacted if logged.
6. Rubric grading (beta) [V from middleware table]: self-grade against a rubric until pass or `max_iterations`. [I] Reject for authority: self-grading must not produce PASS (checkpoint plan requires independent reviewer). Could be a pre-review advisory only.

### 2.4 CrewAI
Sources: Flows (https://docs.crewai.com/en/concepts/flows), Crews (https://docs.crewai.com/en/concepts/crews); accessed 2026-11-04. The Crews page did not cover delegation details or task guardrails; not claimed.

1. Flow state. [V] Shared `self.state`, dict or Pydantic, automatic UUID `id`. [I] Equivalent to the projection; ours is derived, theirs mutable.
2. Routing. [V] `@start`, `@listen` (with `or_`/`and_`), `@router` returns a label to choose the branch. [I] Our stage progression (plan_review to code_review to final_review) is the router; keep it table-driven in `Decide`.
3. Persistence. [V] `@persist` uses SQLite by default; resume via `kickoff(inputs={"id":...})`; fork via `kickoff(restore_from_state_id=...)` with a fresh ID leaving the original intact. [I] Same naming for G1.
4. Human feedback. [V] `@human_feedback` pauses (CrewAI >= 1.8.0); with `emit=` an LLM maps free-form feedback to an outcome. [I] Reject the LLM mapping for authority decisions; keep user-chosen enum, optional bounded note.
5. Crews. [V] Sequential (default) and hierarchical (manager coordinates, delegates, "validating outcomes before proceeding"; needs `manager_llm` or `manager_agent`); `step_callback`, `task_callback`, before/after kickoff callbacks. [I] Hierarchical manager = our owner/supervisor. The "manager validates outcomes" is exactly what the checkpoints plan says must NOT be self-validated; independent reviewer required.
6. Memory. [V] short-term, long-term, entity memory. [I] Defer.

### 2.5 Hermes (Nous Research)
Sources: https://github.com/NousResearch/hermes-agent (agent), https://github.com/NousResearch/Hermes-Function-Calling (format); accessed 2026-11-04. These are GitHub READMEs, less authoritative than product docs; confidence medium.

1. Agent. [V] "The self-improving AI agent"; TUI plus messaging platforms; provider switchable (`hermes model`); "Agent-curated memory with periodic nudges"; autonomous skill creation; FTS5 session search with LLM summarization; built-in cron with delivery to platforms; `/new`, `/retry`, `/undo`, `/compress`; subagents with per-subagent provider, model, limits; terminal backends local/Docker/SSH/Modal/Daytona/Vercel Sandbox; scripts calling tools via RPC. [I] Closest peer in product shape to our console.
2. Session search. [I] A derived FTS index over closed sessions is a cheap, useful non-authority view (never replayed, rebuildable from the log).
3. Per-child model/limits. [I] Add to `ChildObserved` or spawn policy: model, effort, budget bound at spawn and shown.
4. `/retry` `/undo`. [I] Reject as implicit actions; our equivalent is explicit discard (`Abandoned`) then a new request, because INV7 forbids retrying an unknown provider outcome.
5. Function-calling format. [V] Tools in a `<tools>` block as OpenAI-style JSON; calls as JSON in `<tool_call>` tags; results returned in a `tool` role message wrapped in `<tool_response>`; optional `<scratch_pad>`; ChatML. [I] Only relevant if we ever drive a raw Hermes model; then the adapter must treat unparseable tool_call blocks as an explicit refused observation, not a guess.
6. Cron. [I] Scheduled unattended runs correspond to supervision/continuation; must pass the same admission guards (INV4) and `AdmissionRefused` coalescing.

### 2.6 Devin (Cognition)
Sources: intro (https://docs.devin.ai/get-started/devin-intro), llms index (https://docs.devin.ai/llms.txt), advanced capabilities (https://docs.devin.ai/work-with-devin/advanced-capabilities.md), memory (https://docs.devin.ai/product-guides/memory.md); accessed 2026-11-04. The intro page did not cover planning, playbooks or snapshots; not claimed. The index lists Playbooks, Dynamic Workflows, blueprints (snapshots) but those pages were not fetched.

1. Managed child sessions. [V] Coordinator "scopes the work, monitors progress, resolves conflicts, and compiles results"; each child in its own isolated VM with prompt, skills, tags and an ACU limit; auto-approve of child sessions is a setting; parent is notified when a child finishes or needs input and is woken "even if asleep, so it doesn't need to poll"; parent can message, sleep, or terminate children; child output format unspecified. [I] Strongly matches our design: add per-child budget, an explicit child-spawn approval policy fact, wake-on-observation (we already forbid paid polling), and a bounded child outcome.
2. Human takeover. [V] User can follow and "take over" IDE/shell and jump into the interactive browser. [I] Pause, user acts, Resume. Record takeover as control facts so replay shows the gap in agent authorship.
3. Memory drive. [V] Git repo of Markdown, root `MEMORY.md` index, one-line bullets with source metadata linking to the session; new memories "apply to future sessions, not the one that wrote them"; excludes session summaries, task state, rediscoverable facts, secrets; background "dreaming" consolidates and prunes; per-user; automations neither read nor write memory; user can view and disable. [I] Adopt exclusion rules and source-linking (matches our provenance rule), and "no mid-session self-influence" rule. Memory must never be authority state in the kernel.
4. Session event timeline. [V] Devin MCP can list and search a session's event timeline and wait for parallel sessions in one call. [I] Our log API should expose a bounded, redacted timeline query for owners (see section 5).
5. Playbooks and snapshots. [V that pages exist per index; contents unverified]. Defer.

### 2.7 Temporal
Sources: event history (https://docs.temporal.io/workflow-execution/event), detecting activity failures (https://docs.temporal.io/encyclopedia/detecting-activity-failures), message passing (https://docs.temporal.io/encyclopedia/workflow-message-passing); accessed 2026-11-04. Pages did not give idempotency guidance or Update IDs; not claimed (the Event page said that side-effect guidance: "Do not ever have a Side Effect that could fail").

1. Event history. [V] Append-only, durably persisted, "so your application state survives crashes", also an audit log; warning at 10,240 events, termination beyond 51,200 events, 2,000 updates, 10,000 signals; Continue-As-New avoids limits. [I] Directly validates event-sourcing plus replay. We need rollover: a `SessionContinued{fromSeq, snapshotDigest}` or per-session segment so a long-running owner does not grow unbounded (G2). Note our log is a single global log; segment size and quota are K2 concerns.
2. Replay. [V] A Side Effect "does not re-execute upon replay, but instead returns the recorded result." [I] Same as our Reduce-only replay; INV2 tested by seeds is the equivalent of determinism checks; we do not need Temporal's workflow-code determinism rules because Decide/Reduce are pure and effects are descriptors.
3. Retry policy. [V] Retryable failure schedules a retry until Maximum Attempts; non-retryable failure recorded immediately. [I] Use for local idempotent effects (worktree cleanup, payload cleanup). Provider effects get zero retries (INV7). Encode "retryable vs non-retryable" as an enum on local-effect outcomes with attempt count in the fact.
4. Timeouts and heartbeats. [V] Start-to-close detects crashed workers; heartbeat timeout detects stalled progress; heartbeat can carry a progress payload; cancellation is delivered via heartbeats. [I] Gap: kernel says an accepted turn has no timer. Add a progress-heartbeat observation (digest of last activity) feeding `Supervision` stall detection, without ever auto-moving a receipt to unknown; only warns and offers pause/stop. Also confirms that stop must work without heartbeat dependency (our stop-work effects bypass gates).
5. Messages. [V] Queries read and add no history; Signals fire-and-forget; Updates are synchronous, validated before acceptance, written to history if accepted. [I] Command = Update (validate in `Decide`, refusal returned, fact on accept); provider frames = Signals; GET projection = Query. `AdmissionRefused` for automatic work is the "no caller waiting" case.

### 2.8 LangSmith (observability, LangChain)
Source: https://docs.langchain.com/langsmith/observability-concepts; accessed 2026-11-04.
[V] Run = unit of agent work; trace = runs for one operation (cap 25,000 runs per trace); thread groups traces for a multi-turn session via `thread_id`; trajectory is a flat message view; feedback = tag plus score bound to a run id; a run "can think of as a span." [I] Facts already have `seq`; add `traceId`/`spanId` on effects and observations (request id can serve), thread = session. Review verdicts map to feedback on a request. INV6 prevents sending prompt bodies to any external tracer, so only local export of structural spans (OTel-compatible) is allowed.

## 3. Recommended adopt list tied to K-slices

| Slice | Adopt | Source | Note |
|---|---|---|---|
| K1a (accepted, tables frozen) | None required. Record gaps G1-G6 as deferred facts so tables are not reopened | | Avoid scope creep in an accepted slice |
| K1b children and questions | Child spawn policy + per-child model/budget binding; one compact child report; typed answer schema per question kind with closed approve/edit/reject enum; answers keyed by question id | Devin, Hermes, Deep Agents, LangGraph | Fits deferred controls F6-child, F9, F11 |
| K1c inputs | None | | |
| K1d tasks, reviews, checkpoints, supervision, budget | Todo facts (`TodoSet`); thread-level and run-level continuation caps with exit behavior; heartbeat/progress observation for stall detection; independent reviewer only (no self-grade PASS) | Deep Agents, LangChain built-ins, Temporal, CrewAI | G3, G4, G5 |
| K2 eventlog | Segment/rollover and quota awareness (Continue-As-New analogue); fork-from-prefix primitive in log API | Temporal, LangGraph, CrewAI | G1, G2 |
| K4 process lifecycle | Heartbeat from adapter (last-frame time) as observation; stop-work independent of heartbeat (already) | Temporal | |
| K5b/K6 wiring | Effect-boundary hooks (admission, post-observation filter) written as `Decide` guards, trace/span ids on effects | LangChain middleware, LangSmith | |
| K7 controls and questions | Takeover recorded as control facts; typed answers; discard + new request instead of retry | Devin, Hermes, LangGraph | |
| K8 payloads | CAS for tool output offload and large transcripts; `{hash,size,kind}` facts; release after replay | Deep Agents | already in plan; extend scope to tool output |
| K9 reviews | Review verdict as feedback record on a request; router vocabulary | LangSmith, LangChain | |
| K10 import/seeded test | Fork and rollover added to the seeded operation set | | raises seed-test surface; decide before K10 |
| K11 release | Bounded timeline query API for owners; golden fixtures include a fork and a rollover | Devin MCP, Temporal | |
| After K11 | Memory (Devin exclusions, source links), derived FTS session search (Hermes), OTel local export | | defer; non-authority |

### Gaps in the current kernel plan (inference, from reading the plan against these systems)
- G1 No fork: the plan has resume (reopen) and replay but no way to branch a session from log prefix N. LangGraph and CrewAI both treat fork as first-class.
- G2 No log rollover/segmenting for very long sessions; Temporal documents hard limits and Continue-As-New. Plan has quota and hidden history but not rollover with snapshot digest.
- G3 No planning/todo fact family; sidebar tree has task state but not the agent's own plan.
- G4 No stall detection for an accepted turn: "no timer" is right for receipts but supervision needs a non-authoritative progress heartbeat (the checkpoint plan uses progress digest; confirm it covers idle-but-alive).
- G5 Continuation budget is run-scoped; LangChain separates thread and run limits.
- G6 Child budgets and spawn approval are not in the fact vocabulary (`ChildObserved{id,role,turnId}` only); Devin treats ACU limit and auto-approve as launch-time fields.
- G7 Typed answer schema per question `kind` not specified in the vocabulary (`QuestionOpened{kind,digest}`); needs closed enums for tool approvals.
- G8 No trace/span id on effects for observability.

## 4. Rejected, with reasons
- Snapshot checkpoints as persistence (LangGraph): weaker than facts plus receipts.
- Replay that re-executes (LangGraph time travel): violates INV7 and INV5.
- Automatic retry of model calls (LangChain retry/fallback, Hermes `/retry`): provider effect with unknown result must never be retried.
- LLM-routed human feedback (CrewAI `emit=`): nondeterministic authority.
- Manager/self-validated outcomes and rubric self-grading as PASS: conflicts with independent review requirement.
- Temporal itself as runtime: adds a server dependency and workflow determinism for a single-user local Go app; borrow concepts only. [I]
- Python framework adoption of any kind: console is a standard-library Go module with an embedded UI.

## 5. For the QAC agentic-loop owner (a6d317d29925a7f9a)
Practical takeaways for an agentic loop built next to the console:
1. Loop design: run limit and thread limit are separate budgets (LangChain), each with an exit behavior (end, error, continue-with-notice). Make exit behavior explicit and logged, never silent.
2. Never retry an action whose result is unknown. Record unknown and ask. Retry only idempotent local steps, with attempt counts and non-retryable classes (Temporal).
3. Side effects after the approval boundary, never before (LangGraph interrupts): if a step is re-entered after resume, anything before the question must be idempotent. In our model: commit the fact, then act.
4. Progress needs a heartbeat that carries a digest (Temporal heartbeat payload); stall means warn and offer pause/stop, not kill, consistent with "pause-not-kill" for legitimate long jobs.
5. Delegation: a child returns one compact report; keep its transcript separate; bind model and budget at spawn (Deep Agents, Devin, Hermes). Wake the parent on child events, do not poll with model calls.
6. Todos: keep a short structured todo list per task with pending/in_progress/completed, stored by reference; useful for supervision and handoff.
7. Reviews: independent verdict only, tied to exact head; do not let the agent self-grade (CrewAI manager validation and rubric grading are advisory at best).
8. Memory: store preferences, corrections with rule, decisions with reason, environment gotchas; exclude task state, summaries and secrets; every entry source-linked; new memory applies to later sessions only (Devin).
9. Offload large outputs to files/CAS and keep only hash and size in the event record.
10. Coordinate with console-platform before relying on any fact name above; these are proposals (inference), not accepted kernel vocabulary.

## 6. Limits of this research
- WebFetch summarizes pages with a small model; wording quoted is as returned and not independently re-read from raw HTML.
- LangGraph durable-execution (durability modes) not verified; Devin planning/playbooks/snapshots not verified; Temporal idempotency and Update IDs not covered by the fetched pages.
- Hermes pages are GitHub READMEs. Pages are current as of the access date only; vendor docs change frequently.
- No secrets or credentials were used or recorded.
