# Design brief: Harness Mission Control, UI round 1

You are doing round 1 of UI layout and visual design only. Another engineer writes the production code afterwards from your prototype. Work only inside the current directory (it is `docs/mission-control/design-round1/` of a public repository). Do not touch files outside it, and do not modify `BRIEF.md` or `vendor/`. Do not use the network, a CDN, npm, or any package install.

## What it is

A local dashboard that a single developer opens on their Mac (and on a phone-width window) to watch a fleet of AI coding agents ("owners") at work and to chat with the coordinating agent. The user asked for it to be "cool 3d animated, interactive, useful, realtime and mobile responsive". It must look futuristic and alive, but it is a working tool first: every number on screen must be readable at a glance, and nothing important may live only inside the 3D canvas.

## Deliverable

A static, runnable prototype in this directory:

- `index.html` (served by any static server; ES modules are fine),
- `styles.css`,
- `js/` modules with a clear split: `mock.js` (mock data plus a timer that emits fake realtime events), `store.js` (state and subscriptions), `scene.js` (the 3D layer), and one renderer module per panel (`initiatives.js`, `activity.js`, `owners.js`, `chat.js`, `health.js`), plus `main.js` wiring,
- `DESIGN.md` (at most about 150 lines): design tokens, type scale, motion rules, breakpoints, the event-kind colour map, accessibility notes, and anything the production engineer must keep.

`vendor/three.module.min.js` is Three.js 0.170.0 (MIT, licence beside it). You may import it with a relative path, or write plain WebGL/Canvas 2D instead if lighter. No other third-party code, fonts or images; use system font stacks. Keep the total of your own files under about 250 KB.

The production version will replace `mock.js` with a Server-Sent Events stream (`EventSource('/api/events')`) that delivers the same objects, and chat sends with `fetch('/api/chat', {method:'POST'})`. Keep that seam obvious: panels read only from `store.js`.

## Data model (mock these exactly; realistic but invented values)

Initiative (from a JSON file the coordinator maintains):
```
{ id, initiative, state, milestones_done, milestones_total, pct, owner, ticket,
  milestones, next_step, next_eta, full_eta, note, updated, estimate_by }
```
`milestones_done/total/pct` may be null (show an indeterminate "checking" bar, not 0%). `milestones` is one string with items separated by " · ", each starting "Done:" or "Not yet:"; render it as a segmented bar plus an expandable checklist. `estimate_by` is "main" or "owner <id>"; every ETA must show who estimated it, e.g. "ETA ~2 h · est. by main". `state` values seen: "In progress", "In review", "At risk", "Partly proven", "Checking", "Blocked", "Done".

Owner (an agent working a ticket):
```
{ agent_id, runtime: "claude"|"codex", type, ticket, task, state: "live"|"idle"|"DROPPED"|"done",
  last_item: { at, event, note }, initiative_id? }
```
Show each owner's last work item and its age ("4 m ago"), ticking live. Age colour: fresh < 5 min, warm < 30 min, stale beyond.

Event (realtime, schema `mc.event/1`):
```
{ schema:"mc.event/1", id, ts, kind, source, actor:{runtime, session, agent},
  subject:{repo, branch, ticket, initiative}, summary, severity:"info"|"warn"|"high" }
```
`kind` is one of `wal` (an agent wrote to its work log), `push` (a git branch received commits), `release`, `deploy`, `ticket` (a ticket got a checkpoint comment), `chat`, `owner` (owner state changed), `system`. Every event makes a visible pulse: in the 3D scene at the actor's node or the repo/initiative node, and as a new row sliding into the activity feed. Mock about one event every 1-3 seconds with bursts.

Chat message:
```
{ id, from: "user"|"claude"|"codex"|"system", text, ts,
  status: "sending"|"queued"|"delivered"|"answering"|"answered"|"failed", to: "claude"|"codex" }
```
User messages carry the visible label "you · via dashboard". There is a responder switch: Claude (main) or Codex. For Claude also show the target session as a small picker. Replies from Codex stream in token by token; replies from Claude arrive whole after a delay (main has to wake up), so show a "waiting for main to pick this up" state with elapsed time. Show a failure state with Retry. The composer has a character counter (limit 4000) and is disabled with a reason while the connection is down.

Source health: a row per collector (Claude WALs, Codex WALs, GitHub, GoodQA tickets, t2-dev, initiatives file) with ok / stale / error and "last checked 12 s ago". Plus a connection indicator: live / reconnecting / offline.

## Views and layout

Desktop (>= 1200 px): a full-viewport 3D layer behind a glass HUD. Top bar: title, connection indicator, live clock, motion toggle, filter chips by event kind. Left column: initiatives. Centre: the 3D constellation remains visible through the gaps, with the activity feed as a lower band. Right column: owners above, chat dock below. Footer strip: source health.

Tablet (768-1199 px): two columns, the scene becomes a header band.

Phone (360-430 px wide): one column, a bottom tab bar (Overview, Activity, Owners, Chat), the scene as a short animated header band or a static poster. Chat must be fully usable with the on-screen keyboard (composer pinned above it, no horizontal scroll, 44 px touch targets).

## The 3D scene and motion language

Borrow the motion language of the user's own sites (transition2.ai and the agency site), which were inspired by GetLayers templates (Relay, New Era, Vesper, Glass Wave, Flow Wave). You may read these local notes for the spirit (read only; do not copy code or assets):
- `/Users/eric/Documents/Codex/2026-10-31/take/work/t2-sites-source/t2-sites/apps/transition2-ai/GETLAYERS-VISUAL-NOTES.md`
- `/Users/eric/Documents/Codex/2026-10-31/take/work/ai-e2c-review/apps/transition2-agency/GETLAYERS-SOURCE-NOTES.md`
- `/Users/eric/Documents/Codex/2026-10-31/take/work/getlayers/relay/DESIGN-MAP.md`

Key traits to carry over: one persistent canvas with one clock; "one luminous current" that branches and converges (Relay); deep black background `#000`, text `#fff`, muted `#9ba0a6`, dim `#6e7378`, raised surface `#131416`, soft accent `#eaff9e`; glass/silver material, thin luminous lines, slow camera drift, depth through parallax rather than clutter. Device pixel ratio capped at 1.5 desktop and 1 on phones; drawing capped around 25 fps desktop and 18 fps phone; pause when the tab is hidden or the canvas is offscreen.

Scene concept (adapt freely): initiatives are luminous cores arranged on a slow orbit; owners are smaller nodes tethered to their initiative; repos sit on an outer ring. A WAL event sends a short pulse from the agent node into its core; a push travels along the repo ring; a release or deploy blooms a ring wave; a ticket checkpoint flashes the core; chat lights a beam to the chosen responder. Progress is the core's arc fill. Make it interactive: drag or pointer to orbit gently, hover or focus to highlight, click a node to open its card in the HUD (and the same is reachable from the HTML lists by keyboard).

Assign each event kind one colour and one shape/icon so colour is never the only signal.

## Accessibility and fallbacks (required)

- `prefers-reduced-motion: reduce` and a visible motion toggle both stop camera drift and travelling pulses; replace them with a brief static highlight.
- No WebGL, a failed shader or context loss: show a CSS/SVG poster with the same layout; the HUD works unchanged.
- WCAG AA contrast for all text over the scene (use the glass panels' backing), visible keyboard focus everywhere, labelled controls, logical tab order, `aria-live="polite"` for new activity that is throttled (summarise bursts), and the chat log announced politely.
- All data text rendered with `textContent` (never `innerHTML` for data): the real data includes untrusted strings.

## Out of scope for you

Server code, authentication, real data. Keep the prototype honest: label the data as mock in a small corner badge.

When done, list the files you wrote and anything the production engineer must know in your final message.
