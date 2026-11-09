# Harness Mission Control — round 1

A working observatory: one luminous current connects the fleet; stable HTML panels explain its work.
The scene is an instrument for orientation. The HUD holds the evidence and every action.
All names, progress, timestamps, messages, and operational signals are invented.

## Run and review

Serve this directory with any static server, then open `index.html`. No build or package install.
For example, `python3 -m http.server 8080` from this directory, then `http://localhost:8080`.
The only third-party asset is the supplied Three.js 0.170.0 module and its adjacent MIT licence.
No fonts, images, telemetry, API calls, or other remote resources are loaded.
The sliders button and MOCK DATA badge open the prototype lab: connection, burst, failure, poster.
`node verify.mjs` runs dependency-free offline schema and asynchronous interaction checks.

## Visual system

| Token | Value | Use |
| --- | --- | --- |
| `--bg` | `#000000` | Persistent black field |
| `--text` | `#ffffff` | Primary labels and values |
| `--muted` | `#9ba0a6` | Supporting text |
| `--dim` | `#6e7378` | Reserved for decoration; never essential text |
| `--surface` | `#131416` | Raised surface reference |
| `--panel` | `rgba(15,17,18,.93)` | Readable glass backing |
| `--accent` | `#eaff9e` | Active controls, progress, live work |
| `--line` | `#292c2e` | Quiet structural borders |
| `--warm` | `#f1c782` | Delayed evidence and warnings |
| `--danger` | `#f1a6a6` | Dropped owners and errors |

Use system sans for prose; SFMono/Menlo/Consolas for times, counts, tickets, and IDs.
Type: workspace title 29 px; dialog title 26; scene heading 17; panel heading 14;
initiative title 14–17; body 11–13; dense metadata 9–11; decorative coordinates 7–8.
Phone chat text is 13 px; the textarea is 16 px to avoid iOS focus zoom.
Spacing uses 4/8/12/16/24/32 px; panels have 9 px corners, chips 4 px, controls 5–6 px.
The lime edge on the first initiative connects it to the central core without implying selection.
Use opaque dark backing behind text; never trade contrast for a more transparent scene.

## Layout

- **1200+ px:** full-viewport canvas, three-column glass HUD. Initiatives span the left;
  centre topology sits above activity; owners sit above the command channel on the right.
  The shell fills the viewport, with a 720–750 px minimum height to preserve usable panels.
  Short desktop windows scroll the page; individual feeds scroll within their panels.
- **768–1199 px:** topology is a 300 px header band. Initiatives and owners/chat form two
  columns. Activity becomes a full-width band; health wraps below.
- **Below 768 px:** one column; Overview, Activity, Owners, Chat bottom navigation.
  Overview shows the short constellation, initiative cards, and all source health rows.
  Other views show their full panel. Hidden panels leave keyboard and accessibility trees.
- **360–430 px target:** touch controls are at least 44 px. Chat uses a flexing log and
  a fixed-in-panel composer. VisualViewport height/offset handles keyboard resizing and panning.
  While the keyboard is open, the top chrome and bottom navigation give space to chat.
  Keep the draft, routing controls, and offline explanation visible through connection changes.

## Event language

| Kind | Colour | Symbol | Scene gesture |
| --- | --- | --- | --- |
| `wal` | `#eaff9e` | ≋ | Owner → initiative current |
| `push` | `#9ebfff` | ↑ | Pulse along the repository orbit |
| `release` | `#d4b5ff` | ✦ | Expanding core ring |
| `deploy` | `#7edbca` | ◎ | Expanding core ring |
| `ticket` | `#f1c782` | ▤ | Core checkpoint flash |
| `chat` | `#f4b5d4` | ↗ | Repository → responder beam; central core represents main |
| `owner` | `#b5cad6` | ◇ | Owner cue and core ring |
| `system` | `#c7c9ce` | ⊞ | Repository cue and core ring |

Every signal has a text kind, a symbol, and a colour. Severity additionally has a written label.
Filters affect the activity feed; the constellation continues to show the entire fleet.
Pause feed freezes its existing rows and counts arrivals. Resume rejoins the latest 100 events.
Owner ages: fresh `<5 min`, warm `5–<30 min`, stale `>=30 min`; always show an age and state.

## Motion and resilience

One canvas and one requestAnimationFrame clock. No videos, textures, or extra canvas layers.
Drift is a slow ±0.09 radian yaw. Drag is limited to ±0.45 yaw / ±0.15 tilt; Reset restores it.
Cap drawing at 25 fps desktop/tablet, 18 fps phone. Cap DPR at 1.5 / 1 respectively.
Suspend drawing while hidden or offscreen. Reduced motion and the visible toggle stop drift,
travelling pulses, arrival animation, and the indeterminate shimmer. Highlight remains for 650 ms.
System reduced motion takes precedence; a stored toggle preference is restored when appropriate.
Feed arrivals move 12 px over 360 ms. There is no strobing, ambient flashing, or auto-scrolling tour.
Use the inline SVG poster for unavailable WebGL, import/shader failure, or context loss.
Keep interactive HTML node buttons over the poster; preserve all lists, chat, and filters.
The lab can force the poster and restore the scene. No context loss is required to review it.

## Data and production seam

`mock.js` owns fixtures, a 1.2–2.9 s event timer with bursts, source checks, and simulated chat.
`store.js` owns state/subscriptions, deduplication, selections, filters, chat routing, and retries.
Each panel imports its data/actions from the store. `ui.js` is DOM and formatting only.
`main.js` binds the adapter; replace `createMock` with `EventSource('/api/events')`, parse each
`mc.event/1` object, and call `ingestEvent`. Map EventSource lifecycle to live/reconnecting/offline.
Replace `sendChat` with `fetch('/api/chat', {method:'POST', ...})`; route the message with its
target session as separate metadata. Retain the message ID as the server-side idempotency key.
The producer must supply source-health, owner, initiative, and chat status/text updates to the
corresponding store actions. Validate all fields/timestamps at that boundary before publishing.
Wire objects retain the brief's exact fields. UI-only routing state lives outside chat objects.
Claude waits 7 s and replies whole; Codex emits a word every 65 ms. No work is actually dispatched.
Disconnects disable sending with a reason; pending requests can fail and keep Retry available.
Retry preserves the original destination/session even if the user has switched the responder.
Real chat needs acknowledgement IDs, stream resumption, cancellation, and durable history.
The bounded demo retains 100 events / 60 messages; production should paginate durable history.
The scene's seven-core composition is authored for this fixture. Production must reconcile node
creation/removal and progress geometry when initiative snapshots change; store/panels already accept updates.

## Accessibility and review notes

Essential information is HTML. Node buttons open the same native dialog as the lists.
Owner node labels reveal on hover, focus, and signals, keeping the resting constellation quiet.
All data reaches DOM through textContent or text nodes; never interpolate it into HTML.
Focus outlines are lime, dialogs trap focus and support Escape, and the page has a skip link.
Milestones have segmented bars and expandable text checklists. Unknown progress is “checking,”
never 0%. Every next/full estimate names `main` or `owner <id>`; full details are in the dialog.
Activity's polite live region summarizes arrivals every 4.5 s, including bursts.
Chat's separate polite announcement region announces queue/failure and each finished reply once;
the visible log stays available to screen-reader navigation without announcing every streamed word.
Do not replace panel DOM on the one-second age tick or jump the log while someone reads history.
Mock state is labelled in the footer and the phone header, with a dedicated prototype control panel.

Verification: offline checks cover schemas, null progress, age thresholds, event bounds/dedup,
filters/pause, delayed and streaming replies, retry routing, connection loss, motion preference,
local asset references, DOM hooks, safe sinks, and the own-file size budget.
This sandbox rejected a loopback server and aborted Chrome startup. Browser screenshots,
GPU/context-loss execution, screen-reader output, and physical phone keyboard behavior remain
unverified; review at 1440×900, 1024×900, and 360/390/430 px before production implementation.
