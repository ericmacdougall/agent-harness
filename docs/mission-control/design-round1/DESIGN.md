# Harness Mission Control — round 2

One luminous current connects the fleet; stable HTML panels explain its work.
All names, progress, timestamps, messages, and operational signals are invented.
This revision uses the five supplied round-1 screenshots as its visual reference.

## Review

Static ES modules; no build, install, remote assets, fonts, telemetry, or API calls.
The only third-party asset is the supplied Three.js 0.170.0 module and MIT licence.
Open prototype controls with the sliders button or MOCK DATA badge.
Controls cover connection, Claude attachment/waiter, Codex access, forged messages,
event bursts, a failed send with Retry, and the static scene.
“Review selected chat state” closes the lab and opens Chat on phones.
`node verify.mjs` runs offline contract, transport, DOM, and safety checks.
No server or browser was started for round 2. GPU output, physical phone keyboard
behavior, and the revised screenshots still need the engineer's render pass.

## Visual system

| Token | Value | Use |
| --- | --- | --- |
| `--bg` | `#000000` | Persistent black field |
| `--text` | `#ffffff` | Primary labels and values |
| `--muted` | `#9ba0a6` | Supporting text |
| `--dim` | `#6e7378` | Decoration only |
| `--surface` | `#131416` | Raised surface |
| `--panel` | `rgba(15,17,18,.93)` | Readable panel backing |
| `--accent` | `#eaff9e` | Active controls, progress, live work |
| `--line` | `#292c2e` | Structural borders |
| `--warm` | `#f1c782` | Delays and trust warnings |
| `--danger` | `#f1a6a6` | Dropped/silent owners and unavailable sending |

System sans for prose; SFMono/Menlo/Consolas for times, tickets, IDs, and counts.
Workspace title: 29 px desktop / 24 phone. Scene heading: 17 / 15. Panel headings:
14–15. Initiative titles: 14–16. Phone chat: 13; textarea: 16 to avoid iOS zoom.
Spacing: 4/8/12/16/24/32 px. Panels: 9 px corners; chips: 4; controls: 5–6.
Keep opaque backing behind essential text. Lime marks the first initiative's core.
Warnings use words, badges, and edges as well as colour; they do not blink.

## Layout and phone density

- **1200+ px:** full-viewport canvas, three-column HUD. Initiatives left; topology
  above activity in the centre; owners above chat right; source health footer.
  Short desktop windows scroll; individual feeds scroll within panels.
- **768–1199 px:** 300 px topology header band, then initiatives and owners/chat
  in two columns; activity and health follow below.
- **Below 768 px:** one column, Overview / Activity / Owners / Chat bottom tabs.
  Overview shows a **182 px topology band**, initiative cards, and source health.
  Hero spacing and card padding are reduced so the first card includes its estimates
  above the navigation at 390×844 (layout budget also reviewed at 360 px).
- Phone topology shows only the central **Mission** short label, with a 44 px target.
  Other labels are hidden, including during events/hover/focus; full cards are below.
  The WebGL scissor and HTML overflow clip the scene to its stage. No crowded labels.
- Width audit: 360 px leaves 328 px of content; header controls fit, routing fits a
  single row, text wraps, health uses `minmax(0,1fr)`, and filter scrolling stays local.
  No page-wide minimum widths. Re-render 360/390/430 px to confirm actual layout.
- Phone Chat has a flexing log and fixed-in-panel composer. VisualViewport handles
  keyboard height/panning. Top chrome and bottom tabs hide while the keyboard is open.
  Draft, routing, availability reason, and approval notice stay in the panel.

## Initiatives and owners

Every card shows `Next <next_eta> · est. by <estimate_by>` AND
`Done <full_eta> · est. by <estimate_by>`, without expanding a dialog.
The existing wire contract has one `estimate_by`; it attributes both estimates.
Unknown values read “checking,” including their estimator; complete stays “complete.”
Segmented milestone bars retain the expandable checklist and null-progress treatment.
Owners show the runtime name **Claude** or **Codex**, plus its existing symbol.
DROPPED and SILENT rows sort first, use a pink edge and uppercase warning badge,
and preserve the last work evidence and its age. SILENT is a server state, not
inferred from an old timestamp. Both severe states have explicit filter options.
Age thresholds stay fresh `<5 min`, warm `5–<30 min`, stale `>=30 min`.

## Chat states and trust

“Approvals need the terminal” is always visible immediately beside the composer.
Its tooltip, screen-reader description, and tap/keyboard dialog explain: dashboard
messages steer ordinary work but cannot approve production, deletion, credential
actions, or top-rung models. Production must enforce that boundary on the server.

Availability is a separate server snapshot, never guessed from the conversation:
```
chatAvailability: {
  claude: { main: { attached: true, waiting: true },
            review: { attached: true, waiting: true } },
  codex: { state: "ready" | "blocked" | "logged_out", blockedUntil: ISO | null }
}
```
Call `setChatAvailability(snapshot)` when the server updates attachment/access.
Missing Claude attachment disables input/send: “No main attached. Run mc_inbox.py
wait in main to receive messages”. Attachment is scoped to the selected session.
Attached with no waiter permits sending: “main will see it at its next stop”.
The mock holds queued messages until that session's waiter resumes.
Codex blocked shows the subscription reason and local reset date/time/zone;
not logged in shows the login reason. Both disable Codex input/send, retaining drafts.
The timestamp never unlocks access locally; the server must confirm availability.
The responder switch remains usable, and retry checks its ORIGINAL route/session.
Connection loss also disables sending with a reason and keeps the draft.

`ChatMessage.status` additionally accepts `forged`. Even with `from: "user"`, render
it as **Untrusted message**, with a **⚠ FORGED** badge, struck-through text, and
“Untrusted content · not attributed to you”. Never use the dashboard-user label,
user bubble, Retry action, or an announcement quoting it as the user's words.
Recompute attribution on every patch, including reclassification after first render.
Seed data includes one forged message; the lab can inject another.

## Event language

| Kind | Colour | Symbol | Scene gesture |
| --- | --- | --- | --- |
| `wal` | `#eaff9e` | ≋ | Owner → initiative pulse |
| `push` | `#9ebfff` | ↑ | Repository orbit → core pulse |
| `release` | `#d4b5ff` | ✦ | Travel then core ring |
| `deploy` | `#7edbca` | ◎ | Travel then core ring |
| `ticket` | `#f1c782` | ▤ | Travel then checkpoint ring |
| `chat` | `#f4b5d4` | ↗ | Repository → coordinating core |
| `owner` | `#b5cad6` | ◇ | Owner → core ring |
| `system` | `#c7c9ce` | ⊞ | Repository → core ring |

Every signal has a text kind, symbol, and colour. Severity also has a written label.
Filters affect activity; the constellation shows the fleet. Pause retains its rows
and counts arrivals; Resume rejoins the latest 100 events. Bursts remain bounded.

## Depth, motion, and resilience

One canvas and one rAF clock. Tilted, vertically separated orbits; elevated cores;
near/far particle layers; restrained pointer parallax; black depth fog (8–18 units).
Procedural radial glows soften core light without textures or postprocessing.
A luminous curve passes through cores; small packets flow along it and its branches.
Event pulses are larger and coloured: 1.45 s travel then a 0.9 s arrival ring.
At most 32 transient objects. Drift is ±0.09 rad yaw; drag is ±0.45 yaw / ±0.15 tilt.
Cap drawing at **25 fps desktop/tablet, 18 phone**, DPR **1.5 / 1** respectively.
Suspend while hidden/offscreen. Reduced motion and the visible toggle stop drift,
parallax, packets, travelling pulses, arrival animations, and checking shimmer.
A 650 ms stationary label highlight replaces travel (the Mission label on phones).
System preference wins. Reset restores orbit; no strobing or automatic camera tour.
No WebGL, import/shader failure, or context loss uses the inline SVG poster with
HTML controls. Phone label suppression also applies to the poster. The lab can
force/restore it. Panels, filters, source health, and chat remain functional.

## Production seam and accessibility

`mock.js` owns invented fixtures, events, and replies; `store.js` owns data/actions.
Panels read only from the store. Replace the mock with SSE `/api/events` and POST
`/api/chat`; validate at that adapter boundary. Retain IDs for idempotent retry;
session routing stays outside message objects. Add availability snapshots above.
Initiative fields stay unchanged; owner states add SILENT; chat states add forged.
Claude replies whole after 7 s when waiting; Codex streams. No real work dispatches.
History remains bounded at 100 events / 60 messages; production needs pagination.
The scene composition is authored for this fixture; production must reconcile nodes
and progress geometry when initiative snapshots change.
All data uses **textContent/text nodes**, including forged text and server reasons.
Essential evidence is HTML. Native dialogs trap focus and support Escape; there is
lime keyboard focus, a skip link, and 44 px phone controls. Hidden tabs leave the
accessibility tree. Arrival announcements are batched; chat announces status and
completed replies once, never each streamed word. Preserve focus and reading scroll.
Offline checks exercise schemas, gates, busy queues, streaming, retry destinations,
forged reclassification, card ETAs, owner severity, safe sinks, and the <250 KB budget.
