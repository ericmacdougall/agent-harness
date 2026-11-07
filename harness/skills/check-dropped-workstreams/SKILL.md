---
name: check-dropped-workstreams
description: Find workstreams that have silently lost their owner (agent stopped, no handoff, no named wait) and record a decision for each one. Use on the 30-minute cron, after a context compaction or restart, or whenever the user asks whether anything was dropped.
---

# Check for dropped workstreams

A workstream is **dropped** when the work is unfinished, no live agent owns it, and no live disposition records it as resumed, reassigned, waiting on a named ask or ticket, or closed with evidence. A dropped stream is a defect that needs a decision now (GoodQA goodqa#14791).

There is one owner view, `ah owners`, and this skill is a thin wrapper over it. Do not reconstruct the list by hand.

## 1. Run the deterministic scan

```
python3 ~/.claude/skills/check-dropped-workstreams/scan.py --text
```

Exit 0 means the gate is clear. Exit 1 lists every undisposed DROPPED owner (sub-agents and task-named WALs) with the `ah task dispose` line to run. Exit 2 means the owner view is unavailable: treat that as a defect, not as "nothing dropped". The exit code is the record; never write a "0 dropped" WAL line by hand.

## 2. Decide each undisposed owner (all four are `ah` writes; nothing else counts)

- Resume it: `SendMessage` to its agent id with the last state and next step, or spawn a fresh owner at the ladder rung, then `ah task dispose --agent <id> --kind resumed`. The disposition stays live only while activity follows.
- Hand it to another owner: `ah task dispose --agent <id> --kind reassigned --ref <new agent id>`. It holds while that owner is live; if that owner has stopped, only its own live named wait, closure or further reassignment carries over (and expires with it), not a stale `resumed`.
- It really waits on the user or a ticket: `ah task dispose --agent <id> --kind waiting --ref <ask id or GoodQA proj#N> --until <ISO>`. A wait must name an ask id that exists or a ticket; it expires at `--until`.
- It is done, meaning deployed to live and tested: `ah task dispose --agent <id> --kind closed --reason <what you verified> --deployed <deploy WAL id> --live-test <REALLY_TESTED id>`. Both records must name this owner. A merge or commit alone is not done.
- It will not ship: `ah task dispose --agent <id> --kind superseded|wontdo --ref <GoodQA proj#N> --reason <why>`. This is not done, and it says so in reports.
- Verify each owner on its own. Closing several owners in a burst is refused and alerted as a possible bulk close, and so is reusing one reason or one shared record.

## 3. Report

The Stop hook blocks your turn end while any owner is undisposed, so step 2 is not optional. If anything was dropped, tell the user in plain words: what, for how long, who owns it now and the next checkpoint. A repeated cause is a harness defect: file it on the never-lose ticket, not just here.
