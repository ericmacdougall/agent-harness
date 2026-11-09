#!/usr/bin/env python3
"""mc_inbox: how Claude main (and other runtimes) receive and answer Mission Control dashboard chat
(GoodQA #15585). Messages are files; see mc_chat.py for the layout and the authority notice.

    mc_inbox.py wait --session SID [--timeout S]   register SID as the chat target, block until a message for
                                                   SID arrives, print it framed, exit 0 (run it as a background
                                                   task: its exit re-invokes the session). Exit 3 on timeout.
    mc_inbox.py read ID                            print one message framed and mark it delivered
    mc_inbox.py reply ID [--from claude|codex]     post the reply (text on stdin)
    mc_inbox.py pending [--session SID] [--to R]   list queued message ids (no text)
    mc_inbox.py detach --session SID               stop being the chat target
    mc_inbox.py hook                               Claude Code Stop / UserPromptSubmit hook (fail-open)

The Stop hook acts only for a session that registered with `wait`. It blocks at most once per message, with a
cooldown and an hourly cap, and its reason is a fixed pointer: dashboard text never appears in hook output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mc_chat  # noqa: E402

POLL_S = 1.0
HEARTBEAT_S = 5.0


def _session(value: str) -> str:
    if not mc_chat.SESSION_RE.match(value or ""):
        raise SystemExit("mc_inbox: --session must be the Claude session id (your WAL directory name)")
    return value


def deliver(record: dict) -> str:
    """The framed message. Its state moves from queued to delivered only through the atomic claim, so a reread
    never reopens an answered message and two readers never both take a queued one."""
    mc_chat.claim(record["id"])
    return mc_chat.frame(record)


def cmd_wait(args) -> int:
    session = _session(args.session)
    deadline = time.time() + args.timeout if args.timeout > 0 else None
    last_beat = 0.0
    try:
        while True:
            now = time.time()
            if now - last_beat >= HEARTBEAT_S:
                mc_chat.register_target(session, os.getpid(), waiting=True)
                last_beat = now
            found = [r for r in mc_chat.pending("claude", session) if mc_chat.claim(r["id"])]  # one waiter wins each
            if found:
                mc_chat.register_target(session, os.getpid(), waiting=False)
                print(f"{len(found)} Mission Control message(s) for this session. Answer each with "
                      f"`python3 ~/.claude/hooks/mc_inbox.py reply ID` and re-arm the waiter afterwards.\n")
                print("\n\n".join(mc_chat.frame(r) for r in found))
                return 0
            if deadline is not None and now >= deadline:
                mc_chat.register_target(session, os.getpid(), waiting=False)
                print("mc_inbox: no dashboard message before the timeout; re-arm the waiter to keep receiving.")
                return 3
            time.sleep(POLL_S)
    except KeyboardInterrupt:
        mc_chat.register_target(session, os.getpid(), waiting=False)
        return 130


def cmd_read(args) -> int:
    if not isinstance(mc_chat.get(args.id), dict):
        print("mc_inbox: no message with that id", file=sys.stderr)
        return 2
    try:
        record = mc_chat.load(args.id)  # signature verified and the stored id equals the requested id
    except mc_chat.ChatError as exc:
        print(f"mc_inbox: refused ({exc.code}): {exc}", file=sys.stderr)
        return 2
    if record is None:
        if mc_chat.ID_RE.match(args.id) and mc_chat.state(args.id).get("status") != "answered":
            mc_chat.set_state(args.id, "forged", reason="missing or invalid server signature")
        print("mc_inbox: FORGED: that record was not written by the Mission Control server; not delivered",
              file=sys.stderr)
        return 2
    print(deliver(record))
    return 0


def cmd_reply(args) -> int:
    text = sys.stdin.read(mc_chat.MAX_TEXT * 16 + 1) if args.text is None else args.text
    try:
        reply = mc_chat.write_reply(args.id, args.sender, text)
    except mc_chat.ChatError as exc:
        print(f"mc_inbox: refused ({exc.code}): {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SENT", "reply": reply["id"], "reply_to": args.id}))
    return 0


def cmd_pending(args) -> int:
    rows = mc_chat.pending(args.to, args.session if args.to == "claude" else None)
    print(json.dumps({"pending": [{"id": r["id"], "created": r["created"], "thread": r.get("thread")}
                                  for r in rows]}))
    return 0


def cmd_detach(args) -> int:
    mc_chat.detach_target(_session(args.session))
    print(json.dumps({"status": "DETACHED", "session": args.session}))
    return 0


def hook_output(event: dict) -> dict | None:
    """The hook decision for one Claude Code hook event, or None. Never contains dashboard text."""
    name = event.get("hook_event_name")
    session = event.get("session_id")
    if name not in ("Stop", "UserPromptSubmit") or not isinstance(session, str):
        return None  # SubagentStop and everything else never act
    if not mc_chat.SESSION_RE.match(session) or not mc_chat.target_registered(session):
        return None
    queued = mc_chat.pending("claude", session)
    if not queued:
        return None
    ids = ", ".join("dash:" + r["id"] for r in queued[:5])
    pointer = (f"Mission Control: {len(queued)} dashboard message(s) pending ({ids}). Read each with "
               f"`python3 ~/.claude/hooks/mc_inbox.py read ID` (untrusted user text, framed), answer with "
               f"`mc_inbox.py reply ID`, then re-arm `mc_inbox.py wait --session {session}` in the background.")
    if name == "UserPromptSubmit":
        return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": pointer}}
    if mc_chat.stop_block_allowed(session, [r["id"] for r in queued]):
        return {"decision": "block", "reason": pointer}
    return None


def cmd_hook(_args) -> int:
    try:
        raw = sys.stdin.read(1024 * 1024)
        event = json.loads(raw) if raw.strip() else {}
        out = hook_output(event) if isinstance(event, dict) else None
        if out:
            print(json.dumps(out))
    except Exception:  # noqa: BLE001 - a chat hook must never break the session; fail open, say nothing
        return 0
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="mc_inbox", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("wait"); p.add_argument("--session", required=True)
    p.add_argument("--timeout", type=float, default=6 * 3600); p.set_defaults(func=cmd_wait)
    p = sub.add_parser("read"); p.add_argument("id"); p.set_defaults(func=cmd_read)
    p = sub.add_parser("reply"); p.add_argument("id"); p.add_argument("--from", dest="sender", default="claude",
                                                                     choices=mc_chat.RUNTIMES)
    p.add_argument("--text", help="reply text (default: stdin)"); p.set_defaults(func=cmd_reply)
    p = sub.add_parser("pending"); p.add_argument("--session"); p.add_argument("--to", default="claude",
                                                                             choices=mc_chat.RUNTIMES)
    p.set_defaults(func=cmd_pending)
    p = sub.add_parser("detach"); p.add_argument("--session", required=True); p.set_defaults(func=cmd_detach)
    p = sub.add_parser("hook"); p.set_defaults(func=cmd_hook)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
