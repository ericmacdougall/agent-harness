"""Real-shaped Claude Code transcripts for the owner-runtime authority tests (receipt v6 F1): a human turn, and an
AskUserQuestion call with the user's structured answer. Nothing here mocks provenance or command_guard."""
import json
import time
import uuid as _uuid
from pathlib import Path

MISSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _path(home, session, folder="-Users-test"):
    d = Path(home) / ".claude" / "projects" / folder
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{session}.jsonl"


def _stamp(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() if ts is None else ts))


def human_turn(home, session, text, ts=None) -> str:
    """A turn the user typed. Returns its uuid."""
    uid = str(_uuid.uuid4())
    rec = {"type": "user", "uuid": uid, "timestamp": _stamp(ts), "sessionId": session, "origin": {"kind": "human"},
           "message": {"role": "user", "content": text}}
    with open(_path(home, session), "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    return uid


def answer(home, session, question, chosen, options=None, ts=None, multi=False, questions=None, answers=None,
           sidechain=False) -> str:
    """The main conversation asks `question` (or `questions`) with AskUserQuestion and the user picks `chosen`
    (or `answers`). Returns the answer record's uuid; cite it as answer:<session>/<uuid>."""
    uid, use = str(_uuid.uuid4()), "toolu_" + _uuid.uuid4().hex[:20]
    options = options or [chosen, "No"]
    asked = questions or [{"question": question, "header": "Owners", "multiSelect": multi,
                           "options": [o if isinstance(o, dict) else {"label": o, "description": o}
                                       for o in options]}]
    ask = {"type": "assistant", "uuid": str(_uuid.uuid4()), "timestamp": _stamp(ts), "sessionId": session,
           "isSidechain": sidechain,
           "message": {"role": "assistant", "content": [{"type": "tool_use", "id": use, "name": "AskUserQuestion",
                                                         "input": {"questions": asked}}]}}
    reply = {"type": "user", "uuid": uid, "timestamp": _stamp(ts), "sessionId": session, "isSidechain": sidechain,
             "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use,
                                                      "content": "User has answered your questions"}]},
             "toolUseResult": {"questions": asked, "answers": answers or {question: chosen}}}
    with open(_path(home, session), "a") as fh:
        fh.write(json.dumps(ask) + "\n" + json.dumps(reply) + "\n")
    return uid
