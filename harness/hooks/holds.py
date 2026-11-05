#!/usr/bin/env python3
"""Lift or inspect holds (rules S08/S09). A hold is lifted only by the user.

  holds.py status
  holds.py lift <hold-id> --source 'user:<session>/<message-uuid> "lift hold <hold-id>"'

To lift a hold the user (1) sends Claude the message `lift hold <hold-id>` (that exact text as the whole message;
"please" in front and a final "." or "!" are tolerated) and (2) runs `holds.py lift` in their own interactive
terminal, citing that message. `lift` refuses without a terminal on stdin and stdout (an agent's Bash tool has
none), then parses the source with provenance.py and looks the message up in that session's transcript
(provenance.find_user): the same uuid must be a human-typed message, and the whole message must be the lift
phrase, so a quote cut out of "do not lift hold yates" or "until I lift hold yates" lifts nothing. Anything else
(ticket, wal, inferred, agent text, a uuid that is not found) is refused. holds_guard.py re-verifies every state
entry with the same rule on every call, refuses any agent call of `holds.py` other than `status`, protects the
policy files and refuses agent writes to session transcripts.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
POLICY = HERE / "holds.json"
STATE = HERE / "holds.state.json"


def load_state(path: Path = STATE) -> dict:
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, dict) and isinstance(d.get("lifted"), dict) else {"lifted": {}}
    except (OSError, ValueError):
        return {"lifted": {}}


def write_state(state: dict, path: Path = STATE) -> None:
    if path.is_symlink():
        raise OSError("refusing symlink")
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=1)
    os.replace(tmp, path)


NEGATION = re.compile(r"\b(not|no|never|don'?t|doesn'?t|won'?t|until|unless|keep|stay|stays|without|before|after"
                      r"|if|when|wait)\b|n't\b", re.I)


def lift_phrase_ok(text: str, hold_id: str) -> bool:
    """True only for the exact lift phrase `lift hold <id>` (optional leading "please", final "." or "!")."""
    t = re.sub(r"\s+", " ", str(text or "")).strip().lower()
    return bool(re.fullmatch(r"(please )?lift hold " + re.escape(hold_id.lower()) + r" ?[.!]?", t)) \
        and not NEGATION.search(t)


def _interactive() -> bool:
    return os.isatty(0) and os.isatty(1)


def verify_user_source(source: str, finder=None, hold_id: str = None) -> dict:
    """Parsed user source whose uuid really is a human message with that excerpt, else ValueError. With a hold id the
    quoted words AND the whole human message (the finder's preview) must be exactly `lift hold <id>`, so an unrelated
    message, or the phrase cut out of a negated or conditional sentence, can not lift anything."""
    import provenance
    try:
        parsed = provenance.parse_source(source)
    except provenance.Problem as exc:
        raise ValueError(f"source rejected: {exc}") from None
    if parsed["kind"] != "user":
        raise ValueError("only a user: source can lift a hold")
    find = finder or provenance.find_user
    try:
        found = find(parsed["session"], parsed["excerpt"])
    except provenance.Problem as exc:
        raise ValueError(f"cannot verify: {exc}") from None
    matches = [f for f in found if str(f.get("uuid", "")).lower() == parsed["uuid"]]
    if not matches:
        raise ValueError("that message uuid is not a human message containing the excerpt in that session")
    if hold_id is not None:
        if not lift_phrase_ok(parsed["excerpt"], hold_id) or not any(
                lift_phrase_ok(m.get("preview", ""), hold_id) for m in matches):
            raise ValueError(f"the user's whole message must be exactly `lift hold {hold_id}` "
                             "(no negation, condition or other words)")
    return parsed


def lift(hold_id: str, source: str, policy: Path = POLICY, state_path: Path = STATE, finder=None, now=None) -> str:
    ids = {h["id"] for h in json.loads(policy.read_text())["holds"]}
    if hold_id not in ids:
        raise ValueError(f"unknown hold {hold_id!r}; known: {', '.join(sorted(ids))}")
    if not _interactive():
        raise ValueError("a hold is lifted only by the user in an interactive terminal (stdin and stdout must be a "
                         "TTY); an agent can not run this")
    parsed = verify_user_source(source, finder, hold_id)
    state = load_state(state_path)
    state["lifted"][hold_id] = {"source_uuid": parsed["uuid"], "session": parsed["session"],
                                "excerpt": parsed["excerpt"][:200], "at": int(time.time() if now is None else now)}
    write_state(state, state_path)
    return f"hold {hold_id} lifted by user message {parsed['uuid']}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    li = sub.add_parser("lift")
    li.add_argument("hold_id")
    li.add_argument("--source", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "status":
        lifted = load_state()["lifted"]
        for h in json.loads(POLICY.read_text())["holds"]:
            print(f"{h['id']:12} {'LIFTED by ' + lifted[h['id']]['source_uuid'] if h['id'] in lifted else 'ACTIVE'}")
        return 0
    try:
        print(lift(a.hold_id, a.source))
        return 0
    except (ValueError, OSError) as exc:
        print(f"holds: refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
