#!/usr/bin/env python3
"""Lift or inspect holds (rules S08/S09). A hold is lifted only with a verified user source.

  holds.py status
  holds.py lift <hold-id> --source 'user:<session>/<message-uuid> "verbatim words"'

`lift` parses the source with provenance.py, then looks the message up in that session's transcript
(provenance.find_user) and requires the same uuid to be a human-typed message containing the excerpt. Anything
else (ticket, wal, inferred, agent text, a uuid that is not found) is refused, so an agent cannot lift a hold on
its own say-so. The quoted words must name the hold and say lift. holds_guard.py refuses `holds.py lift` when an
agent runs it and protects the policy files, so the user running it in their own terminal is the only path.
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


LIFT_WORDS = re.compile(r"\b(lift|lifted|release|unhold|un-hold|remove|drop)\b", re.I)


def verify_user_source(source: str, finder=None, hold_id: str = None) -> dict:
    """Parsed user source whose uuid really is a human message with that excerpt, else ValueError. With a hold id
    the words must also name that hold and say lift, so an unrelated human message can not lift anything."""
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
    if parsed["uuid"] not in {str(f.get("uuid", "")).lower() for f in found}:
        raise ValueError("that message uuid is not a human message containing the excerpt in that session")
    if hold_id is not None and (hold_id.lower() not in parsed["excerpt"].lower() or not LIFT_WORDS.search(parsed["excerpt"])):
        raise ValueError(f"the quoted words must name the hold {hold_id!r} and say to lift it")
    return parsed


def lift(hold_id: str, source: str, policy: Path = POLICY, state_path: Path = STATE, finder=None, now=None) -> str:
    ids = {h["id"] for h in json.loads(policy.read_text())["holds"]}
    if hold_id not in ids:
        raise ValueError(f"unknown hold {hold_id!r}; known: {', '.join(sorted(ids))}")
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
