#!/usr/bin/env python3
"""Lift or inspect holds (rules S08/S09). A hold is lifted only on a real user instruction.

  holds.py status
  holds.py lift <hold-id> --source 'user:<session>/<message-uuid> "lift hold <hold-id>"'

Any agent (main included) may run `lift`; the authority is the user's message, checked twice:
  1. the LOCAL transcript (provenance.find_user): the uuid must be a human-typed message in that session and the whole
     message must be the lift phrase `lift hold <id>` ("please" in front and a final "." or "!" tolerated), so a quote
     cut out of "do not lift hold yates" or "until I lift hold yates" lifts nothing;
  2. the OFF-HOST TRANSCRIPT BACKUP (rclone, the log backup's Dropbox remote): the same uuid and words must be in the
     backed-up copy of that session's transcript. A message that is not backed up yet is refused with the next step
     (run the backup, then retry); an unreachable backup is refused (fail closed). Nothing is cached.
After writing holds.state.json, lift runs `integrity.py record` so the new state is part of the mirrored record.
holds_guard.py re-verifies every state entry against the local transcript on every call.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
POLICY = HERE / "holds.json"
STATE = HERE / "holds.state.json"
BACKUP_RUN = "~/.agent-harness/bin/log-backup.sh"
BACKUP_BASE = "lessons-dropbox:Backups/agent-logs"
RCLONE_NOT_FOUND = (3, 4)  # rclone exit codes: directory not found, file not found


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


def verify_user_source(source: str, finder=None, hold_id: str = None) -> dict:
    """Parsed user source whose uuid really is a human message with that excerpt, else ValueError. With a hold id the
    quoted words AND the whole human message (the finder's preview) must be exactly `lift hold <id>`."""
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


class BackupUnreachable(Exception):
    """The off-host transcript backup could not be asked (rclone missing, network, auth, timeout)."""


def _rclone_env() -> dict:
    """Inherited RCLONE_* options (other than the config path) must not redirect the lookup."""
    return {k: v for k, v in os.environ.items() if not k.startswith("RCLONE_") or k == "RCLONE_CONFIG"}


def backup_location(session: str) -> str:
    """rclone path of the backed-up transcript, the layout harness/bin/log-backup.sh writes:
    <LOG_BACKUP_REMOTE or lessons-dropbox:Backups/agent-logs>/<LOG_BACKUP_HOST or hostname -s>/.claude/projects/
    <project dir>/<session>.jsonl."""
    import provenance
    try:
        local = provenance.find_transcript(session)
    except provenance.Problem as exc:
        raise ValueError(f"cannot locate the local transcript: {exc}") from None
    base = os.environ.get("LOG_BACKUP_REMOTE") or BACKUP_BASE
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_./-]*", base) or ".." in base:
        raise ValueError("LOG_BACKUP_REMOTE is not a plain NAME:path")
    host = os.environ.get("LOG_BACKUP_HOST") or socket.gethostname().split(".")[0]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", host):
        raise ValueError("backup host label is not plain")
    return f"{base.rstrip('/')}/{host}/.claude/projects/{local.parent.name}/{session}.jsonl"


def backup_has_message(session: str, uuid: str, hold_id: str, run=subprocess.run, rclone: str = "rclone",
                       remote: str | None = None) -> bool:
    """True when the backed-up transcript holds the human message `uuid` and it is the lift phrase for hold_id.
    False when the transcript or the message is not in the backup yet. BackupUnreachable when rclone can not answer.
    The copy goes to a private temporary directory removed afterwards; no secret is passed in argv."""
    import provenance
    remote = remote or backup_location(session)
    try:
        st = run([rclone, "lsjson", "--stat", "--ask-password=false", "--", remote], stdin=subprocess.DEVNULL,
                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, env=_rclone_env(), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BackupUnreachable(f"rclone could not run ({type(exc).__name__})") from None
    if st.returncode in RCLONE_NOT_FOUND:
        return False
    if st.returncode != 0:
        raise BackupUnreachable(f"rclone lsjson exit {st.returncode}")
    with tempfile.TemporaryDirectory(prefix="holds-backup-") as tmp:
        project = Path(tmp) / "projects" / remote.rsplit("/", 2)[-2]
        project.mkdir(parents=True, mode=0o700)
        target = project / f"{session}.jsonl"
        try:
            cp = run([rclone, "copyto", "--ask-password=false", "--", remote, str(target)], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300, env=_rclone_env(), check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BackupUnreachable(f"rclone could not copy ({type(exc).__name__})") from None
        if cp.returncode in RCLONE_NOT_FOUND:
            return False
        if cp.returncode != 0 or not target.is_file():
            raise BackupUnreachable(f"rclone copyto exit {cp.returncode}")
        try:
            found = provenance.find_user(session, f"lift hold {hold_id}", home=tmp, limit=50)
        except provenance.Problem as exc:
            raise BackupUnreachable(f"backed-up transcript unreadable: {exc}") from None
    return any(str(f.get("uuid", "")).lower() == uuid.lower() and lift_phrase_ok(f.get("preview", ""), hold_id)
               for f in found)


def record_integrity() -> str:
    """Run integrity.py record next to this file; a one-line status (never raises: the lift already happened)."""
    try:
        r = subprocess.run([sys.executable, "-I", "-S", str(HERE / "integrity.py"), "record"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"integrity record could not run ({type(exc).__name__}); run integrity.py record"
    last = (r.stdout.strip().splitlines() or [""])[-1][:200]
    return last if r.returncode == 0 else f"integrity record failed (exit {r.returncode}): {last}; run integrity.py record"


def lift(hold_id: str, source: str, policy: Path = POLICY, state_path: Path = STATE, finder=None, now=None,
         backup=None, record=None) -> str:
    ids = {h["id"] for h in json.loads(policy.read_text())["holds"]}
    if hold_id not in ids:
        raise ValueError(f"unknown hold {hold_id!r}; known: {', '.join(sorted(ids))}")
    parsed = verify_user_source(source, finder, hold_id)
    check = backup or backup_has_message
    try:
        in_backup = check(parsed["session"], parsed["uuid"], hold_id)
    except BackupUnreachable as exc:
        raise ValueError(f"the off-host transcript backup is unreachable ({exc}); refusing to lift (fail closed); "
                         "check `rclone lsd lessons-dropbox:` and retry") from None
    if not in_backup:
        raise ValueError(f"message {parsed['uuid']} is not in the off-host transcript backup yet; run the backup now: "
                         f"{BACKUP_RUN}, then retry")
    state = load_state(state_path)
    state["lifted"][hold_id] = {"source_uuid": parsed["uuid"], "session": parsed["session"],
                                "excerpt": parsed["excerpt"][:200], "at": int(time.time() if now is None else now)}
    write_state(state, state_path)
    status = (record or record_integrity)()
    return f"hold {hold_id} lifted by user message {parsed['uuid']} (verified locally and in the backup); {status}"


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
