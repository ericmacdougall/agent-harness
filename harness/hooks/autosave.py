#!/usr/bin/env python3
"""Stop, SubagentStop and SessionEnd hook: save what the session's checkouts hold nowhere else (docs/lifecycle.md).

For each git checkout under ~/.agent-harness/work/<session>/ (a bounded search, at most 20 checkouts, children first)
it calls git_save.save, all inside one budget of 20 seconds. An unchanged checkout is answered from git_save's state
file and costs no network call. Unpushed commits, stashes and working-tree changes end up on the rescue remote or in
a verified bundle, which is what lets `ah reap` remove the folder later without losing work.
It prints nothing when everything is saved and one line on stderr when something is not. It always exits 0 and
writes nothing to stdout, so it never blocks a turn from ending. No command text is read. About every ten minutes it
also measures the folder (at most 2 seconds) and records the size in the session's state file
(session_env.state_file), which session_env.py reads at the next session start. Standard library only.
"""
from __future__ import annotations

import collections
import fcntl
import os
import re
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import ah_log_push  # noqa: E402  (shown_url: a reason never carries a credential)
    import git_save  # noqa: E402
    import safe_input  # noqa: E402
    import session_env  # noqa: E402
    import workdir  # noqa: E402
except ImportError:   # a partial install must not fail the end of a turn
    if __name__ == "__main__":
        sys.exit(0)
    raise

BUDGET_S = 20          # every save of one run together
MAX_CHECKOUTS = 20
WALK_ENTRIES = 20000   # directory entries looked at while searching for checkouts
SIZE_SECONDS = 2.0     # the size walk stops here; what it counted by then is recorded as a lower bound
SIZE_EVERY_S = 600


def checkouts(folder):
    """([checkout paths, deepest first], more): directories under `folder` that hold a `.git` entry, and bare
    repositories. Symlinks, `.git` itself and rebuildable directories are not entered. `more` is True when the search
    stopped at a limit, so there may be checkouts it did not list."""
    found, seen, more, queue = [], 0, False, collections.deque([(str(folder), 0)])
    while queue and not more:
        path, depth = queue.popleft()
        try:
            with os.scandir(path) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            continue
        names = {entry.name for entry in children}
        bare = ".git" not in names and {"HEAD", "objects", "refs"} <= names
        seen += len(children)
        if ".git" in names or bare:
            found.append((-depth, path))
        more = len(found) > MAX_CHECKOUTS or seen > WALK_ENTRIES
        queue.extend((entry.path, depth + 1) for entry in children
                     if not bare and entry.name != ".git" and entry.is_dir(follow_symlinks=False)
                     and not git_save.rebuildable(entry.path))
    return [path for _depth, path in sorted(found[:MAX_CHECKOUTS])], more


def measure(folder, tmp) -> dict:
    """{"bytes", "complete", "top": [[name, bytes], ...]} for the folder plus the session temp directory, with the
    three largest directories directly inside. Symlinks are not followed. `complete` False means the time ran out
    and `bytes` is a lower bound."""
    deadline, seen, sizes = time.monotonic() + SIZE_SECONDS, 0, collections.Counter()
    stack = [(str(folder), None)]
    if os.path.isdir(tmp) and not os.path.islink(tmp):
        stack.append((str(tmp), "temp files (%s)" % tmp))
    while stack:
        path, top = stack.pop()
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    sizes[top or (entry.name if stat.S_ISDIR(info.st_mode) else "")] += info.st_blocks * 512
                    if stat.S_ISDIR(info.st_mode):
                        stack.append((entry.path, top or entry.name))
                    seen += 1
                    if seen % 512 == 0 and time.monotonic() > deadline:
                        stack = []
                        break
        except OSError:
            continue   # a directory that vanished or cannot be read is not counted
    largest = [[name, size] for name, size in sizes.most_common() if name][:3]
    return {"bytes": sum(sizes.values()), "complete": time.monotonic() <= deadline, "top": largest}


def run(session) -> str:
    """Save every checkout of the session. Returns the one line to report, or '' when everything is saved."""
    folder = workdir.work_root() / workdir.safe_name(session)
    if folder.is_symlink() or not folder.is_dir():
        return ""
    started, state_path = time.monotonic(), str(session_env.state_file(folder.name))
    git_save._mkdirs(os.path.dirname(state_path))
    with open(state_path + ".lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return ""   # another run for this session is saving right now
        found, more = checkouts(folder)
        unsaved = []
        for path in found:
            rel, left = os.path.relpath(path, str(folder)), BUDGET_S - (time.monotonic() - started)
            result = (git_save.save(path, folder.name, "top" if rel == "." else rel, budget_s=left) if left >= 1
                      else {"ok": False, "reason": "the %d second budget ran out" % BUDGET_S})
            if not result["ok"]:
                reason = ah_log_push.shown_url(result.get("reason") or "not saved")[:200]
                unsaved.append({"path": rel, "reason": reason})
        state = git_save._read_json(state_path)
        state.update(folder=str(folder), at=time.time(), unsaved=unsaved, more=more)
        sized = state.get("sized_at")
        if not isinstance(sized, (int, float)) or time.time() - sized >= SIZE_EVERY_S:
            state.update(measure(folder, session_env.tmp_dir(folder.name)), sized_at=time.time())
        git_save._write_json(state_path, state)
    notes = []
    if unsaved:
        notes.append("%d of %d checkouts not saved (%s)" % (len(unsaved), len(found), "; ".join(
            "%s: %s" % (item["path"], item["reason"]) for item in unsaved[:3])))
    if more:
        notes.append("the search stopped at its limit, so other checkouts may not be saved")
    text = "autosave: %s: %s. Nothing was deleted." % (folder, "; ".join(notes))
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text)[:600] if notes else ""


def main() -> int:
    try:
        data = safe_input.safe_json_loads(safe_input.read_stdin_bounded(256 * 1024) or b"{}")
        session = data.get("session_id") if isinstance(data, dict) else None
        if isinstance(session, str) and session.strip():
            line = run(session)
            if line:
                sys.stderr.write(line + "\n")
    except Exception as error:   # noqa: BLE001  this hook never fails or blocks the end of a turn
        sys.stderr.write("autosave: skipped (%s)\n" % type(error).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
