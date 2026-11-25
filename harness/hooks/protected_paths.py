#!/usr/bin/env python3
"""The one list of instruction and configuration files an agent never writes (goodqa#17155).

An agent that can edit ~/.claude/CLAUDE.md, the settings files or the Codex config can change the rules that bind it,
so those files are written only by the user. Reads stay allowed. This module holds the list and the check; the
Write/Edit/NotebookEdit hook (protected_write_hook.py) imports it, and so can the Bash command guard, so there is a
single list. Standard library only.
"""

import fnmatch
import os
import posixpath

# Relative to a home directory; each segment is matched on its own (a `*` never crosses a `/`), case-insensitively.
PROTECTED_WRITE_GLOBS = (
    ".claude/CLAUDE.md",
    ".claude/settings*.json",
    ".codex/config.toml",
    ".codex/hooks.json",
)

REASON = ("%s is an instruction or configuration file that only the user changes. Agents may read it, never write it. "
          "Put the proposed change in your reply or a ticket, and the user applies it.")


def _segments(path):
    return [s for s in path.casefold().split("/") if s]


def _matches(rel_segments):
    for pattern in PROTECTED_WRITE_GLOBS:
        parts = _segments(pattern)
        if len(parts) == len(rel_segments) and all(fnmatch.fnmatchcase(r, p) for r, p in zip(rel_segments, parts)):
            return True
    return False


def _original_case(path, count):
    """The last `count` segments of `path` as spelled (the match itself is case-insensitive)."""
    return [s for s in path.split("/") if s][-count:]


def _homes(home):
    homes = {posixpath.normpath(home)}
    try:
        homes.add(os.path.realpath(home))
    except OSError:
        pass
    return homes


def _under_home(path, homes):
    folded = _segments(path)
    for h in homes:
        base = _segments(h)
        if folded[:len(base)] == base and len(folded) > len(base):
            yield folded[len(base):]


def _protected_inodes(homes):
    found = set()
    for h in homes:
        for pattern in PROTECTED_WRITE_GLOBS:
            directory, _, name = pattern.rpartition("/")
            folder = os.path.join(h, directory)
            try:
                entries = os.listdir(folder)
            except OSError:
                continue
            for entry in entries:
                if fnmatch.fnmatchcase(entry.casefold(), name.casefold()):
                    try:
                        info = os.stat(os.path.join(folder, entry))  # follows a symlink: its real target is protected too
                    except OSError:
                        continue
                    found.add((info.st_dev, info.st_ino))
    return found


def protected_write_refusal(path, home=None, cwd=None):
    """A refusal sentence when writing `path` would change a protected file, else None.

    The path is checked as spelled (after ~ and .. are resolved), after symlinks are followed, and, for an existing
    file with extra links, by inode, so neither a symlink nor a hard link to a protected file is a way around it."""
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        return None
    home = home or os.path.expanduser("~")
    text = path.strip()
    if text == "~" or text.startswith("~/"):
        text = home + text[1:]
    if not text.startswith("/"):
        text = posixpath.join(cwd or os.getcwd(), text)
    spelled = posixpath.normpath(text)
    candidates = {spelled}
    try:
        candidates.add(os.path.realpath(spelled))
    except OSError:
        pass
    homes = _homes(home)
    for candidate in candidates:
        for rel in _under_home(candidate, homes):
            if _matches(rel):
                return REASON % ("~/" + "/".join(_original_case(candidate, len(rel))))
    try:
        info = os.stat(spelled)
        if (info.st_dev, info.st_ino) in _protected_inodes(homes):
            return REASON % "this path (the same file as a protected one: a hard link or the target of a protected symlink)"
    except OSError:
        pass
    return None
