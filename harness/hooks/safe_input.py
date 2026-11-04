#!/usr/bin/env python3
"""Bounded, validated input for every hook: one implementation of "never trust a path, a stream or a JSON text".

Why this exists: a hook that did `open(transcript_path).read()` was pointed at /dev/zero by a red-team test and
grew to tens of GB; a hook that opened a FIFO would block forever; Python 3.9 aborts the whole interpreter on very
deep JSON. A hook must treat every path, stdin and JSON text it did not write as hostile.

API (stdlib only, Python 3.9):
  open_regular_file(path, allowed_roots=None, max_bytes=None) -> fd   regular files only, re-checked after open
  read_bounded(path, max_bytes, allowed_roots=None) -> bytes          whole small file, or InputRejected
  read_tail(path, window, allowed_roots=None) -> bytes                at most the last `window` bytes
  read_stdin_bounded(max_bytes) -> bytes                              never more than max_bytes (+1 to detect overflow)
  safe_json_loads(data, max_depth, max_bytes) -> object              byte and nesting limits; ValueError otherwise
  iter_jsonl_lines(path, ...) -> yields (number, line-or-None)        per-line cap, optional byte and time budget

Every rejection is `InputRejected(code, message)`; hooks catch it, say so on stderr and fail open or closed as
their own policy says. Nothing here raises on a hostile input except InputRejected or ValueError.
tests/test_input_lint.py fails the suite on new unbounded reads in harness/hooks.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time

MAX_JSON_DEPTH = 100  # default of safe_json_loads(text, max_depth=100), shared with domain_gates and review_map
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
DEFAULT_STDIN_BYTES = 4 * 1024 * 1024
_STRUCTURE = re.compile(rb'["\\\[\]{}]')


class InputRejected(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _short(value, limit: int = 60) -> str:
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", str(value))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _inside(real: str, roots) -> bool:
    for root in roots:
        base = os.path.realpath(os.fspath(root))
        try:
            if os.path.commonpath([real, base]) == base:
                return True
        except ValueError:  # different drives or mixed absolute and relative
            continue
    return False


def open_regular_file(path, allowed_roots=None, max_bytes=None) -> int:
    """Read-only fd of a regular file. Rejects devices, FIFOs, sockets, directories, and symlinks (resolved first)
    that land outside allowed_roots or on a non-regular file. The path is checked, opened without blocking or
    following a final symlink, and checked again on the fd (a swap between check and open is rejected)."""
    try:
        real = os.path.realpath(os.fspath(path))
        if allowed_roots is not None and not _inside(real, allowed_roots):
            raise InputRejected("file-outside-root", "path is outside the allowed directories")
        before = os.lstat(real)
        if not stat.S_ISREG(before.st_mode):
            raise InputRejected("file-not-regular", "path is not a regular file (device, FIFO, socket or directory)")
        fd = os.open(real, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except InputRejected:
        raise
    except (OSError, ValueError, TypeError) as error:
        raise InputRejected("file-unreadable", f"cannot open {_short(os.path.basename(str(path)))} ({type(error).__name__})")
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise InputRejected("file-changed", "file changed between check and open")
        if max_bytes is not None and after.st_size > max_bytes:
            raise InputRejected("file-too-large", f"file is larger than {max_bytes} bytes")
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_bounded(path, max_bytes: int, allowed_roots=None) -> bytes:
    """The whole file when it is at most max_bytes; InputRejected otherwise. Never reads more than max_bytes+1."""
    fd = open_regular_file(path, allowed_roots)
    try:
        data = os.read(fd, max_bytes + 1)
    except OSError as error:
        raise InputRejected("file-unreadable", f"cannot read file ({type(error).__name__})")
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise InputRejected("file-too-large", f"file is larger than {max_bytes} bytes")
    return data


def read_tail(path, window: int, allowed_roots=None) -> bytes:
    """At most the last `window` bytes of a regular file, however large the file is."""
    fd = open_regular_file(path, allowed_roots)
    try:
        size = os.fstat(fd).st_size
        return os.pread(fd, min(window, size), max(0, size - window))
    except OSError as error:
        raise InputRejected("file-unreadable", f"cannot read file ({type(error).__name__})")
    finally:
        os.close(fd)


def read_stdin_bounded(max_bytes: int = DEFAULT_STDIN_BYTES) -> bytes:
    """stdin up to max_bytes; InputRejected when there is more (e.g. stdin redirected from /dev/zero)."""
    chunks, total = [], 0
    try:
        while total <= max_bytes:
            chunk = os.read(0, min(1 << 20, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError as error:
        raise InputRejected("stdin-unreadable", f"cannot read stdin ({type(error).__name__})")
    if total > max_bytes:
        raise InputRejected("stdin-too-large", f"stdin is larger than {max_bytes} bytes")
    return b"".join(chunks)


def safe_json_loads(text, max_depth: int = MAX_JSON_DEPTH, max_bytes: int = MAX_JSON_BYTES):
    """json.loads for untrusted text or bytes. Python 3.9 can abort the interpreter outright on deeply nested JSON
    instead of raising RecursionError, so size and nesting are checked first. Raises ValueError, never aborts."""
    data = text
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    elif isinstance(data, bytearray):
        data = bytes(data)
    if len(data) > max_bytes:
        raise ValueError("JSON input too large")
    if data.count(b"[") + data.count(b"{") > max_depth:  # depth cannot exceed the bracket count: cheap bound first
        depth, in_string, skip = 0, False, -1
        for token in _STRUCTURE.finditer(data):  # linear: structural bytes only
            at = token.start()
            if at == skip:
                continue
            char = token.group()
            if in_string:
                if char == b"\\":
                    skip = at + 1
                elif char == b'"':
                    in_string = False
            elif char == b'"':
                in_string = True
            elif char in (b"[", b"{"):
                depth += 1
                if depth > max_depth:
                    raise ValueError("JSON nested too deeply")
            elif char in (b"]", b"}"):
                depth -= 1
    try:
        return json.loads(data)
    except RecursionError:
        raise ValueError("JSON nested too deeply")


def iter_jsonl_lines(path, max_line: int = MAX_LINE_BYTES, max_total_bytes=None, max_seconds=None, allowed_roots=None):
    """Yield (line_number, line_bytes) for a regular file, reading each line with a hard cap. An over-long line is
    yielded once as (line_number, None) and the rest of it skipped. Stops quietly at the byte or time budget."""
    fd = open_regular_file(path, allowed_roots)
    deadline = None if max_seconds is None else time.monotonic() + max_seconds
    total = 0
    try:
        with os.fdopen(fd, "rb", closefd=False) as handle:
            number = 0
            while True:
                line = handle.readline(max_line + 1)
                if not line:
                    return
                number += 1
                total += len(line)
                if len(line) > max_line and not line.endswith(b"\n"):
                    while True:  # drain the remainder of the oversized line in bounded pieces
                        rest = handle.readline(max_line)
                        total += len(rest)
                        if not rest or rest.endswith(b"\n"):
                            break
                        if max_total_bytes is not None and total > max_total_bytes:
                            return
                    yield number, None
                else:
                    yield number, line.rstrip(b"\r\n") if line.endswith(b"\n") else line
                if max_total_bytes is not None and total > max_total_bytes:
                    return
                if deadline is not None and number % 256 == 0 and time.monotonic() > deadline:
                    return
    finally:
        os.close(fd)


def note(tool: str, rejected: InputRejected) -> None:
    """The standard one-line stderr note for a rejected input (no payload text, short, single line)."""
    print(f"{tool}: input rejected ({rejected.code}); skipped", file=sys.stderr)
