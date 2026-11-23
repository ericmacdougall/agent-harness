#!/usr/bin/env python3
"""WAL segments: the single owner of the 50 MiB rotation contract (docs/wal-segments.md, docs/spec/wal-segments.md).

Names: the live WAL `<stem>.jsonl` is always the newest segment; closed segments are `<stem>.NNNN.jsonl` (oldest
first, contiguous from 0001). The first line of every live file created by a rotation is a `wal_segment_open`
marker that links to its predecessor (prev name, bytes, lines, sha256). Rotation only renames (exclusively, never
over an existing name) and creates; it never truncates, rewrites or deletes a WAL. The only truncation in this
module is the pre-existing removal of an unterminated torn tail line of the live file (`_repair_tail`).

Writers call `append_line`; every reader uses `open_chain`, `iter_lines`, `read_tail`, `list_wals`, `exists`.
CLI: wal_segments.py {map,verify,cat,reindex} DIR [STEM].
"""

import argparse
import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 1
SEGMENT_BYTES = 50 * 1024 * 1024
PROD_FLOOR = 1024 * 1024
MARKER_ONLY_BYTES = 1024
MAX_RETRIES = 8
SEGMENT_RE = re.compile(r"^(?P<stem>.+)\.(?P<seq>\d{4,})\.jsonl$")
STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
MARKER_EVENT = "wal_segment_open"
MARKER_BY = "wal_segments"
FAULT_STEPS = ("after_hash", "after_rename", "after_create", "after_marker", "after_index")


class SegmentProblem(Exception):
    """Raised by strict readers instead of reading past a problem."""

    def __init__(self, code, message, seq=None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.seq = code, message, seq


class RotateFailed(Exception):
    """Rotation failed after the rename and could not be undone; the record was NOT written anywhere."""


def warn(code, detail=""):
    print(f"wal_segments: {code} {detail}".rstrip(), file=sys.stderr)


def parse_name(filename):
    """(stem, seq) for `<stem>.NNNN.jsonl`, (stem, None) for `<stem>.jsonl`, (None, None) otherwise."""
    m = SEGMENT_RE.match(filename)
    if m:
        return m.group("stem"), int(m.group("seq"))
    if filename.endswith(".jsonl") and len(filename) > 6:
        return filename[:-6], None
    return None, None


def segment_name(stem, seq):
    return f"{stem}.{seq:04d}.jsonl"


def is_segment_shaped_stem(stem):
    return re.search(r"\.\d{4,}$", stem) is not None


# ---------------------------------------------------------------------------------------------------------
# configuration (test-only overrides are ignored outside a test sandbox)
# ---------------------------------------------------------------------------------------------------------

def test_mode():
    if os.environ.get("HARNESS_TEST") != "1":
        return False
    home = os.path.realpath(str(Path.home()))
    roots = {os.path.realpath(tempfile.gettempdir()), os.path.realpath("/tmp"), os.path.realpath("/var/tmp")}
    return any(home == r or home.startswith(r + os.sep) for r in roots)


def segment_limit():
    if test_mode():
        try:
            return max(1, int(os.environ.get("HARNESS_WAL_SEGMENT_BYTES", SEGMENT_BYTES)))
        except ValueError:
            return SEGMENT_BYTES
    return SEGMENT_BYTES


def enable_file():
    return Path.home() / ".agent-harness" / "state" / "wal-rotation.on"


def rotation_enabled():
    try:
        return enable_file().is_file()
    except OSError:
        return False


def _fault(step):
    if test_mode() and os.environ.get("HARNESS_WAL_FAULT") == step:
        os._exit(77)
    if test_mode() and os.environ.get("HARNESS_WAL_PAUSE") == step:
        marker = os.environ.get("HARNESS_WAL_PAUSE_FILE")
        if marker:
            Path(marker).write_text("paused")
            deadline = time.time() + 20
            while os.path.exists(marker) and time.time() < deadline:
                time.sleep(0.01)


# ---------------------------------------------------------------------------------------------------------
# directory scan and chain
# ---------------------------------------------------------------------------------------------------------

class Seg:
    __slots__ = ("seq", "name", "kind", "size", "ino")

    def __init__(self, seq, name, kind, size, ino):
        self.seq, self.name, self.kind, self.size, self.ino = seq, name, kind, size, ino

    def as_dict(self):
        return {"seq": self.seq, "name": self.name, "bytes": self.size, "kind": self.kind}


class Chain:
    """Directory-derived view of one logical WAL. `problems` is a list of {code, message, seq}."""

    def __init__(self, directory, stem):
        self.directory, self.stem = directory, stem
        self.segments = []   # closed segments, ascending seq (regular files only)
        self.live = None
        self.problems = []
        self.max_seq = 0

    def problem(self, code, message, seq=None):
        self.problems.append({"code": code, "message": message, "seq": seq})

    @property
    def complete(self):
        return not [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")]

    def path(self, seg):
        return os.path.join(self.directory, seg.name)


def _scan(directory_or_fd, stem=None):
    """{stem: ({seq: [names]}, live_name_or_None)} for a directory path or fd."""
    out = {}
    with os.scandir(directory_or_fd) as it:
        for entry in it:
            s, seq = parse_name(entry.name)
            if s is None or entry.name.startswith("."):
                continue
            if stem is not None and s != stem:
                continue
            slot = out.setdefault(s, ({}, []))
            if seq is None:
                slot[1].append(entry.name)
            else:
                slot[0].setdefault(seq, []).append(entry.name)
    return out


def _build_chain(directory, stem, scan_dir, dfd=None):
    ch = Chain(directory, stem)

    def lstat_name(name):  # stat relative to the pinned directory fd when given, never the cwd
        return os.lstat(name, dir_fd=dfd) if dfd is not None else os.lstat(os.path.join(directory, name))

    seqs, lives = scan_dir.get(stem, ({}, []))
    ch.max_seq = max(seqs) if seqs else 0
    for seq in sorted(seqs):
        names = seqs[seq]
        if len(names) > 1:
            ch.problem("ambiguous", f"{len(names)} names parse to segment {seq}: {sorted(names)}", seq)
            continue
        name = names[0]
        try:
            st = lstat_name(name)
        except OSError as error:
            ch.problem("unreadable", f"{name}: {type(error).__name__}", seq)
            continue
        if not stat.S_ISREG(st.st_mode):
            ch.problem("not_regular", f"{name} is not a regular file (never followed)", seq)
            continue
        ch.segments.append(Seg(seq, name, "segment", st.st_size, st.st_ino))
    present = sorted(seqs)
    if present:  # gaps are reported as [lo, hi] ranges, never enumerated
        expect = 1
        for seq in present:
            if seq > expect:
                ch.problem("gap", f"segments {expect}..{seq - 1} are missing" if seq - 1 > expect else f"segment {expect} is missing", expect)
            expect = seq + 1
    if lives:
        try:
            st = lstat_name(lives[0])
            if stat.S_ISREG(st.st_mode):
                ch.live = Seg(ch.max_seq + 1, lives[0], "live", st.st_size, st.st_ino)
            else:
                ch.problem("not_regular", f"{lives[0]} is not a regular file (never followed)", ch.max_seq + 1)
        except OSError as error:
            ch.problem("unreadable", f"{lives[0]}: {type(error).__name__}", ch.max_seq + 1)
    elif present:
        ch.problem("live_missing", "no live file (a crashed rotation; the next append or `reindex --write` repairs it)")
    return ch


def chain(directory, stem):
    directory = str(directory)
    return _build_chain(directory, stem, _scan(directory, stem))


def list_wals(directory):
    """{stem: Chain} for every logical WAL in a directory; segment files are folded into their stem."""
    directory = str(directory)
    scan = _scan(directory)
    return {stem: _build_chain(directory, stem, scan) for stem in sorted(scan)}


def exists(path):
    """True when the live file or any closed segment of this WAL exists (a crashed rotation still counts)."""
    path = str(path)
    d, name = os.path.split(path)
    stem, seq = parse_name(name)
    if stem is None:
        return False
    if os.path.lexists(path):
        return True
    try:
        with os.scandir(d or ".") as it:
            return any(SEGMENT_RE.match(e.name) and SEGMENT_RE.match(e.name).group("stem") == stem for e in it)
    except OSError:
        return False


def _open_regular(directory, name):
    fd = os.open(os.path.join(directory, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def parse_marker(raw):
    """The marker dict when `raw` (line bytes) is an exact open marker, else None."""
    if not raw or MARKER_EVENT.encode() not in raw:
        return None
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    if (isinstance(rec, dict) and rec.get("event") == MARKER_EVENT and rec.get("by") == MARKER_BY
            and isinstance(rec.get("segment"), int) and isinstance(rec.get("stem"), str)):
        return rec
    return None


def _first_line(fd, limit=8192):
    return os.pread(fd, limit, 0).split(b"\n", 1)[0]


# ---------------------------------------------------------------------------------------------------------
# reader snapshot
# ---------------------------------------------------------------------------------------------------------

class Snapshot:
    """A consistent point-in-time read of one logical WAL. Opens the live fd FIRST, then lists the directory, then
    reconciles by inode, so a concurrent rotation yields neither a duplicated nor a lost pre-snapshot line."""

    def __init__(self, path, strict=False, include_markers=False, max_total_bytes=None):
        self.directory, name = os.path.split(str(path))
        self.directory = self.directory or "."
        self.stem, _ = parse_name(name)
        if self.stem is None:
            raise SegmentProblem("bad_name", f"not a WAL name: {name}")
        self.strict, self.include_markers, self.max_total_bytes = strict, include_markers, max_total_bytes
        self.problems = []
        self.live_fd = None
        self.live_ino = None
        live_name = self.stem + ".jsonl"
        try:
            self.live_fd = _open_regular(self.directory, live_name)
            self.live_ino = os.fstat(self.live_fd).st_ino
        except OSError as error:
            if error.errno not in (errno.ENOENT,):
                self.problems.append({"code": "not_regular" if error.errno in (errno.ELOOP, errno.EINVAL) else "unreadable",
                                      "message": f"{live_name}: {type(error).__name__}", "seq": None})
        _fault_reader()
        self.chain = chain(self.directory, self.stem)
        self.problems.extend(p for p in self.chain.problems
                             if not (p["code"] == "live_missing" and self.live_fd is not None))
        # an fd opened before a rotation is now a closed segment: it is the last segment of the snapshot, and the
        # new live file (written after our snapshot) is beyond it
        self.tail_fd, self.tail_name = self.live_fd, live_name
        if self.live_fd is not None:
            for seg in self.chain.segments:
                if seg.ino == self.live_ino:
                    self.tail_name = seg.name
                    self.chain.segments = [s for s in self.chain.segments if s.seq <= seg.seq]
                    self.chain.live = None
                    break
        if self.strict and [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")]:
            first = [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")][0]
            self.close()
            raise SegmentProblem(first["code"], first["message"], first.get("seq"))

    def close(self):
        if self.live_fd is not None:
            try:
                os.close(self.live_fd)
            except OSError:
                pass
            self.live_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    def _sources(self):
        """[(name, fd_or_None)] in order; closed segments are opened lazily by name, the tail by its pinned fd."""
        out = [(s.name, None) for s in self.chain.segments if s.name != self.tail_name]
        if self.tail_fd is not None:
            out.append((self.tail_name, self.tail_fd))
        return out

    @property
    def complete(self):
        return not [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")]

    def lines(self):
        """Yield (segment_name, logical_line_no, raw_bytes_without_newline); markers are skipped unless asked for.
        A line longer than 8 MiB is yielded as None. Budget exhaustion adds a `truncated` problem."""
        total, number = 0, 0
        for name, fd in self._sources():
            own = fd is None
            try:
                if own:
                    fd = _open_regular(self.directory, name)
                with os.fdopen(os.dup(fd), "rb") as handle:
                    handle.seek(0)
                    first = True
                    while True:
                        raw = handle.readline(8 * 1024 * 1024 + 1)
                        if not raw:
                            break
                        total += len(raw)
                        if first:
                            first = False
                            if parse_marker(raw.rstrip(b"\r\n")) is not None and not self.include_markers:
                                continue
                        number += 1
                        yield name, number, (raw.rstrip(b"\r\n") if len(raw) <= 8 * 1024 * 1024 else None)
                        if self.max_total_bytes is not None and total > self.max_total_bytes:
                            self.problems.append({"code": "truncated", "message": f"read budget of {self.max_total_bytes} bytes reached in {name}", "seq": None})
                            if self.strict:
                                raise SegmentProblem("truncated", "read budget reached")
                            return
            except OSError as error:
                self.problems.append({"code": "unreadable", "message": f"{name}: {type(error).__name__}", "seq": None})
                if self.strict:
                    raise SegmentProblem("unreadable", name)
            finally:
                if own and fd is not None:
                    os.close(fd)

    def read_tail(self, window):
        """At most the last `window` bytes of the logical stream (markers dropped), newest segment first."""
        pieces, left = [], window
        sources = self._sources()
        for name, fd in reversed(sources):
            if left <= 0:
                break
            own = fd is None
            try:
                if own:
                    fd = _open_regular(self.directory, name)
                size = os.fstat(fd).st_size
                start = max(0, size - left)
                data = os.pread(fd, size - start, start)
                if start == 0:
                    first, _, rest = data.partition(b"\n")
                    if parse_marker(first) is not None and not self.include_markers:
                        data = rest
                pieces.append(data)
                left -= (size - start)
            except OSError as error:
                self.problems.append({"code": "unreadable", "message": f"{name}: {type(error).__name__}", "seq": None})
                if self.strict:
                    raise SegmentProblem("unreadable", name)
            finally:
                if own and fd is not None:
                    os.close(fd)
        if left > 0 and self.max_total_bytes is not None:
            pass
        return b"".join(reversed(pieces))


def _fault_reader():
    if test_mode() and os.environ.get("HARNESS_WAL_READER_PAUSE") == "after_open":
        marker = os.environ.get("HARNESS_WAL_PAUSE_FILE")
        if marker:
            Path(marker).write_text("reader-paused")
            deadline = time.time() + 20
            while os.path.exists(marker) and time.time() < deadline:
                time.sleep(0.01)


def open_chain(path, **kw):
    return Snapshot(path, **kw)


def iter_lines(path, strict=False, include_markers=False, max_total_bytes=None, problems=None):
    """Drop-in for a reader's `for raw in open(path)` loop: yields (segment, logical_line_no, bytes). Problems are
    appended to `problems` (a list) when given; strict=True raises SegmentProblem instead of reading past one."""
    with Snapshot(path, strict=strict, include_markers=include_markers, max_total_bytes=max_total_bytes) as snap:
        try:
            yield from snap.lines()
        finally:
            if problems is not None:
                problems.extend(snap.problems)


def read_tail(path, window, problems=None, strict=False):
    with Snapshot(path, strict=strict) as snap:
        data = snap.read_tail(window)
        if problems is not None:
            problems.extend(snap.problems)
        return data


def read_logical(path, max_bytes=None, problems=None):
    """The whole logical WAL as bytes (markers dropped); `max_bytes` bounds it and reports `truncated`."""
    out, size = [], 0
    with Snapshot(path, max_total_bytes=max_bytes) as snap:
        for _, _, raw in snap.lines():
            if raw is None:
                continue
            out.append(raw)
            size += len(raw) + 1
        if problems is not None:
            problems.extend(snap.problems)
    return b"".join(x + b"\n" for x in out)


# ---------------------------------------------------------------------------------------------------------
# exclusive rename
# ---------------------------------------------------------------------------------------------------------

_libc = None


def _exclusive_rename(dir_fd, old, new):
    """rename(old, new) that fails with FileExistsError instead of replacing `new`; NotImplementedError when the
    platform has no such call (the caller then skips rotation and appends to the live file)."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    o, n = old.encode(), new.encode()
    if sys.platform == "darwin":
        fn = getattr(_libc, "renameatx_np", None)
        if fn is None:
            raise NotImplementedError("renameatx_np")
        rc = fn(dir_fd, o, dir_fd, n, 0x4)  # RENAME_EXCL
    else:
        fn = getattr(_libc, "renameat2", None)
        if fn is None:
            raise NotImplementedError("renameat2")
        rc = fn(dir_fd, o, dir_fd, n, 1)  # RENAME_NOREPLACE
    if rc != 0:
        err = ctypes.get_errno()
        if err in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
            raise NotImplementedError(os.strerror(err))
        if err == errno.EEXIST:
            raise FileExistsError(new)
        raise OSError(err, os.strerror(err), new)


# ---------------------------------------------------------------------------------------------------------
# writer
# ---------------------------------------------------------------------------------------------------------

def _repair_tail(fd, current_target):
    """A killed writer may leave an unterminated final record: remove only that suffix under the lock (the sole
    truncation in this module; it never touches a terminated line)."""
    end = os.lseek(fd, 0, os.SEEK_END)
    if end and os.pread(fd, 1, end - 1) != b"\n":
        scan = min(end, 65_536)
        tail = os.pread(fd, scan, end - scan)
        last_newline = tail.rfind(b"\n")
        if last_newline < 0 and end > scan:
            raise ValueError("WAL crash tail exceeds recovery budget")
        os.ftruncate(fd, end - scan + last_newline + 1)
        if not current_target():
            raise ValueError("WAL target changed during crash recovery")


def _hash_fd(fd):
    h, size, lines = hashlib.sha256(), 0, 0
    while True:
        block = os.pread(fd, 1 << 20, size)
        if not block:
            break
        h.update(block)
        lines += block.count(b"\n")
        size += len(block)
    return h.hexdigest(), size, lines


def _now():
    return datetime.now(timezone.utc).isoformat()


def _marker(stem, seq, prev_name, prev_bytes, prev_lines, prev_sha):
    rec = {"at": _now(), "event": MARKER_EVENT, "by": MARKER_BY, "schema": SCHEMA, "stem": stem, "segment": seq,
           "prev": prev_name, "prev_bytes": prev_bytes, "prev_lines": prev_lines, "prev_sha256": prev_sha,
           "limit": segment_limit()}
    return (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def _next_seq(directory_fd, stem, live_fd=None):
    seqs = _scan(directory_fd, stem).get(stem, ({}, []))[0]
    top = max(seqs) if seqs else 0
    if live_fd is not None:
        m = parse_marker(_first_line(live_fd))
        if m and m["stem"] == stem:
            top = max(top, m["segment"] - 1)
    return top + 1


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _rotate(dir_fd, stem, name, fd, current_target):
    """Rename the live file (fd) to the next segment, create the new live file with its open marker, rewrite the
    index. Returns the new live fd (the old fd is closed). Raises RotateFailed when the rename could not be undone."""
    sha, size, lines = _hash_fd(fd)
    _fault("after_hash")
    seq = _next_seq(dir_fd, stem, fd)
    current_max = max(_scan(dir_fd, stem).get(stem, ({}, []))[0] or {0: 0})
    if seq > current_max + 1000:
        warn("seq_implausible", f"{seq}; rotation refused")
        return fd
    seg = segment_name(stem, seq)
    try:
        _exclusive_rename(dir_fd, name, seg)
    except FileExistsError:
        warn("rotate_collision", f"{seg} already exists; rotation skipped")
        return fd
    except NotImplementedError as error:
        warn("rotate_unsupported", str(error))
        return fd
    os.fsync(dir_fd)
    _fault("after_rename")
    try:
        new_fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
    except OSError as error:
        try:
            _exclusive_rename(dir_fd, seg, name)
            os.fsync(dir_fd)
        except FileExistsError:  # an old writer recreated the live name: that file IS the live file (R3-8)
            warn("rotate_create_failed", f"{type(error).__name__}; live name recreated by another writer")
            return None
        except (OSError, NotImplementedError):
            raise RotateFailed(f"create of {name} failed ({type(error).__name__}) and the rename could not be undone")
        warn("rotate_create_failed", f"{type(error).__name__}; rotation undone")
        return fd
    try:
        os.fchmod(new_fd, 0o600)
        fcntl.flock(new_fd, fcntl.LOCK_EX)
        os.fsync(dir_fd)
        _fault("after_create")
        _write_all(new_fd, _marker(stem, seq + 1, seg, size, lines, sha))
        os.fsync(new_fd)
        _fault("after_marker")
    except BaseException:
        os.close(new_fd)
        raise
    try:
        write_index(dir_fd, stem)
    except Exception as error:  # noqa: BLE001 - the index is derived and advisory: never fail an append over it
        warn("index_failed", type(error).__name__)
    _fault("after_index")
    os.close(fd)
    return new_fd


def _finish_live(dir_fd, stem, fd):
    """Recovery rule: an empty live file next to closed segments (crash after create) gets its open marker."""
    scan = _scan(dir_fd, stem).get(stem, ({}, []))[0]
    if not scan or os.fstat(fd).st_size:
        return
    top = max(scan)
    prev = segment_name(stem, top)
    pfd = None
    try:
        pfd = os.open(prev, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        sha, size, lines = _hash_fd(pfd)
    except OSError:
        return
    finally:
        if pfd is not None:
            os.close(pfd)
    _write_all(fd, _marker(stem, top + 1, prev, size, lines, sha))
    os.fsync(fd)


def append_line(dir_fd, name, payload, current_directory=None, retry_sleep=0.01):
    """Append one complete JSONL line to `name` in the pinned directory `dir_fd`, rotating at the segment limit.
    Lock order: seglock, live open, data flock, target check. Raises ValueError for an unsafe target."""
    stem, seq = parse_name(name)
    if stem is None or seq is not None or is_segment_shaped_stem(stem):
        raise ValueError("WAL name is reserved or invalid")
    check_dir = current_directory or (lambda: True)
    rotate_on = rotation_enabled()
    lock_fd = None
    lock_name = f".{stem}.seglock"  # taken on every append, switch or not, so flipping the switch cannot race
    try:
        lock_fd = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
        info = os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError(errno.EINVAL, "seglock is not a plain file")
        os.fchmod(lock_fd, 0o600)
        deadline = time.monotonic() + (float(os.environ.get("HARNESS_WAL_LOCK_WAIT", "2")) if test_mode() else 2.0)
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise
                if time.monotonic() > deadline:
                    warn("seglock_timeout", "rotation skipped for this append")
                    os.close(lock_fd)
                    lock_fd, rotate_on = None, False
                    break
                time.sleep(0.01)
    except OSError as error:
        warn("seglock_unusable", type(error).__name__)
        if lock_fd is not None:
            os.close(lock_fd)
        lock_fd, rotate_on = None, False
    recover_on = lock_fd is not None  # the recovery rule needs the seglock, not the switch
    try:
        for attempt in range(MAX_RETRIES):
            if not check_dir():
                raise ValueError("WAL session directory changed")
            fd = None
            for tries in range(4):
                try:
                    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
                    break
                except FileNotFoundError:
                    # A concurrent first write has occasionally observed ENOENT on macOS despite O_CREAT. Retry only
                    # while the named session directory still resolves to the pinned inode.
                    if tries == 3 or not check_dir():
                        raise
                    time.sleep(retry_sleep * (tries + 1))
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("WAL must be a regular file with no hard links")

                def current_target(fd=fd):
                    if not check_dir():
                        return False
                    try:
                        named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                        opened = os.fstat(fd)
                    except OSError:
                        return False
                    return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                            and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino))

                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                if not current_target():
                    os.close(fd)
                    fd = None
                    if attempt == MAX_RETRIES - 1:
                        raise ValueError("WAL target changed before append")
                    time.sleep(retry_sleep)
                    continue
                _repair_tail(fd, current_target)
                if recover_on:
                    _finish_live(dir_fd, stem, fd)
                if rotate_on:
                    end = os.fstat(fd).st_size
                    if end > MARKER_ONLY_BYTES and end + len(payload) > segment_limit():
                        _fault("before_rotate")
                        try:
                            fd = _rotate(dir_fd, stem, name, fd, current_target)
                        except RotateFailed as error:
                            raise ValueError(f"rotate_failed_record_not_written: {error}")
                        if fd is not None:
                            info = os.fstat(fd)

                            def current_target(fd=fd):  # noqa: F811 - the new live inode
                                if not check_dir():
                                    return False
                                try:
                                    named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                                    opened = os.fstat(fd)
                                except OSError:
                                    return False
                                return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                                        and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino))
                _fault("before_write")
                _write_all(fd, payload)
                os.fsync(fd)
                if not current_target():
                    raise ValueError("WAL target changed during append")
                return
            finally:
                if fd is not None:
                    os.close(fd)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


# ---------------------------------------------------------------------------------------------------------
# index (derived, advisory, rebuildable from the directory and the markers)
# ---------------------------------------------------------------------------------------------------------

def _first_last_at(fd):
    size = os.fstat(fd).st_size
    first = last = None
    for raw in os.pread(fd, 65536, 0).split(b"\n")[:3]:
        try:
            rec = json.loads(raw)
            if isinstance(rec, dict) and rec.get("event") != MARKER_EVENT and isinstance(rec.get("at"), str):
                first = rec["at"]
                break
        except ValueError:
            continue
    tail = os.pread(fd, min(size, 65536), max(0, size - 65536)).split(b"\n")
    for raw in reversed([t for t in tail if t.strip()]):
        try:
            rec = json.loads(raw)
            if isinstance(rec, dict) and isinstance(rec.get("at"), str):
                last = rec["at"]
                break
        except ValueError:
            continue
    return first, last


def build_index(directory_fd, stem):
    ch = _build_chain(".", stem, _scan(directory_fd, stem), dfd=directory_fd)
    segs = []
    names = [s.name for s in ch.segments]
    markers = {}
    for seg in ch.segments + ([ch.live] if ch.live else []):
        try:
            fd = os.open(seg.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except OSError:
            continue
        try:
            m = parse_marker(_first_line(fd))
            if m:
                markers[seg.seq] = m
        finally:
            os.close(fd)
    for i, seg in enumerate(ch.segments):
        nxt = markers.get(seg.seq + 1)
        try:
            fd = os.open(seg.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                first_at, last_at = _first_last_at(fd)
            finally:
                os.close(fd)
        except OSError:
            first_at = last_at = None
        segs.append({"seq": seg.seq, "name": seg.name, "bytes": seg.size,
                     "lines": nxt.get("prev_lines") if nxt else None, "sha256": nxt.get("prev_sha256") if nxt else None,
                     "first_at": first_at, "last_at": last_at,
                     "prev": segment_name(stem, seg.seq - 1) if seg.seq > 1 else None,
                     "next": segment_name(stem, seg.seq + 1) if (seg.seq < ch.max_seq or ch.live) else None})
    return {"schema": SCHEMA, "stem": stem, "updated": _now(), "segments": segs,
            "live": ({"seq": ch.live.seq, "name": ch.live.name, "bytes": ch.live.size} if ch.live else None)}


def write_index(dir_fd, stem):
    index = build_index(dir_fd, stem)
    final = f"{stem}.segments.json"
    tmp = f".{stem}.segments.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        _write_all(fd, (json.dumps(index, indent=1, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, final, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)  # the index is derived data: replacing it is intended
    os.fsync(dir_fd)


# ---------------------------------------------------------------------------------------------------------
# verify / map / CLI
# ---------------------------------------------------------------------------------------------------------

def verify_chain(directory, stem, deep=False):
    """List of problem dicts: chain problems, marker consistency, (deep) rehash of every closed segment."""
    ch = chain(directory, stem)
    problems = list(ch.problems)
    ordered = ch.segments + ([ch.live] if ch.live else [])
    prev = None
    for seg in ordered:
        try:
            fd = _open_regular(str(directory), seg.name)
        except OSError:
            prev = seg
            continue
        try:
            m = parse_marker(_first_line(fd))
            if seg.seq > 1:
                if m is None:
                    problems.append({"code": "marker_missing", "message": f"{seg.name} has no open marker on line 1", "seq": seg.seq})
                elif prev is not None and (m["prev"] != prev.name or m["stem"] != stem or m["segment"] != seg.seq):
                    problems.append({"code": "marker_mismatch", "message": f"{seg.name} marker names prev {m.get('prev')!r}, expected {prev.name!r}", "seq": seg.seq})
                if m and m.get("schema", 1) > SCHEMA:
                    problems.append({"code": "schema_newer", "message": f"{seg.name} marker schema {m['schema']}", "seq": seg.seq})
                if m and m.get("limit") != SEGMENT_BYTES:
                    problems.append({"code": "marker_info", "message": f"{seg.name} marker limit {m.get('limit')} differs from the default", "seq": seg.seq})
                if deep and m and prev is not None:
                    pfd = _open_regular(str(directory), prev.name)
                    try:
                        sha, size, lines = _hash_fd(pfd)
                    finally:
                        os.close(pfd)
                    if (sha, size, lines) != (m.get("prev_sha256"), m.get("prev_bytes"), m.get("prev_lines")):
                        problems.append({"code": "marker_mismatch", "message": f"{prev.name} bytes differ from what {seg.name}'s marker recorded (modified, or an old writer appended after rotation)", "seq": prev.seq})
        finally:
            os.close(fd)
        prev = seg
    return problems


def map_directory(directory):
    out = []
    for stem, ch in list_wals(directory).items():
        problems = verify_chain(directory, stem)
        segs = []
        idx = None
        for seg in ch.segments + ([ch.live] if ch.live else []):
            row = seg.as_dict()
            try:
                fd = _open_regular(str(directory), seg.name)
                try:
                    row["first_at"], row["last_at"] = _first_last_at(fd)
                finally:
                    os.close(fd)
            except OSError:
                pass
            segs.append(row)
        out.append({"stem": stem, "segments": segs, "problems": problems, "complete": not [p for p in problems if p["code"] not in ("live_missing", "marker_info", "schema_newer")]})
    return {"directory": str(directory), "wals": out}


def _checked_dir(raw):
    if os.path.islink(raw):
        raise SystemExit("wal_segments: refusing a symlinked directory argument")
    if not os.path.isdir(raw):
        raise SystemExit(f"wal_segments: not a directory: {raw}")
    return raw


def _checked_stem(raw):
    if not STEM_RE.match(raw) or is_segment_shaped_stem(raw) or raw.endswith(".jsonl"):
        raise SystemExit("wal_segments: bad stem (a WAL stem such as main or agent-<id>, no path)")
    return raw


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("map", help="JSON map of every logical WAL in DIR")
    p.add_argument("dir")
    p = sub.add_parser("verify", help="exit 1 on any problem; --deep rehashes every closed segment")
    p.add_argument("dir")
    p.add_argument("stem", nargs="?")
    p.add_argument("--deep", action="store_true")
    p = sub.add_parser("cat", help="stream the logical WAL (markers dropped) in order")
    p.add_argument("dir")
    p.add_argument("stem")
    p.add_argument("--allow-gaps", action="store_true")
    p = sub.add_parser("reindex", help="rewrite S.segments.json from the directory; dry run unless --write")
    p.add_argument("dir")
    p.add_argument("stem")
    p.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)
    directory = _checked_dir(args.dir)
    if args.cmd == "map":
        print(json.dumps(map_directory(directory), indent=1))
        return 0 if all(w["complete"] for w in map_directory(directory)["wals"]) else 1
    if args.cmd == "verify":
        stems = [_checked_stem(args.stem)] if args.stem else list(list_wals(directory))
        bad = False
        for stem in stems:
            for pr in verify_chain(directory, stem, deep=args.deep):
                if pr["code"] in ("live_missing", "marker_info", "schema_newer"):
                    print(f"info {stem}: {pr['code']}: {pr['message']}", file=sys.stderr)
                    continue
                bad = True
                print(f"problem {stem}: {pr['code']}: {pr['message']}", file=sys.stderr)
        return 1 if bad else 0
    stem = _checked_stem(args.stem)
    if args.cmd == "cat":
        probs = []
        snap = Snapshot(os.path.join(directory, stem + ".jsonl"))
        try:
            for _, _, raw in snap.lines():
                if raw is not None:
                    sys.stdout.buffer.write(raw + b"\n")
            probs = snap.problems
        finally:
            snap.close()
        bad = [p for p in probs if p["code"] not in ("live_missing", "marker_info", "schema_newer")]
        for pr in bad:
            print(f"problem {stem}: {pr['code']}: {pr['message']}", file=sys.stderr)
        return 0 if (not bad or args.allow_gaps) else 1
    if args.cmd == "reindex":
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not args.write:
                print(json.dumps(build_index(dir_fd, stem), indent=1, sort_keys=True))
            else:
                write_index(dir_fd, stem)
                print(f"wrote {stem}.segments.json")
        finally:
            os.close(dir_fd)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
