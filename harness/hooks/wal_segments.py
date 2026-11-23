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
import collections
import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
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
LINE_CAP = 8 * 1024 * 1024  # a longer line is one None, never split
MAX_RETRIES = 8
SEGMENT_RE = re.compile(r"^(?P<stem>.+)\.(?P<seq>\d{4,})\.jsonl$")
STEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
MARKER_EVENT = "wal_segment_open"
MARKER_BY = "wal_segments"
FAULT_STEPS = ("after_hash", "after_temp", "after_rename", "after_live", "after_index")


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
    if os.environ.get("HARNESS_WAL_FAULT") == step and test_mode():  # cheap env check first: test_mode() does realpath calls
        os._exit(77)
    if os.environ.get("HARNESS_WAL_PAUSE") == step and test_mode():
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
    __slots__ = ("seq", "name", "kind", "size", "ino", "dev", "mtime_ns")

    def __init__(self, seq, name, kind, size, ino, dev=None, mtime_ns=None):
        self.seq, self.name, self.kind, self.size, self.ino = seq, name, kind, size, ino
        self.dev, self.mtime_ns = dev, mtime_ns

    @property
    def ident(self):
        """(st_dev, st_ino): the identity a reopened file must have; the inode number alone is not unique across devices."""
        return (self.dev, self.ino)

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
        self._tail_cache = {}

    def problem(self, code, message, seq=None):
        self.problems.append({"code": code, "message": message, "seq": seq})

    def validate_tail(self, deep=False, first_line=None):
        """The tail problems of this chain: the live file's open marker must be the successor of the newest closed
        segment (see tail_problems). One cached open of the live file; `deep` also rehashes the newest closed segment
        against the marker's prev_sha256 (cached per process by file identity). A chain with no live file has no tail
        to validate here (`live_missing` is reported separately). Hard problems: a gate must not treat the chain as
        complete when any is present."""
        cached = first_line is None and bool(deep) in self._tail_cache
        if cached:
            return list(self._tail_cache[bool(deep)])
        live = self.live
        if live is None:
            return []
        read_here = first_line is None
        if read_here:
            try:
                fd = _open_regular(self.directory, live.name)
                try:
                    first_line = _first_line(fd)
                finally:
                    os.close(fd)
            except OSError as error:
                return [{"code": "unreadable", "message": f"{live.name}: {type(error).__name__}", "seq": live.seq}]
        prev = next((s for s in self.segments if s.seq == self.max_seq), None)
        found = tail_problems(self.stem, live.seq, segment_name(self.stem, self.max_seq) if self.max_seq else None,
                              prev.size if prev else None, first_line)
        if deep and not found and prev is not None:
            found = deep_tail_problems(self.directory, None, prev, first_line)
        if read_here:
            self._tail_cache[bool(deep)] = list(found)
        return found

    @property
    def complete(self):
        hard = [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")]
        return not hard and not self.validate_tail()

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
        ch.segments.append(Seg(seq, name, "segment", st.st_size, st.st_ino, st.st_dev, st.st_mtime_ns))
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
                ch.live = Seg(ch.max_seq + 1, lives[0], "live", st.st_size, st.st_ino, st.st_dev, st.st_mtime_ns)
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


scan_chain = chain  # the Snapshot parameter and the public functions below name their argument `chain`


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


class _Changed(OSError):
    """A segment is not the file that was listed (replaced or swapped after the directory listing)."""


def _open_at(dfd, directory, name, ident=None):
    """Open a regular file read-only through the pinned directory fd (no re-resolution of the path), refusing a
    file whose (st_dev, st_ino) differs from the identity that was listed."""
    if dfd is None:
        fd = _open_regular(directory, name)
    else:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if ident is not None and (st.st_dev, st.st_ino) != tuple(ident):
            raise _Changed(errno.ESTALE, f"{name} is not the file that was listed")
    except BaseException:
        os.close(fd)
        raise
    return fd


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


def valid_marker(first_line, stem, seq):
    """THE marker rule, public: the marker dict when `first_line` is exactly the open marker of the source `stem`
    segment `seq` (seq >= 2, `segment` equal to seq, `stem` equal), else None. A marker-shaped line that fails this is
    an ordinary record."""
    m = parse_marker(first_line)
    if m is not None and seq >= 2 and m["segment"] == seq and m["stem"] == stem:
        return m
    return None


Source = collections.namedtuple("Source", "name fd seq ino dev")  # fd is None for a closed segment (opened lazily)


def _tp(code, message, seq):
    return {"code": code, "message": message, "seq": seq}


def tail_problems(stem, expected_seq, prev_name, prev_bytes, first_line):
    """THE tail rule (one validator for every gate and tool): is the file whose first line is `first_line` the
    successor of the newest closed segment? `expected_seq` is that file's sequence number (newest closed + 1),
    `prev_name`/`prev_bytes` the newest closed segment (None when there is none). Returns hard problems:
      - nothing closed before it but its marker claims segment >= 2: closed segments were deleted (tail_missing);
      - closed segments exist but it has no marker (marker_missing);
      - its marker names a LATER segment than expected: the newest closed segment(s) were deleted (tail_missing);
      - its marker names another stem or an earlier segment (marker_mismatch);
      - its marker's prev is not the newest closed segment's name, or prev_bytes differs from its size (marker_mismatch).
    prev_sha256 is checked by deep_tail_problems (it needs a hash of the segment)."""
    m = parse_marker(first_line)
    if prev_name is None:
        if m is not None and m["stem"] == stem and m["segment"] >= 2:
            return [_tp("tail_missing", f"the open marker says segment {m['segment']} but no closed segment precedes it", expected_seq)]  # outcome: tail_missing_all
        return []
    if m is None:
        return [_tp("marker_missing", f"segment {expected_seq} has no open marker but closed segments exist", expected_seq)]  # outcome: tail_marker_missing
    if m["stem"] == stem and m["segment"] > expected_seq:
        msg = f"the open marker says segment {m['segment']} but the newest closed segment is {prev_name}: {m['segment'] - expected_seq} newer closed segment(s) are missing"
        return [_tp("tail_missing", msg, expected_seq)]  # outcome: tail_missing
    if m["stem"] != stem or m["segment"] != expected_seq:
        return [_tp("marker_mismatch", f"the open marker is for {m['stem']} segment {m['segment']}, expected {stem} segment {expected_seq}", expected_seq)]  # outcome: tail_segment_mismatch
    if m.get("prev") != prev_name:
        return [_tp("marker_mismatch", f"the open marker names prev {m.get('prev')!r}, the newest closed segment is {prev_name!r}", expected_seq)]  # outcome: tail_marker_mismatch
    if prev_bytes is not None and m.get("prev_bytes") != prev_bytes:
        return [_tp("marker_mismatch", f"{prev_name} is {prev_bytes} bytes, the open marker recorded {m.get('prev_bytes')}", expected_seq)]  # outcome: tail_bytes_mismatch
    return []


_DEEP_CACHE = {}  # (name, st_dev, st_ino, st_size, st_mtime_ns) -> (sha256, bytes, lines); digests only, never a verdict


def _deep_digest(directory, dfd, seg):
    """sha256, size and line count of a closed segment, cached per process by the file's identity taken from a fresh
    fstat of the opened file (so a changed file always re-hashes); a failed comparison is never cached."""
    fd = _open_at(dfd, directory, seg.name, None)
    try:
        st = os.fstat(fd)
        key = (seg.name, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        hit = _DEEP_CACHE.get(key)
        if hit is None:
            sha, size, lines = _hash_fd(fd)
            if len(_DEEP_CACHE) >= 64:
                _DEEP_CACHE.clear()
            hit = _DEEP_CACHE[key] = (sha, size, lines)
        return hit
    finally:
        os.close(fd)


def deep_tail_problems(directory, dfd, prev_seg, first_line):
    """The prev_sha256 / prev_lines check of the live marker against the newest closed segment (a hash of up to
    50 MB, cached by identity). Run only after tail_problems found nothing."""
    m = parse_marker(first_line)
    if m is None:
        return []
    try:
        sha, size, lines = _deep_digest(directory, dfd, prev_seg)
    except OSError as error:
        return [_tp("unreadable", f"{prev_seg.name}: {type(error).__name__}", prev_seg.seq)]
    if (sha, size, lines) != (m.get("prev_sha256"), m.get("prev_bytes"), m.get("prev_lines")):
        msg = f"{prev_seg.name} no longer matches the digest its successor's open marker recorded (modified, or a writer appended after the rotation)"
        return [_tp("marker_mismatch", msg, prev_seg.seq)]  # outcome: tail_deep_mismatch
    return []


# ---------------------------------------------------------------------------------------------------------
# reader snapshot
# ---------------------------------------------------------------------------------------------------------

class Snapshot:
    """A consistent point-in-time read of one logical WAL. Opens the live fd FIRST, then lists the directory, then
    reconciles by inode, so a concurrent rotation yields neither a duplicated nor a lost pre-snapshot line."""

    def _adopt(self, listing):
        """A private copy of `listing` when it can be trusted against the live fd opened BEFORE it was used, else None.
        Trusted means exactly: same directory and stem, a live fd that this read holds, and the live file the listing
        names is that very file ((st_dev, st_ino)). A read with no live fd never trusts a listing (a missing live file
        is rare, so rescanning costs almost nothing, and a listing that still shows a live file or older segments could
        hide newer ones); a stale listing (a rotation happened after it was taken) names a different live file and is
        ignored too. The listing is always built before this read's live fd is opened, so there is no other case."""
        if listing is None or getattr(listing, "stem", None) != self.stem:
            return None
        if os.path.abspath(str(listing.directory)) != os.path.abspath(self.directory):
            return None
        live = listing.live
        if self.live_fd is None or live is None or live.ident != (self.live_dev, self.live_ino):
            return None
        copy = Chain(listing.directory, listing.stem)
        copy.segments, copy.live = list(listing.segments), live
        copy.problems, copy.max_seq = list(listing.problems), listing.max_seq
        return copy

    def _open_dfd(self):
        if self.dfd is None:
            try:
                self.dfd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
            except OSError:
                self.dfd = None

    def __init__(self, path, strict=False, include_markers=False, max_total_bytes=None, deep_tail=False, chain=None):
        self.directory, name = os.path.split(str(path))
        self.directory = self.directory or "."
        self.stem, _ = parse_name(name)
        if self.stem is None:
            raise SegmentProblem("bad_name", f"not a WAL name: {name}")
        self.strict, self.include_markers, self.max_total_bytes = strict, include_markers, max_total_bytes
        self.problems = []
        self.live_fd = None
        self.live_ino = self.live_dev = None
        self.dfd = None  # pinned directory fd: opened when a directory scan or a closed segment needs it (see below)
        live_name = self.stem + ".jsonl"
        try:
            self.live_fd = _open_regular(self.directory, live_name)  # O_NOFOLLOW on the final component
            info = os.fstat(self.live_fd)
            self.live_ino, self.live_dev = info.st_ino, info.st_dev
        except OSError as error:
            if error.errno not in (errno.ENOENT,):
                self.problems.append({"code": "not_regular" if error.errno in (errno.ELOOP, errno.EINVAL) else "unreadable",
                                      "message": f"{live_name}: {type(error).__name__}", "seq": None})
        _fault_reader()
        # A pre-scanned listing (list_wals) is adopted only after the live fd is open and only when it names that very
        # live file (_adopt); a stale, foreign or contradictory listing, or a read with no live fd, scans the directory
        # again through the pinned directory fd, never by re-resolving the path.
        adopted = self._adopt(chain)
        if adopted is not None:
            self.chain = adopted
        else:
            self._open_dfd()
            if self.dfd is not None:
                self.chain = _build_chain(self.directory, self.stem, _scan(self.dfd, self.stem), self.dfd)
            else:
                self.chain = scan_chain(self.directory, self.stem)
        self._ids = {s.name: s.ident for s in self.chain.segments}  # what was listed: reopened files must match (dev, ino)
        if self.chain.segments:  # closed segments are reopened through the pinned directory fd
            self._open_dfd()
        self.problems.extend(p for p in self.chain.problems
                             if not (p["code"] == "live_missing" and self.live_fd is not None))
        # an fd opened before a rotation is now a closed segment: it is the last segment of the snapshot, and the
        # new live file (written after our snapshot) is beyond it
        self.tail_fd, self.tail_name = self.live_fd, live_name
        if self.live_fd is not None:
            for seg in self.chain.segments:
                if seg.ident == (self.live_dev, self.live_ino):
                    self.tail_name = seg.name
                    self.chain.segments = [s for s in self.chain.segments if s.seq <= seg.seq]
                    self.chain.live = None
                    break
        self._check_tail(deep_tail)
        if self.strict and [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")]:
            first = [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")][0]
            self.close()
            raise SegmentProblem(first["code"], first["message"], first.get("seq"))

    def close(self):
        for attr in ("live_fd", "dfd"):
            fd = getattr(self, attr, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attr, None)

    def _open_closed(self, name):
        return _open_at(self.dfd, self.directory, name, self._ids.get(name))

    def _check_tail(self, deep):
        """The shared tail rule (tail_problems) against the tail this snapshot pinned, reusing the live fd it already
        holds: deleting the newest closed segment, or all of them, is a hard problem, never a clean chain."""
        if self.tail_fd is None:
            return
        seq = parse_name(self.tail_name)[1] or (self.chain.max_seq + 1)
        prev = next((s for s in self.chain.segments if s.seq == seq - 1), None)
        first = _first_line(self.tail_fd)
        found = tail_problems(self.stem, seq, segment_name(self.stem, seq - 1) if seq > 1 else None,
                              prev.size if prev else None, first)
        if deep and not found and prev is not None:
            found = deep_tail_problems(self.directory, self.dfd, prev, first)
        self.problems.extend(found)

    def _read_problem(self, name, error):
        code = "segment_changed" if isinstance(error, _Changed) else "unreadable"
        self.problems.append({"code": code, "message": f"{name}: {type(error).__name__}", "seq": None})
        if self.strict:
            raise SegmentProblem(code, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    def sources(self):
        """The snapshot's files in order as Source(name, fd, seq, ino, dev): closed segments (fd None, opened lazily
        through the pinned directory fd) then the tail (the live file, pinned by its fd, or the segment it was rotated
        into)."""
        out = [Source(s.name, None, s.seq, s.ino, s.dev) for s in self.chain.segments if s.name != self.tail_name]
        if self.tail_fd is not None:
            seq = parse_name(self.tail_name)[1] or (self.chain.max_seq + 1)
            out.append(Source(self.tail_name, self.tail_fd, seq, self.live_ino, self.live_dev))
        return out

    def _sources(self):
        """[(name, fd_or_None, seq)] in order (internal form of sources())."""
        return [(s.name, s.fd, s.seq) for s in self.sources()]

    def _marker_note(self, name, seq):
        self.problems.append({"code": "marker_mismatch", "seq": seq,
                              "message": f"{name} line 1 looks like an open marker but is not this file's (seq {seq}, stem {self.stem}); kept as a record"})

    def _drops_marker(self, first_line, name, seq):
        """THE marker rule, shared by every reader: line 1 is dropped only when it is exactly this source's open
        marker (seq >= 2, segment == seq, stem equal). Any other marker-shaped line is a record plus a problem."""
        if parse_marker(first_line) is None:
            return False
        if valid_marker(first_line, self.stem, seq) is not None:
            return not self.include_markers
        self._marker_note(name, seq)
        return False

    def _frame(self, handle, name, seq):
        """THE framing rule, shared by every reader: yields (raw_without_newline_or_None, nbytes) per line. A line
        over LINE_CAP is discarded up to its newline and yielded once as None (never split into fake lines)."""
        first = True
        while True:
            raw = handle.readline(LINE_CAP + 1)
            if not raw:
                return
            nbytes = len(raw)
            if nbytes > LINE_CAP and not raw.endswith(b"\n"):
                while True:
                    rest = handle.readline(LINE_CAP)
                    nbytes += len(rest)
                    if not rest or rest.endswith(b"\n"):
                        break
                first = False
                yield None, nbytes
                continue
            body = raw.rstrip(b"\r\n")
            if first:
                first = False
                if self._drops_marker(body, name, seq):
                    continue
            yield body, nbytes

    @property
    def complete(self):
        return not [p for p in self.problems if p["code"] not in ("live_missing", "schema_newer", "marker_info")]

    def lines(self):
        """Yield (segment_name, logical_line_no, raw_bytes_without_newline); markers are skipped unless asked for.
        A line longer than 8 MiB is yielded as None. Budget exhaustion adds a `truncated` problem."""
        total, number = 0, 0
        for name, fd, seq in self._sources():
            own = fd is None
            try:
                if own:
                    fd = self._open_closed(name)
                with os.fdopen(os.dup(fd), "rb") as handle:
                    handle.seek(0)
                    for raw, nbytes in self._frame(handle, name, seq):
                        total += nbytes
                        number += 1
                        yield name, number, raw
                        if self.max_total_bytes is not None and total > self.max_total_bytes:
                            self.problems.append({"code": "truncated", "message": f"read budget of {self.max_total_bytes} bytes reached in {name}", "seq": None})
                            if self.strict:
                                raise SegmentProblem("truncated", "read budget reached")
                            return
            except OSError as error:
                self._read_problem(name, error)
            finally:
                if own and fd is not None:
                    os.close(fd)

    def read_tail(self, window):
        """At most the last `window` bytes of the logical stream (markers dropped), newest segment first."""
        pieces, left = [], window
        sources = self._sources()
        for name, fd, seq in reversed(sources):
            if left <= 0:
                break
            own = fd is None
            try:
                if own:
                    fd = self._open_closed(name)
                size = os.fstat(fd).st_size
                start = max(0, size - left)
                data = os.pread(fd, size - start, start)
                if start == 0:
                    first, _, rest = data.partition(b"\n")
                    if self._drops_marker(first, name, seq):  # the same marker rule as lines()
                        data = rest
                pieces.append(data)
                left -= (size - start)
            except OSError as error:
                self._read_problem(name, error)
            finally:
                if own and fd is not None:
                    os.close(fd)
        return b"".join(reversed(pieces))


def _fault_reader():
    if os.environ.get("HARNESS_WAL_READER_PAUSE") == "after_open" and test_mode():
        marker = os.environ.get("HARNESS_WAL_PAUSE_FILE")
        if marker:
            Path(marker).write_text("reader-paused")
            deadline = time.time() + 20
            while os.path.exists(marker) and time.time() < deadline:
                time.sleep(0.01)


def open_chain(path, **kw):
    return Snapshot(path, **kw)


def iter_lines(path, strict=False, include_markers=False, max_total_bytes=None, problems=None, chain=None):
    """Drop-in for a reader's `for raw in open(path)` loop: yields (segment, logical_line_no, bytes). Problems are
    appended to `problems` (a list) when given; strict=True raises SegmentProblem instead of reading past one.
    `chain` is an optional pre-scanned listing (`list_wals(dir)[stem]`), used only when it is consistent with the
    live fd opened for this read, so a reader that walks many WALs scans each directory once, not once per WAL."""
    with Snapshot(path, strict=strict, include_markers=include_markers, max_total_bytes=max_total_bytes, chain=chain) as snap:
        try:
            yield from snap.lines()
        finally:
            if problems is not None:
                problems.extend(snap.problems)


def read_tail(path, window, problems=None, strict=False, chain=None):
    """The last `window` bytes of the logical WAL (markers dropped); `chain` as for iter_lines."""
    with Snapshot(path, strict=strict, chain=chain) as snap:
        data = snap.read_tail(window)
        if problems is not None:
            problems.extend(snap.problems)
        return data


def closed_digests(directory, stem, chain=None):
    """{seq: {"name", "bytes", "lines", "sha256"}} for the closed segments of a WAL, taken from the open markers of
    the NEXT source (segment seq+1 or the live file): no hashing, one small read per source. A closed segment whose
    successor has no valid marker naming it (a legacy segment, a crashed rotation) is left out. `chain` as for
    iter_lines (no directory scan when given). Cache keys for incremental readers: (name, bytes, sha256)."""
    directory = str(directory)
    ch = chain if (chain is not None and getattr(chain, "stem", None) == stem
                   and os.path.abspath(str(chain.directory)) == os.path.abspath(directory)) else scan_chain(directory, stem)
    ordered = list(ch.segments) + ([ch.live] if ch.live else [])
    names = {s.seq: s.name for s in ch.segments}
    out = {}
    for seg in ordered:
        if seg.seq < 2:
            continue
        try:
            fd = _open_regular(directory, seg.name)
        except OSError:
            continue
        try:
            m = valid_marker(_first_line(fd), stem, seg.seq)
        finally:
            os.close(fd)
        prev = names.get(seg.seq - 1)
        if m is not None and prev is not None and m.get("prev") == prev:
            out[seg.seq - 1] = {"name": prev, "bytes": m.get("prev_bytes"), "lines": m.get("prev_lines"),
                                "sha256": m.get("prev_sha256")}
    return out


def read_logical(path, max_bytes=None, problems=None, chain=None):
    """The whole logical WAL as bytes (markers dropped); `max_bytes` bounds it and reports `truncated`."""
    out, size = [], 0
    with Snapshot(path, max_total_bytes=max_bytes, chain=chain) as snap:
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


ROTATED, SKIPPED, RECREATED = "rotated", "skipped", "recreated"


def _rotate(dir_fd, stem, name, fd, current_target):
    """Rename the live file (fd) to the next segment, create the new live file with its open marker, rewrite the
    index. Never closes `fd` and never returns a bare fd or None: it returns (status, fd) where
      ROTATED   -> the new live fd (locked, marker written); the caller closes the old fd;
      SKIPPED   -> the SAME fd, still the live file (collision, unsupported, implausible seq, create failed and undone);
      RECREATED -> None: another writer recreated the live name after our rename; the caller closes the old fd and
                   retries into that file.
    Raises RotateFailed when the rename could not be undone (the record is then not written anywhere)."""
    sha, size, lines = _hash_fd(fd)
    _fault("after_hash")
    seq = _next_seq(dir_fd, stem, fd)
    current_max = max(_scan(dir_fd, stem).get(stem, ({}, []))[0] or {0: 0})
    if seq > current_max + 1000:
        warn("seq_implausible", f"{seq}; rotation refused")
        return SKIPPED, fd  # outcome: implausible_seq
    seg = segment_name(stem, seq)
    # The new live file is prepared COMPLETE (created under a temp dot-name, locked, marker written and synced) before
    # anything is renamed, so the live name never exists without its marker (gate F1) and a failure while preparing
    # it changes nothing on disk: rotation is skipped and the record still lands in the current live file (F2).
    _discard_stale_temps(dir_fd, stem)
    tmp = _temp_name(stem)
    try:
        new_fd = os.open(tmp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
    except OSError as error:
        warn("rotate_create_failed", f"{type(error).__name__} creating the marked temp file; rotation skipped")
        return SKIPPED, fd  # outcome: temp_create_failed
    try:
        os.fchmod(new_fd, 0o600)
        fcntl.flock(new_fd, fcntl.LOCK_EX)
        _write_all(new_fd, _marker(stem, seq + 1, seg, size, lines, sha))
        os.fsync(new_fd)
        _fault("after_temp")
    except OSError as error:
        warn("rotate_create_failed", f"{type(error).__name__} writing the marker; rotation skipped")
        _discard_temp(dir_fd, tmp, new_fd)
        os.close(new_fd)
        return SKIPPED, fd  # outcome: marker_write_failed
    except BaseException:
        os.close(new_fd)
        raise
    try:
        _exclusive_rename(dir_fd, name, seg)
    except FileExistsError:
        warn("rotate_collision", f"{seg} already exists; rotation skipped")
        _discard_temp(dir_fd, tmp, new_fd)
        os.close(new_fd)
        return SKIPPED, fd  # outcome: collision
    except NotImplementedError as error:
        warn("rotate_unsupported", str(error))
        _discard_temp(dir_fd, tmp, new_fd)
        os.close(new_fd)
        return SKIPPED, fd  # outcome: unsupported
    except OSError as error:
        warn("rotate_failed", f"{type(error).__name__} renaming the live file; rotation skipped")
        _discard_temp(dir_fd, tmp, new_fd)
        os.close(new_fd)
        return SKIPPED, fd  # outcome: live_rename_failed
    # from here the live name is absent until the marked file takes it; only a lockless old writer can win that gap
    try:
        os.fsync(dir_fd)
        _fault("after_rename")
        _exclusive_rename(dir_fd, tmp, name)
    except FileExistsError:  # a lockless writer created the live name in the gap: that file IS the live file (R3-8)
        warn("rotate_create_failed", "live name recreated by another writer; retrying into it")
        _discard_temp(dir_fd, tmp, new_fd)
        os.close(new_fd)
        return RECREATED, None  # outcome: recreated_in_gap
    except (OSError, NotImplementedError) as error:
        try:  # undo: put the old live file back under its name
            _exclusive_rename(dir_fd, seg, name)
            os.fsync(dir_fd)
        except FileExistsError:
            _discard_temp(dir_fd, tmp, new_fd)
            os.close(new_fd)
            return RECREATED, None  # outcome: recreated_before_undo
        except (OSError, NotImplementedError):
            os.close(new_fd)  # the marked temp file stays on disk as evidence; the next rotation discards it
            raise RotateFailed(f"moving the marked file into {name} failed ({type(error).__name__}) and the rename could not be undone")  # outcome: rotate_failed_record_not_written
        warn("rotate_create_failed", f"{type(error).__name__}; rotation undone")
        _discard_temp(dir_fd, tmp, new_fd)
        os.close(new_fd)
        return SKIPPED, fd  # outcome: undo_ok
    try:
        try:
            os.fsync(dir_fd)
            _fault("after_live")
            write_index(dir_fd, stem)
        except Exception as error:  # noqa: BLE001 - the index is derived and advisory: never fail an append over it
            warn("index_failed", type(error).__name__)
        _fault("after_index")
    except BaseException:
        os.close(new_fd)
        raise
    return ROTATED, new_fd  # outcome: rotated


def _temp_name(stem):
    return f".{stem}.live.{os.getpid()}.{secrets.token_hex(4)}.new"


def _discard_temp(dir_fd, name, fd):
    """Remove OUR marker-only temp file (never a WAL): only while the name still is the inode we created and it holds
    at most the marker. The only unlink in this module."""
    try:
        named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        opened = os.fstat(fd)
        if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino) and opened.st_size <= MARKER_ONLY_BYTES:
            os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def _discard_stale_temps(dir_fd, stem):
    """Orphans of a crashed rotation: marker-only temp files of this stem that nobody holds (the flock is free)."""
    prefix = f".{stem}.live."
    try:
        with os.scandir(dir_fd) as it:
            names = [e.name for e in it if e.name.startswith(prefix) and e.name.endswith(".new")]
    except OSError:
        return
    for name in names:
        try:
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except OSError:
            continue
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                continue
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                continue  # held by a live rotation
            _discard_temp(dir_fd, name, fd)
        finally:
            os.close(fd)


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


def _rotated_away(dir_fd, stem, fd):
    """True when the inode behind `fd` is now a closed segment of this stem (a rotation moved it)."""
    try:
        want = os.fstat(fd)
        for seq, names in _scan(dir_fd, stem).get(stem, ({}, []))[0].items():
            for n in names:
                st = os.stat(n, dir_fd=dir_fd, follow_symlinks=False)
                if (st.st_dev, st.st_ino) == (want.st_dev, want.st_ino):
                    return True
    except OSError:
        pass
    return False


def _wait_for_live(dir_fd, stem, name, seconds):
    """A writer that holds no seglock waits (up to `seconds`) for the live name to exist before it may O_CREAT it:
    with closed segments present a rotation may be between its two renames. After the wait it creates the file as a
    last resort (a record is never dropped)."""
    if not _scan(dir_fd, stem).get(stem, ({}, []))[0]:
        return  # no closed segments: no rotation can be in flight
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            return
        except FileNotFoundError:
            time.sleep(0.01)
        except OSError:
            return


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
    lock_wait = float(os.environ.get("HARNESS_WAL_LOCK_WAIT", "2")) if test_mode() else 2.0
    try:
        lock_fd = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
        info = os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError(errno.EINVAL, "seglock is not a plain file")
        os.fchmod(lock_fd, 0o600)
        deadline = time.monotonic() + lock_wait
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
    if lock_fd is None:  # without the seglock never create the live file while a rotation may be moving it into place
        _wait_for_live(dir_fd, stem, name, lock_wait)
    try:
        for attempt in range(MAX_RETRIES):
            if not check_dir():
                raise ValueError("WAL session directory changed")
            fd = None
            for tries in range(4):
                if tries and not check_dir():  # re-pin after the backoff: never open through a redirected directory
                    raise ValueError("WAL session directory changed")
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

                cur = [fd]  # the fd this attempt currently owns; rebound when a rotation swaps in the new live file

                def current_target():
                    if not check_dir():
                        return False
                    try:
                        named = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                        opened = os.fstat(cur[0])
                    except OSError:
                        return False
                    return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                            and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino))

                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                if not current_target():
                    # Retry only when OUR rotation renamed this inode to a closed segment; any other change of the
                    # target (replacement, swap, link) is refused as before.
                    rotated = _rotated_away(dir_fd, stem, fd)
                    os.close(fd)
                    fd = None
                    if not rotated or attempt == MAX_RETRIES - 1:
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
                            status, new_fd = _rotate(dir_fd, stem, name, fd, current_target)
                        except RotateFailed as error:
                            raise ValueError(f"rotate_failed_record_not_written: {error}")
                        if status == ROTATED:  # swap: the old (renamed) inode is closed, the new live file is ours
                            os.close(fd)
                            fd = cur[0] = new_fd
                        elif status == RECREATED:  # another writer recreated the live name: retry into that file
                            os.close(fd)
                            fd = None
                            if attempt == MAX_RETRIES - 1:
                                raise ValueError("WAL live file kept changing during rotation")
                            time.sleep(retry_sleep)
                            continue
                        # SKIPPED: `fd` is unchanged and still the live file
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
            is_live = seg.kind == "live"  # the live file is judged by the shared tail rule below (validate_tail)
            if seg.seq > 1:
                if m is None:
                    if not is_live:
                        problems.append({"code": "marker_missing", "message": f"{seg.name} has no open marker on line 1", "seq": seg.seq})
                elif not is_live and prev is not None and (m["prev"] != prev.name or m["stem"] != stem or m["segment"] != seg.seq):
                    problems.append({"code": "marker_mismatch", "message": f"{seg.name} marker names prev {m.get('prev')!r}, expected {prev.name!r}", "seq": seg.seq})
                if m and m.get("schema", 1) > SCHEMA:
                    problems.append({"code": "schema_newer", "message": f"{seg.name} marker schema {m['schema']}", "seq": seg.seq})
                if m and m.get("limit") != SEGMENT_BYTES:
                    problems.append({"code": "marker_info", "message": f"{seg.name} marker limit {m.get('limit')} differs from the default", "seq": seg.seq})
                if deep and m and prev is not None and not is_live:
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
    problems.extend(ch.validate_tail(deep=deep))  # the live file against the newest closed segment (tail_missing, ...)
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


def _live_layout(directory):
    """True for a session directory of a real WAL root (its parent is named `wals` or `codex-wals`); a backup copy
    or any other path is not."""
    return os.path.basename(os.path.dirname(os.path.realpath(directory))) in ("wals", "codex-wals")


def recover_live(directory, stem, write=False):
    """Finish a crashed rotation: create the live file (when missing) or fill an EMPTY one with its open marker.
    Returns (code, message): 0 done or nothing to do, 1 when a live file that already holds records has no valid
    marker (a rotation never edits a WAL: it is reported, not repaired). Needs the seglock (2 s)."""
    ch = scan_chain(directory, stem)
    if not ch.segments:
        return 0, "nothing to do: no closed segments"
    live = ch.live
    if live is not None and live.size > 0:
        fd = _open_regular(directory, live.name)
        try:
            ok = valid_marker(_first_line(fd), stem, live.seq) is not None
        finally:
            os.close(fd)
        if ok:
            return 0, "nothing to do: the live file has its marker"
        return 1, f"problem {stem}: marker_missing: {live.name} holds records but no open marker; not edited"
    action = "create the live file with its marker" if live is None else "write the marker into the empty live file"
    if not write:
        return 0, f"would {action} (dry run; add --write)"
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        lock_fd = os.open(f".{stem}.seglock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
        try:
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                return 1, "problem: the seglock is not a regular file"
            end = time.monotonic() + 2.0
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN) or time.monotonic() > end:
                        return 1, "problem: could not take the seglock (a writer is rotating); retry"
                    time.sleep(0.01)
            fd = os.open(f"{stem}.jsonl", os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                if os.fstat(fd).st_size == 0:
                    _finish_live(dir_fd, stem, fd)
                    os.fsync(dir_fd)
                else:
                    return 1, "problem: the live file received a record meanwhile; not edited"
            finally:
                os.close(fd)
        finally:
            os.close(lock_fd)
    finally:
        os.close(dir_fd)
    return 0, f"recovered: {action}"


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
    p = sub.add_parser("recover", help="finish a crashed rotation in a live WAL folder (under a wals root only)")
    p.add_argument("dir")
    p.add_argument("stem")
    p.add_argument("--write", action="store_true", help="make the change; without it only say what would happen")
    args = ap.parse_args(argv)
    directory = _checked_dir(args.dir)
    if args.cmd == "map":
        result = map_directory(directory)  # once: the printed map and the exit code come from the same read
        print(json.dumps(result, indent=1))
        return 0 if all(w["complete"] for w in result["wals"]) else 1
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
    if args.cmd == "recover":
        if not _live_layout(directory):
            raise SystemExit("wal_segments: recover works only in a live WAL folder (a session directory under a `wals` or "
                             "`codex-wals` root); never in a backup copy")
        code, message = recover_live(directory, stem, write=args.write)
        print(message, file=sys.stderr if code else sys.stdout)
        return code
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
            for pr in verify_chain(directory, stem):  # a reindex never hides a problem (e.g. a live file left without its marker)
                if pr["code"] not in ("live_missing", "marker_info", "schema_newer"):
                    print(f"problem {stem}: {pr['code']}: {pr['message']}", file=sys.stderr)
        finally:
            os.close(dir_fd)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
