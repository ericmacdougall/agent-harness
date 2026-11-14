"""Lane store: layout, atomic writes, store lock, index, hash-chained journal, op records, snapshot IO (S1).

Contracts frozen at S1 (build-spec section 1.2): changed only by a numbered revision with a migration test.

* Root mode 0700 and files 0600; every write is a temp file in the same directory, fsync, atomic rename.
* A symlink, FIFO, directory, or file over MAX_FILE is refused as input (NEG-4); a root that is a symlink, is not
  owned by the caller or is group/world accessible is refused (NEG-84).
* One store lock (flock on ``store.lock``, 10 s timeout). A timeout raises LockTimeout (exit 5) and is logged.
* Journal row: ``{v, seq, ts_utc, kind, lane, generation, writer, idem, source, data, prev, hash}`` with
  ``hash = sha256(prev || canonical_json(row without hash))``; ``head`` holds the last hash. The idempotency key is
  unique per lane: a replay returns the first row, the same key with other content is a KeyConflict.
* Exit codes: refused 3, lock or key conflict 5.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

MAX_FILE = 1 << 20
MAX_LANE_DIR = 8 << 20
LOCK_TIMEOUT = 10.0
# Kinds shipped by S1 (each later slice adds only kinds it ships behaviour for, by a new revision).
KINDS = frozenset({"created", "queued", "start_reserved", "start_released", "holder_bound", "holder_released",
                   "checkpoint", "ledger_resolved"})
EFFECT_STATES = ("pending", "done", "failed", "uncertain")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")


class StoreError(Exception):
    exit_code = 3


class RefusedInput(StoreError):
    exit_code = 3


class LockTimeout(StoreError):
    exit_code = 5


class KeyConflict(StoreError):
    exit_code = 5


class JournalFull(StoreError):
    exit_code = 5


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data) -> str:
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def read_input(path) -> bytes:
    """Read a store file as input: regular, not a symlink, within the size cap, else RefusedInput."""
    path = str(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise RefusedInput("store input refused (%s): %s" % (error.strerror or "unreadable", os.path.basename(path)))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RefusedInput("store input is not a regular file: %s" % os.path.basename(path))
        if info.st_size > MAX_FILE:
            raise RefusedInput("store input over %d bytes: %s" % (MAX_FILE, os.path.basename(path)))
        data = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_FILE:
                raise RefusedInput("store input over %d bytes: %s" % (MAX_FILE, os.path.basename(path)))
        return data
    finally:
        os.close(fd)


def atomic_write(path, data: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    tmp = path.with_name(".%s.%d.tmp" % (path.name, os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _load_json(path, what):
    try:
        value = json.loads(read_input(path).decode())
    except RefusedInput:
        raise
    except (ValueError, UnicodeDecodeError):
        raise RefusedInput("%s is not valid JSON; preserved, not rewritten: %s" % (what, os.path.basename(str(path))))
    if not isinstance(value, dict):
        raise RefusedInput("%s must be a JSON object: %s" % (what, os.path.basename(str(path))))
    return value


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self._depth = 0
        self._fd = None

    # -- layout ----------------------------------------------------------------------------------------------
    def ensure_root(self) -> None:
        if os.path.islink(str(self.root)):
            raise RefusedInput("lane store root is a symlink")
        if not self.root.exists():
            self.root.mkdir(mode=0o700, parents=True)
            os.chmod(str(self.root), 0o700)
        info = os.lstat(str(self.root))
        if not stat.S_ISDIR(info.st_mode):
            raise RefusedInput("lane store root is not a directory")
        if info.st_uid != os.getuid():
            raise RefusedInput("lane store root belongs to another user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RefusedInput("lane store root is accessible to other users (needs mode 0700)")

    def lane_dir(self, lane_id: str) -> Path:
        if not SAFE_ID.match(lane_id or ""):
            raise RefusedInput("invalid lane id")
        return self.root / lane_id

    # -- lock ------------------------------------------------------------------------------------------------
    @contextmanager
    def lock(self, timeout: float = LOCK_TIMEOUT):
        if self._depth:
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
            return
        self.ensure_root()
        fd = os.open(str(self.root / "store.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    self._log({"event": "lock_timeout", "timeout_s": timeout})
                    raise LockTimeout("store lock not acquired within %.1f s" % timeout)
                time.sleep(0.05)
        self._depth = 1
        try:
            yield
        finally:
            self._depth = 0
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _log(self, row: dict) -> None:
        row = dict(row, ts_unix=int(time.time()))
        fd = os.open(str(self.root / "store.log.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (canonical_json(row) + "\n").encode())
        finally:
            os.close(fd)

    # -- index -----------------------------------------------------------------------------------------------
    def load_index(self) -> dict:
        path = self.root / "index.json"
        if not os.path.lexists(str(path)):
            return {"v": 1, "lanes": {}}
        value = _load_json(path, "index")
        if value.get("v") != 1 or not isinstance(value.get("lanes"), dict):
            raise RefusedInput("index has an unknown schema; preserved")
        return value

    def claim_key(self, key: str, lane_id: str) -> str:
        """Under the lock: the lane id that owns ``key`` (the existing one when already claimed)."""
        with self.lock():
            index = self.load_index()
            existing = index["lanes"].get(key)
            if existing:
                return existing
            index["lanes"][key] = lane_id
            atomic_write(self.root / "index.json", (canonical_json(index) + "\n").encode())
            return lane_id

    def release_key(self, key: str, lane_id: str) -> None:
        with self.lock():
            index = self.load_index()
            if index["lanes"].get(key) == lane_id:
                del index["lanes"][key]
                atomic_write(self.root / "index.json", (canonical_json(index) + "\n").encode())

    # -- journal ---------------------------------------------------------------------------------------------
    def _rows(self, lane_dir):
        path = Path(lane_dir) / "journal.jsonl"
        if not os.path.lexists(str(path)):
            return []
        rows = []
        for number, line in enumerate(read_input(path).decode().splitlines(), 1):
            try:
                rows.append(json.loads(line))
            except ValueError:
                raise RefusedInput("journal row %d is not valid JSON; preserved" % number)
        return rows

    @staticmethod
    def _row_hash(prev: str, row: dict) -> str:
        body = {k: v for k, v in row.items() if k != "hash"}
        return sha256_hex(prev + canonical_json(body))

    def journal_append(self, lane_dir, *, kind, lane, generation, writer, idem, source, data, ts):
        if kind not in KINDS:
            raise RefusedInput("unknown journal kind %r" % str(kind)[:40])
        if not SAFE_ID.match(idem or ""):
            raise RefusedInput("invalid idempotency key")
        lane_dir = Path(lane_dir)
        with self.lock():
            rows = self._rows(lane_dir)
            content = canonical_json({"kind": kind, "generation": generation, "data": data, "source": source})
            for row in rows:
                if row.get("idem") == idem:
                    first = canonical_json({"kind": row["kind"], "generation": row["generation"],
                                            "data": row["data"], "source": row["source"]})
                    if first != content:
                        raise KeyConflict("idempotency key %r already used with different content" % idem)
                    return row
            prev = rows[-1]["hash"] if rows else "0" * 64
            row = {"v": 1, "seq": len(rows) + 1, "ts_utc": ts, "kind": kind, "lane": lane, "generation": generation,
                   "writer": writer, "idem": idem, "source": source, "data": data, "prev": prev}
            row["hash"] = self._row_hash(prev, row)
            line = (canonical_json(row) + "\n").encode()
            path = lane_dir / "journal.jsonl"
            size = os.lstat(str(path)).st_size if os.path.lexists(str(path)) else 0
            if size + len(line) > MAX_FILE:
                raise JournalFull("journal would pass the %d byte input cap; start a successor lane" % MAX_FILE)
            if os.path.islink(str(path)):
                raise RefusedInput("journal is a symlink")
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            atomic_write(lane_dir / "head", (row["hash"] + "\n").encode())
            return row

    def verify_journal(self, lane_dir):
        """``(ok, first_broken_seq, reason)``; read-only."""
        lane_dir = Path(lane_dir)
        rows = self._rows(lane_dir)
        prev = "0" * 64
        for row in rows:
            if row.get("prev") != prev or row.get("hash") != self._row_hash(prev, row):
                return False, row.get("seq"), "hash chain broken at seq %s" % row.get("seq")
            prev = row["hash"]
        head_path = lane_dir / "head"
        head = read_input(head_path).decode().strip() if os.path.lexists(str(head_path)) else None
        if rows and head != prev:
            return False, len(rows), "head does not match the last journal row (rows dropped or head edited)"
        if not rows and head:
            return False, 0, "head present but journal empty"
        return True, None, None

    # -- op records ------------------------------------------------------------------------------------------
    def _op_path(self, lane_dir, op):
        if not SAFE_ID.match(op or ""):
            raise RefusedInput("invalid operation id")
        return Path(lane_dir) / "ops" / (op + ".json")

    def begin_op(self, lane_dir, *, op, kind, lane, key, content, effects, ts):
        path = self._op_path(lane_dir, op)
        digest = sha256_hex(canonical_json(content))
        with self.lock():
            if os.path.lexists(str(path)):
                record = _load_json(path, "operation record")
                if record.get("content_sha256") != digest or record.get("key") != key:
                    raise KeyConflict("operation %r exists with different content" % op)
                return record
            (Path(lane_dir) / "ops").mkdir(mode=0o700, exist_ok=True)
            record = {"v": 1, "op": op, "kind": kind, "lane": lane, "key": key, "content_sha256": digest,
                      "intent_ts": ts, "effects": [{"name": n, "state": "pending", "ref": None, "ts": None}
                                                   for n in effects]}
            atomic_write(path, (canonical_json(record) + "\n").encode())
            return record

    def set_effect(self, lane_dir, op, name, state, ref=None, ts=None):
        if state not in EFFECT_STATES:
            raise RefusedInput("invalid effect state %r" % str(state)[:20])
        path = self._op_path(lane_dir, op)
        with self.lock():
            record = _load_json(path, "operation record")
            for effect in record["effects"]:
                if effect["name"] == name:
                    effect.update(state=state, ref=ref, ts=ts)
                    atomic_write(path, (canonical_json(record) + "\n").encode())
                    return record
            raise RefusedInput("operation %r has no effect %r" % (op, str(name)[:40]))

    @staticmethod
    def pending_effects(record) -> list:
        return [e for e in record["effects"] if e["state"] != "done"]

    # -- snapshot --------------------------------------------------------------------------------------------
    def write_snapshot(self, lane_dir, snapshot: dict) -> None:
        atomic_write(Path(lane_dir) / "snapshot.json", (canonical_json(snapshot) + "\n").encode())

    def read_snapshot(self, lane_dir):
        path = Path(lane_dir) / "snapshot.json"
        if not os.path.lexists(str(path)):
            return None
        return _load_json(path, "snapshot")
