"""takeover: decide when a stopped session's leftovers may be cleaned up by another session, and do it (goodqa#16441).

A session that stopped (usage limit, crash, handoff) leaves worktrees and processes behind. Another agent that takes
the work over may clean them up without asking, but only through this module's routes and only when the old session
is RETIRED: it declared a stop or was claimed, has been quiet long enough, has no live process on either host, and has
no open ask or task. Everything else is "live" or "unknown", and unknown means nothing is touched.

    session_state(old, action, ...)     the verdict and the reasons; read only
    claim(...)  / tombstone             an HMAC'd record that tells the resumed session what was done
    worktree_candidates / process_candidates   what a cleanup may touch, never more than this
    cleanup(...)                        plan or apply; every target is re-judged right before it is acted on

Stdlib only, Python 3.9 compatible. Read only except for takeover-audit.jsonl and the claim/tombstone file. This module
never writes the old session's WAL, never reads a secret, and never raises a flag that relaxes ah_kill or the
worktree verifier: both keep every one of their own refusals.
"""
from __future__ import annotations

import datetime as dt
import glob
import hashlib
import hmac
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TAKEOVER_VERSION = 1
QUIET_WORKTREE_S = 3600
QUIET_PROCESS_S = 4 * 3600
WALLESS_QUIET_S = 24 * 3600
SKEW_S = 300
ENV_READ_CAP = 1024
MAX_CANDIDATES = 64
MAX_REMOVED_RECORDED = 64
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{7,127}$")
TICKET_RE = re.compile(r"^GoodQA [a-z0-9-]{1,32}#[0-9]{1,7}$")
REMOTE_HOST = "t2-dev"
LOCAL_ONLY = "local-only"  # session_state(remote=LOCAL_ONLY): judge this host alone (the verifier; no ssh from a guard)
# Rows the hooks write on their own: they say a session is running, never that it stopped.
HOOK_EVENTS = {"prompt", "subagent", "subagent_stop", "session", "tool", "stop", "sessionstart", "userpromptsubmit",
               "pretooluse", "posttooluse", "subagentstart", "subagentstop", "interrupt", "takeover-notice"}
LIVE_CODES = {"not_stopped", "recent_activity", "session_live", "open_work"}
ACTIONS = ("worktrees", "processes")


class TakeoverError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


class ProbeFailed(Exception):
    """ps, lsof or ssh did not answer: the state is unknown and nothing may be touched."""


def _sibling(name):
    spec = importlib.util.spec_from_file_location(name, str(HERE / (name + ".py")))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_AK = None


def ak():
    """ah_kill, loaded by path (the hooks run under python -I, so the script directory is not on sys.path)."""
    global _AK
    if _AK is None:
        _AK = sys.modules.get("ah_kill") or _sibling("ah_kill")
    return _AK


def _redact(text):
    try:
        redact = sys.modules.get("redact") or _sibling("redact")
        return redact.redact(text)
    except Exception:  # noqa: BLE001 - a missing redactor must never leak: drop the text instead
        return "[text withheld: redactor unavailable]"


def _iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value):
    """Epoch seconds of an ISO-8601 string (Z or offset), or None."""
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------------------------- the host probe

class HostProbe:
    """Process facts of this host. It wraps ah_kill.Probe (info, table, session_pairs, comm_table) and adds the three
    scans takeover needs. Tests replace the whole object; every method raises ProbeFailed when the OS did not answer."""

    host = "local"

    def __init__(self):
        self._p = ak().Probe()

    def __getattr__(self, name):  # info, table, user, cwd, session_pairs, signal ... come from ah_kill.Probe
        return getattr(self._p, name)

    def proc_table(self):
        """{pid: {ppid, start (epoch), command, comm}} from one `ps -A` argv table and one comm table."""
        try:
            out = self._p._ps("pid", "ppid", "uid", "lstart", "command")
            comms = self._p.comm_table()
        except ak().KillError as error:
            raise ProbeFailed(str(error))
        rows, mine = {}, os.getuid()
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)\s+(\d+)\s+(-?\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]{8}\s+\d{4})\s+(.*)$", line)
            if not m or int(m.group(3)) != mine:
                continue  # a takeover only ever handles this user's own processes
            pid = int(m.group(1))
            rows[pid] = {"ppid": int(m.group(2)), "start": ak()._epoch_lstart(m.group(4)),
                         "command": m.group(5).strip(), "comm": comms.get(pid, "")}
        return rows

    def env_pairs(self, pids):
        """{pid: {(flavor, id)}}: only the two session variables are kept, the raw environment text is dropped. One
        `ps eww -p` call per batch of 64 pids, parsed in this process and never logged or returned."""
        found = {}
        pids = list(pids)
        for index in range(0, len(pids), 64):
            batch = pids[index:index + 64]
            try:
                done = subprocess.run(["ps", "eww", "-o", "pid=,command=", "-p", ",".join(str(p) for p in batch)],
                                      capture_output=True, text=True, timeout=30, env=dict(os.environ, LC_ALL="C"))
            except (OSError, subprocess.SubprocessError):
                raise ProbeFailed("ps eww could not be run")
            if done.returncode not in (0, 1):
                raise ProbeFailed("ps eww failed")
            blocks, current = {p: [] for p in batch}, None
            for line in done.stdout.splitlines():
                m = re.match(r"\s*(\d+)\s", line)
                if m and int(m.group(1)) in blocks:
                    current = int(m.group(1))
                if current is not None:
                    blocks[current].append(line)
            for pid, lines in blocks.items():
                found[pid] = ak().session_pairs_from("\n".join(lines))
        return found

    def cwd_scan(self):
        """{pid: cwd} from one lsof scan."""
        try:
            out = self._p._lsof(["-d", "cwd", "-Fpn"])
        except ak().KillError as error:
            raise ProbeFailed(str(error))
        found, pid = {}, None
        for line in out.splitlines():
            if line.startswith("p") and line[1:].isdigit():
                pid = int(line[1:])
            elif line.startswith("n") and pid is not None:
                found[pid] = line[1:]
        return found


# ------------------------------------------------------------------------------------------------ small readers

def _tail_lines(path, limit=65536):
    """The last complete-ish lines of a file (at most `limit` bytes), or None when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            handle.seek(max(0, size - limit))
            data = handle.read(limit)
    except OSError:
        return None
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > limit and lines else lines


def _last_stamp(path):
    """(mtime, last-row timestamp) of a JSONL file; either may be None. A row stamp the file mtime does not show
    (a backdating touch) still counts."""
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return None, None
    stamp = None
    for line in reversed(_tail_lines(path) or []):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            stamp = _epoch(row.get("at") or row.get("timestamp"))
            if stamp is not None:
                break
    return mtime, stamp


def _real_dir_ok(path):
    """(exists, ok): a directory this user owns that is not a symlink."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False, True
    except OSError:
        return True, False
    return True, stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()


def _read_json_file(path, limit=4096):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        return json.loads(os.read(fd, limit + 1))
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)


def _continuation(wal_dir):
    """(visible state or None, mtime) of a Codex continuation checkpoint, as the Codex wal hook reads it."""
    path = os.path.join(wal_dir, "continuation.json")
    state = _read_json_file(path, 1024)
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        mtime = None
    if not isinstance(state, dict) or not isinstance(state.get("state"), str):
        return None, mtime
    marker = None
    try:
        with open(os.path.join(wal_dir, "continuation.interrupt"), "rb") as handle:
            m = re.fullmatch(r"([0-9a-f]{32})(?::[0-9a-f]{64})?", handle.read(97).decode("ascii", "replace"))
            marker = m.group(1) if m else None
    except OSError:
        pass
    visible = state["state"]
    if visible == "active" and marker != state.get("interrupt"):
        visible = "paused"  # wal.visible_checkpoint
    return visible, mtime


def _last_non_hook_event(path):
    for line in reversed(_tail_lines(path) or []):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("event"), str) and row["event"].casefold() not in HOOK_EVENTS:
            return row["event"]
    return None


def _open_asks(wal_dir):
    """(open ask ids, unreadable): asks in the session's WALs that no ask_resolved row closes."""
    asks, closed, unreadable = set(), set(), False
    try:
        names = sorted(n for n in os.listdir(wal_dir) if n == "main.jsonl" or (n.startswith("agent-") and n.endswith(".jsonl")))
    except OSError:
        return [], True
    for name in names:
        path = os.path.join(wal_dir, name)
        try:
            if os.stat(path).st_size > 16 << 20:
                unreadable = True
                continue
            with open(path, "rb") as handle:
                for raw in handle:
                    if b'"ask' not in raw:
                        continue
                    try:
                        row = json.loads(raw)
                    except ValueError:
                        continue
                    if not isinstance(row, dict):
                        continue
                    if row.get("event") == "ask" and isinstance(row.get("id"), str):
                        asks.add(row["id"])
                    elif row.get("event") == "ask_resolved" and isinstance(row.get("ref"), str):
                        closed.add(row["ref"])
        except OSError:
            unreadable = True
    return sorted(asks - closed), unreadable


def default_tasks(home):
    """Open registered tasks as [{task, session, latest_actor}], from the ah ledger. Raises when it cannot be read."""
    ah = _sibling("ah")
    rows = ah.task_list(Path(home), open_only=True)["tasks"]
    ledger = ah._ledger(Path(home))
    out = []
    for task in rows:
        actor = None
        for row in ledger:
            if row.get("op") == "task.status" and (row.get("args") or {}).get("task") == task.get("task"):
                actor = str(row.get("actor") or "")
        out.append({"task": task.get("task"), "session": task.get("session"), "latest_actor": actor})
    return out


def _bg_job_records(home, old):
    base = os.path.join(home, ".agent-harness", "work", old)
    for record in (glob.glob(os.path.join(base, "*", "bg-jobs", "*.json"))[:256]
                   + glob.glob(os.path.join(base, "bg-jobs", "*.json"))[:256]):
        data = _read_json_file(record, 65536)
        if isinstance(data, dict) and isinstance(data.get("pid"), int) and isinstance(data.get("nonce"), str):
            yield record, data


def _bg_job_pids(home, old):
    return {data["pid"] for _record, data in _bg_job_records(str(home), old)}


def _bg_jobs_live(home, old, table):
    """Names of bg_job records under the session work dir whose pid still carries the record's nonce."""
    live = []
    for record, data in _bg_job_records(home, old):
        row = table.get(data["pid"])
        if row and data["nonce"] and data["nonce"] in row["command"]:
            live.append(str(data.get("name") or os.path.basename(record))[:60])
    return live


# ------------------------------------------------------------------------------------------- claim / tombstone

def claim_path(home, session):
    return os.path.join(str(home), ".agent-harness", "takeover", session + ".json")


def _canonical(fields):
    return json.dumps({k: v for k, v in fields.items() if k != "hmac"}, sort_keys=True, separators=(",", ":"))


def _key(home, create=False):
    kg = ak()._kill_guard()
    key = kg.read_key(str(home))
    if not key and create:
        key = kg.ensure_key(str(home))
    return key


def _valid_claim(data, session, home):
    """The claim dict when its fields validate and its HMAC verifies, else None."""
    if not isinstance(data, dict) or set(data) != {"v", "session", "flavor", "caller", "claimed_at", "updated_at", "ticket",
                                                   "removed", "stopped", "host", "hmac"}:
        return None
    work = os.path.realpath(os.path.join(str(home), ".agent-harness", "work", session)) + os.sep
    try:
        ok = (data["v"] == 1 and data["session"] == session and ID_RE.fullmatch(session)
              and data["flavor"] in ("claude", "codex") and isinstance(data["caller"], str) and ID_RE.fullmatch(data["caller"])
              and (data["claimed_at"] is None or isinstance(data["claimed_at"], str) and _epoch(data["claimed_at"]) is not None)
              and isinstance(data["updated_at"], str) and _epoch(data["updated_at"]) is not None
              and isinstance(data["ticket"], str) and TICKET_RE.fullmatch(data["ticket"])
              and isinstance(data["removed"], list) and len(data["removed"]) <= MAX_REMOVED_RECORDED
              and all(isinstance(p, str) and os.path.realpath(p).startswith(work) for p in data["removed"])
              and isinstance(data["stopped"], list) and len(data["stopped"]) <= MAX_REMOVED_RECORDED
              and all(isinstance(s, dict) and set(s) == {"pid", "start"} and type(s["pid"]) is int and type(s["start"]) is int
                      for s in data["stopped"])
              and isinstance(data["host"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", data["host"])
              and isinstance(data["hmac"], str))
    except (TypeError, ValueError):
        return None
    if not ok:
        return None
    key = _key(home)
    if not key:
        return None
    good = hmac.new(key, _canonical(data).encode(), hashlib.sha256).hexdigest()
    return data if hmac.compare_digest(good, data["hmac"]) else None


def read_claim(home, session):
    """(valid claim or None, present-but-invalid)."""
    path = claim_path(home, session)
    if not os.path.lexists(path):
        return None, False
    data = _read_json_file(path, 65536)
    claim = _valid_claim(data, session, home)
    return claim, claim is None


def write_claim(home, session, flavor, caller, ticket, now, host, claimed=True, removed=(), stopped=()):
    """Write (or update) the HMAC'd record at ~/.agent-harness/takeover/<session>.json, 0600, from validated fields only."""
    if not ID_RE.fullmatch(session) or not ID_RE.fullmatch(caller or "") or not TICKET_RE.fullmatch(ticket or ""):
        raise TakeoverError("bad_request", "session, caller and ticket must be well formed")
    previous, _bad = read_claim(home, session)
    # An update keeps the claim time only for the session that made the claim: a second taker's tombstone update must not
    # inherit the first taker's R2 standing under its own name (review minor).
    kept = (previous or {}).get("claimed_at") if (previous or {}).get("caller") == caller else None
    data = {"v": 1, "session": session, "flavor": flavor, "caller": caller,
            "claimed_at": _iso(now) if claimed else kept, "updated_at": _iso(now),
            "ticket": ticket, "removed": list(((previous or {}).get("removed") or []) + list(removed))[-MAX_REMOVED_RECORDED:],
            "stopped": list(((previous or {}).get("stopped") or []) + list(stopped))[-MAX_REMOVED_RECORDED:],
            "host": re.sub(r"[^A-Za-z0-9._-]", "", host)[:64] or "host"}
    key = _key(home, create=True)
    if not key:
        raise TakeoverError("no_key", "the kill-guard key is unavailable, so a claim cannot be signed")
    data["hmac"] = hmac.new(key, _canonical(data).encode(), hashlib.sha256).hexdigest()
    folder = os.path.dirname(claim_path(home, session))
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    temp = claim_path(home, session) + ".tmp%d" % os.getpid()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, json.dumps(data, sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, claim_path(home, session))
    return data


def render_notice(session, home):
    """The fixed notice text for a session whose valid tombstone exists, and the tombstone's hash; (None, None) when
    there is no valid tombstone. Only validated fields are rendered; there is no free-text field."""
    try:
        claim, _bad = read_claim(home, session)
    except Exception:  # noqa: BLE001 - a notice never breaks a session start
        return None, None
    if not claim:
        return None, None
    paths = claim["removed"]
    shown = ", ".join(paths[:20]) + (" and %d more" % (len(paths) - 20) if len(paths) > 20 else "") if paths else "none"
    text = ("Takeover notice: session %s took over this session's work at %s (ticket %s). Removed worktrees: %s. "
            "Stopped pids: %d. Do not continue in removed paths; re-create from the remote and coordinate on the ticket."
            % (claim["caller"], claim["claimed_at"] or claim["updated_at"], claim["ticket"], shown, len(claim["stopped"])))
    return text, hashlib.sha256(_canonical(claim).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------------------- audit (takeover-audit)

def audit(home, row):
    """Append one redacted row to ~/.agent-harness/takeover-audit.jsonl (0600, O_APPEND). Raises when it cannot."""
    path = Path(home) / ".agent-harness" / "takeover-audit.jsonl"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    clean = {}
    for key, value in dict(row, at=_iso(time.time())).items():
        clean[key] = _redact(value) if isinstance(value, str) and key not in ("at", "event", "state") else value
    line = (json.dumps(clean, ensure_ascii=False, separators=(",", ":"), default=str) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


# -------------------------------------------------------------------------------------------- local evidence

def _ancestors(table, pid, limit=64):
    out, seen = [], {pid}
    for _ in range(limit):
        row = table.get(pid)
        if not row:
            break
        pid = row["ppid"]
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        out.append(pid)
    return out


def _is_host(row):
    return ak().is_agent_host({"comm": row.get("comm", ""), "command": row.get("command", "")})


def collect_evidence(old, home, probe, now, ledger_spawns=None, tasks_fn=None, with_processes=False):
    """Everything this host can say about `old`, as plain JSON (also what `takeover status --evidence-only` prints).

    Read only. A probe that did not answer is recorded as `probe_failed` (the judge then returns unknown)."""
    home = str(home)
    ev = {"version": TAKEOVER_VERSION, "host": getattr(probe, "host", "local"), "now": now, "problems": [], "flavors": [],
          "cont_state": None, "declared_stop": False, "last_activity": None, "future": False, "transcript": False,
          "open_asks": [], "open_tasks": [], "bg_live": [], "live": [], "worktrees": [], "walless": None,
          "claim_present": False, "probe_failed": False, "asks_unreadable": False, "tasks_unreadable": False}
    wals = {"claude": os.path.join(home, ".claude", "wals", old),
            "codex": os.path.join(home, ".agent-harness", "codex-wals", old)}
    work = os.path.join(home, ".agent-harness", "work", old)
    stamps, wal_dir = [], None
    for flavor, directory in wals.items():
        exists, ok = _real_dir_ok(directory)
        if not ok:
            ev["problems"].append("bad_dir")
        if exists and ok and os.path.isfile(os.path.join(directory, "main.jsonl")):
            ev["flavors"].append(flavor)
    exists, ok = _real_dir_ok(work)
    if not ok:
        ev["problems"].append("bad_dir")
    ev["work_dir"] = exists and ok
    if len(ev["flavors"]) == 1:
        flavor = ev["flavors"][0]
        wal_dir = wals[flavor]
        for name in os.listdir(wal_dir):
            if name == "main.jsonl" or (name.startswith("agent-") and name.endswith(".jsonl")):
                stamps += list(_last_stamp(os.path.join(wal_dir, name)))
        if flavor == "codex":
            ev["cont_state"], cont_mtime = _continuation(wal_dir)
            stamps.append(cont_mtime)
            ev["declared_stop"] = ev["cont_state"] in ("complete", "handoff")
        else:
            ev["declared_stop"] = _last_non_hook_event(os.path.join(wal_dir, "main.jsonl")) == "handoff"
        for transcript in _transcripts(home, old, flavor):
            stamps += list(_last_stamp(transcript))
        ev["open_asks"], ev["asks_unreadable"] = _open_asks(wal_dir)
    elif not ev["flavors"]:
        # R7: no WAL here. The newest depth-1 entry of the work dir bounds its age.
        ev["walless"] = _walless_facts(work, now) if ev["work_dir"] else {"exists": False}
    ev["transcript"] = any(_transcripts(home, old, f) for f in ("claude", "codex"))  # R7 needs "none of either flavor"
    claim, invalid = read_claim(home, old)
    ev["claim_present"] = bool(claim or invalid)
    if claim:
        ev["claim"] = {"caller": claim["caller"], "claimed_at": _epoch(claim["claimed_at"]) if claim["claimed_at"] else None}
        if ev["claim"]["claimed_at"] is not None:
            stamps.append(ev["claim"]["claimed_at"])
    ev["claim_invalid"] = invalid
    stamps = [s for s in stamps if s is not None]
    if stamps:
        ev["last_activity"] = max(stamps)
        ev["future"] = max(stamps) > now + SKEW_S
    try:
        table = probe.proc_table()
        cwds = probe.cwd_scan()
        ev["live"] = _live_markers(old, home, probe, table, cwds, ledger_spawns)
        ev["bg_live"] = _bg_jobs_live(home, old, table)
        if with_processes:
            # Unbounded candidates (no start-time cut): the host that knows last_activity applies the bound itself.
            found, _predicate, _basis = process_candidates(
                old, home, probe, None, table=table, spawns=ledger_spawns,
                spawn_start=getattr(probe, "spawn_start", None), exclude_pids=_bg_job_pids(home, old))
            ev["process_candidates"] = [{"pid": p, "start": s} for p, s in sorted(found.items())]
    except ProbeFailed:
        ev["probe_failed"] = True
        table = {}
    try:
        tasks = (tasks_fn or default_tasks)(home)
        ev["open_tasks"] = [{"task": str(t.get("task")), "actor": t.get("latest_actor")} for t in tasks
                            if t.get("session") == old]
    except Exception:  # noqa: BLE001 - an unreadable task ledger is unknown, never "no tasks"
        ev["tasks_unreadable"] = True
    if wal_dir is not None or ev["work_dir"]:
        try:
            ev["worktrees"] = [{"path": p, "head": h} for p, _common, h in worktree_candidates(old, home)]
        except OSError:
            ev["problems"].append("worktrees_unreadable")
    return ev


def _transcripts(home, old, flavor):
    """App-written transcripts of the session: Claude's project JSONL files, Codex's rollout files (exact id suffix)."""
    if flavor == "codex":
        found = glob.glob(os.path.join(home, ".codex", "sessions", "*", "*", "*", "rollout-*-%s.jsonl" % old))
        return [p for p in found[:512] if p.endswith("-" + old + ".jsonl")]
    return (glob.glob(os.path.join(home, ".claude", "projects", "*", old + ".jsonl"))[:512]
            + glob.glob(os.path.join(home, ".claude", "projects", "*", old, "subagents", "*.jsonl"))[:512])


def _walless_facts(work, now):
    newest, count, capped = 0.0, 0, False
    try:
        with os.scandir(work) as entries:
            for entry in entries:
                count += 1
                if count > 512:
                    capped = True
                    break
                newest = max(newest, entry.stat(follow_symlinks=False).st_mtime)
    except OSError:
        return {"exists": True, "unreadable": True}
    return {"exists": True, "newest": newest, "capped": capped, "future": newest > now + SKEW_S}


def _live_markers(old, home, probe, table, cwds, ledger_spawns):
    """R4 evidence: processes of this host that carry `old` as their session marker, with whether each is an agent
    host or hangs under one. The env read set is bounded (ENV_READ_CAP), over the cap means probe_failed."""
    hosts = {pid for pid, row in table.items() if _is_host(row)}
    wanted = set(hosts)
    for pid in table:
        if any(a in hosts for a in _ancestors(table, pid)):
            wanted.add(pid)
    work = os.path.realpath(os.path.join(home, ".agent-harness", "work", old)) + os.sep
    for pid, cwd in cwds.items():
        if cwd and (os.path.realpath(cwd) + os.sep).startswith(work):
            wanted.add(pid)
    for pid, row in table.items():
        if old in row["command"]:
            wanted.add(pid)
    wanted &= set(table)
    if len(wanted) > ENV_READ_CAP:
        raise ProbeFailed("more than %d processes to inspect" % ENV_READ_CAP)
    pairs = probe.env_pairs(sorted(wanted))
    live = []
    for pid in sorted(wanted):
        ids = sorted({value for _flavor, value in pairs.get(pid, ())})
        if old not in ids:
            continue
        under = _is_host(table[pid]) or any(a in hosts for a in _ancestors(table, pid))
        live.append({"pid": pid, "start": table[pid]["start"], "ids": ids, "agent_host": under})
    seen = {proc["pid"] for proc in live}
    live += [proc for proc in _record_live(old, home, probe, table) if proc["pid"] not in seen]
    return live


SESSION_RECORD_CAP = 512
RECORD_NAME = re.compile(r"^([0-9]{1,10})\.json$")


def _record_live(old, home, probe, table):
    """R4 for a Claude CLI whose environment shows no marker (macOS hides it; on t2-dev the CLI's comm is its version):
    its own ~/.claude/sessions/<pid>.json, bound to the live start time by claude_record, names `old`. Records of pids
    that are not running are never read or counted; more live-pid records than the cap is probe_failed, never a cut."""
    folder = os.path.join(str(home), ".claude", "sessions")
    try:
        with os.scandir(folder) as entries:
            pids = [int(m.group(1)) for m in (RECORD_NAME.match(entry.name) for entry in entries) if m]
    except FileNotFoundError:
        return []
    except OSError:
        raise ProbeFailed("the Claude session records could not be read")
    pids = sorted(pid for pid in pids if pid in table)
    if len(pids) > SESSION_RECORD_CAP:
        raise ProbeFailed("more than %d Claude session records of live pids" % SESSION_RECORD_CAP)
    live = []
    for pid in pids:
        row = table[pid]
        if claude_record(home, pid, {"comm": row.get("comm", ""), "command": row.get("command", "")}, probe) == old:
            live.append({"pid": pid, "start": row["start"], "ids": [old], "agent_host": True, "basis": "session_record"})
    return live


# ------------------------------------------------------------------------------------------------- the verdict

def _result(state, reasons, ev=None, eligible_at=None, extra=None):
    out = {"state": state, "reasons": list(reasons), "eligible_at": eligible_at,
           "evidence": {k: v for k, v in (ev or {}).items() if k in ("flavor", "origin_host", "cont_state", "last_activity",
                                                                      "claim_at")}}
    out.update(extra or {})
    return out


def _finish(reasons, ev=None, eligible_at=None, extra=None, walless=False):
    if not reasons:
        return _result("walless" if walless else "retired", [], ev, eligible_at, extra)
    unknown = [r for r in reasons if r not in LIVE_CODES]
    return _result("unknown" if unknown else "live", reasons, ev, eligible_at, extra)


def session_state(old, action, home, probe, now, caller, remote=None, tasks_fn=None, ledger_spawns=None, evidence=None):
    """The verdict {state: retired|walless|live|unknown, reasons, eligible_at, evidence} for session `old`.

    `retired` needs R1 to R5 all true; `walless` only R7 and only for worktrees. `remote` is the other host's parsed
    `takeover status --evidence-only --json` output; None means it was not reachable (unknown), LOCAL_ONLY means judge
    this host alone. Any probe failure, parse error or ambiguity gives unknown."""
    home = str(home)
    if not isinstance(old, str) or not ID_RE.fullmatch(old):
        return _result("unknown", ["bad_id"])
    if action not in ACTIONS:
        return _result("unknown", ["bad_action"])
    if not caller or not isinstance(caller, str) or not ID_RE.fullmatch(caller):
        return _result("unknown", ["caller_unknown"])
    if old == caller:
        return _result("unknown", ["self_takeover"])
    ev = evidence or collect_evidence(old, home, probe, now, ledger_spawns, tasks_fn)
    evs = [ev]
    if remote is None:
        return _result("unknown", ["origin_unreachable"], ev)
    if remote != LOCAL_ONLY:
        if not isinstance(remote, dict) or remote.get("version") != TAKEOVER_VERSION:
            return _result("unknown", ["remote_version"], ev)
        evs.append(remote)
    # R1 identity and origin host
    if any("bad_dir" in e.get("problems", []) for e in evs):
        return _result("unknown", ["bad_dir"], ev)
    holders = [e for e in evs if e.get("flavors")]
    if any(len(e["flavors"]) > 1 for e in holders) or len(holders) > 1:
        return _result("unknown", ["ambiguous_session"], ev)
    if any(e.get("probe_failed") for e in evs):
        return _result("unknown", ["probe_failed"], ev)
    if not holders:
        if remote == LOCAL_ONLY:
            # This host has no WAL for the session, and the other host was not consulted: a Mac session whose worktree
            # sits here would look "walless". Only a two-host judgement may say walless; the verifier never does.
            return _result("unknown", ["origin_unreachable"], ev)
        return _walless_state(old, action, evs, now, ev)
    origin = holders[0]
    info = {"flavor": origin["flavors"][0], "origin_host": origin.get("host"), "cont_state": origin.get("cont_state"),
            "last_activity": origin.get("last_activity"), "claim_at": (origin.get("claim") or {}).get("claimed_at")}
    reasons, eligible_at = [], None
    # R2 declared stop, or a valid claim of this caller. claim() writes a claim only on the session's origin host, so the
    # claim is read from the origin's evidence (review F3; a claim on another host cannot count).
    claim = origin.get("claim")
    claimed = bool(claim and claim.get("caller") == caller and claim.get("claimed_at") is not None)
    if not origin.get("declared_stop") and not claimed:
        reasons.append("not_stopped")
    # R3 quiet window, measured from app-written transcripts as well as the WALs, and from the claim itself
    if not origin.get("transcript"):
        reasons.append("transcript_missing")
    future = bool(origin.get("future") or ev.get("future"))
    if future:
        reasons.append("clock_skew")
    stamps = [s for s in (origin.get("last_activity"), (claim or {}).get("claimed_at")) if s is not None]
    last = max(stamps) if stamps else None
    info["last_activity"] = last
    window = QUIET_WORKTREE_S if action == "worktrees" else QUIET_PROCESS_S
    if last is None:
        if "transcript_missing" not in reasons:
            reasons.append("no_activity_record")
    elif not future and now - last < window:
        reasons.append("recent_activity")
        eligible_at = _iso(last + window)
    # R4 no live agent process on either host (a process of the caller's own session neither blocks nor qualifies)
    for e in evs:
        for proc in e.get("live", []):
            if caller in proc.get("ids", []):
                continue
            if proc.get("agent_host"):
                reasons.append("session_live")
                break
    # R5 no open work
    if origin.get("asks_unreadable"):
        reasons.append("asks_unreadable")
    if origin.get("tasks_unreadable"):
        reasons.append("tasks_unreadable")
    open_tasks = [t for t in origin.get("open_tasks", []) if caller not in str(t.get("actor") or "")]
    if origin.get("open_asks") or open_tasks or origin.get("bg_live"):
        reasons.append("open_work")
        info["open_work"] = {"asks": origin.get("open_asks", [])[:10], "tasks": [t["task"] for t in open_tasks][:10],
                             "jobs": origin.get("bg_live", [])[:10]}
    reasons = list(dict.fromkeys(reasons))
    return _finish(reasons, info, eligible_at, {"open_work": info.get("open_work")} if info.get("open_work") else None)


def _walless_state(old, action, evs, now, ev):
    """R7: no WAL on any reachable host. Worktrees only, and only for a work dir nothing has touched for a day."""
    if action != "worktrees":
        return _result("unknown", ["session_unknown"], ev)
    reasons = []
    for e in evs:
        if e.get("transcript"):
            reasons.append("transcript_present")  # the session existed: it has a transcript or rollout, so it is not walless
        for proc in e.get("live", []):
            if proc.get("agent_host"):
                reasons.append("session_live")
        facts = e.get("walless") or {}
        if facts.get("unreadable") or facts.get("capped") or facts.get("future"):
            reasons.append("walless_unreadable")
        if facts.get("exists") and facts.get("newest") is not None and now - facts["newest"] < WALLESS_QUIET_S:
            reasons.append("recent_activity")
    if not any((e.get("walless") or {}).get("exists") for e in evs):
        return _result("unknown", ["session_unknown"], ev)
    # a transcript of this id on a host without a WAL still means the session existed: refuse
    reasons = list(dict.fromkeys(reasons))
    if reasons:
        unknown = [r for r in reasons if r not in LIVE_CODES]
        return _result("unknown" if unknown else "live", reasons, ev)
    return _result("walless", [], ev)


# -------------------------------------------------------------------------------------------- candidates

def worktree_candidates(old, home, run=subprocess.run):
    """[(path, common repository, head)] of linked worktrees at depth 1 or 2 under work/<old>/, each confirmed by
    `git worktree list --porcelain` in its repository. Never work/<old>/ itself, a primary checkout, a WAL, a *.jsonl,
    kit.json or state. Capped at MAX_CANDIDATES. lstat checks everywhere: a symlink is never followed."""
    base = os.path.join(str(home), ".agent-harness", "work", old)
    exists, ok = _real_dir_ok(base)
    if not exists or not ok:
        return []
    found = []

    def real_dirs(directory):
        try:
            with os.scandir(directory) as entries:
                for entry in sorted(entries, key=lambda e: e.name)[:512]:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and "/" not in entry.name:
                        yield entry.path
        except OSError:
            return

    def linked(path):
        gitfile = os.path.join(path, ".git")
        try:
            st = os.lstat(gitfile)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 4096:
                return None
            with open(gitfile, "rb") as handle:
                text = handle.read(4096).decode("utf-8", "replace").strip()
        except OSError:
            return None
        m = re.fullmatch(r"gitdir: (/\S.*?)/worktrees/[^/]+", text)
        if not m:
            return None
        common = m.group(1)
        return os.path.dirname(common) if os.path.basename(common) == ".git" else common

    for first in real_dirs(base):
        for path in ([first] if linked(first) else real_dirs(first)):
            common = linked(path)
            if common:
                found.append((path, common))
    confirmed = []
    for path, common in found[:MAX_CANDIDATES]:
        try:
            done = run(["git", "-c", "core.hooksPath=/dev/null", "-C", common, "worktree", "list", "--porcelain"],
                       capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        if done.returncode != 0:
            continue
        entries, current = [], {}
        for line in done.stdout.splitlines() + [""]:
            if not line:
                if current:
                    entries.append(current)
                current = {}
            elif " " in line:
                key, value = line.split(" ", 1)
                current[key] = value
        for index, entry in enumerate(entries):
            if index and os.path.realpath(entry.get("worktree", "")) == os.path.realpath(path) \
                    and re.fullmatch(r"[0-9a-f]{40,64}", entry.get("HEAD", "")):
                confirmed.append((path, common, entry["HEAD"]))
    return confirmed


def process_candidates(old, home, probe, last_activity, table=None, spawns=None, spawn_start=None, exclude_pids=(),
                       caller=None):
    """({pid: start_epoch}, predicate, basis) of the processes a takeover may stop.

    A pid qualifies only if it carries `old` as its session marker (and no other session's), or is in the spawn ledger
    of work/<old> and carries no other session's marker; it started no later than the old session's last activity; it
    is not an agent host and has no agent-host ancestor; it is not a registered task or bg_job pid; and it carries no
    marker of the caller. A cwd inside work/<old>/ alone never qualifies. The predicate is re-run by ah_kill on a fresh
    snapshot, and `expect` pins the exact start time, so a reused pid is `candidate_changed`."""
    table = table if table is not None else probe.proc_table()
    spawns = spawns if spawns is not None else set()
    excluded = set(exclude_pids)
    hosts = {pid for pid, row in table.items() if _is_host(row)}
    readable = sorted(set(table) - hosts)
    if len(readable) > ENV_READ_CAP:
        raise ProbeFailed("more than %d processes to inspect" % ENV_READ_CAP)
    pairs = probe.env_pairs(readable)
    start_of = spawn_start or (lambda pid: ak().spawn_start(probe, pid) if spawns else None)
    candidates, basis = {}, {}
    for pid in readable:
        row = table[pid]
        if pid in excluded or pid <= 1 or any(a in hosts for a in _ancestors(table, pid)):
            continue
        ids = {value for _flavor, value in pairs.get(pid, ())}
        # a marker of the caller or of any other session never matches `ids == {old}` or the empty set below
        if ids == {old}:
            kind = "marker"
        elif not ids and (pid, start_of(pid)) in spawns:
            kind = "ledger"  # recorded by kill_guard spawn for work/<old>, and it carries no other session's marker
        else:
            continue  # no marker of this session, or another session's marker: never a candidate (cwd alone is not one)
        if last_activity is not None and (row["start"] is None or row["start"] > last_activity):
            continue
        if row["start"] is None:
            continue
        candidates[pid], basis[pid] = int(row["start"]), kind
    ledger = set(spawns)

    def predicate(live_probe, info):
        pid = info["pid"]
        if basis.get(pid) is None:
            return False
        started = ak()._epoch_lstart(info.get("start"))
        if started is None or (last_activity is not None and started > last_activity):
            return False
        fresh = {value for _flavor, value in ak()._owner_pairs(live_probe, pid)}
        if caller and caller in fresh:
            return False
        if basis[pid] == "marker" and fresh != {old}:
            return False
        if basis[pid] == "ledger" and (not fresh <= {old} or (pid, start_of(pid)) not in ledger):
            return False
        seen, cur = set(), pid
        for _ in range(16):
            parent = live_probe.info(cur)
            if not parent or parent["ppid"] <= 1 or parent["ppid"] in seen:
                break
            seen.add(parent["ppid"])
            cur = parent["ppid"]
            above = live_probe.info(cur)
            if above and ak().is_agent_host(above):
                return False
        return not ak().is_agent_host(info)

    return candidates, predicate, basis


# -------------------------------------------------------------------------------------- remote evidence (ssh)

def fetch_remote_evidence(old, runner=subprocess.run, local_is_remote=None):
    """The other host's evidence, or None when it is not reachable.

    A caller on t2-dev cannot reach the Mac, so it gets LOCAL_ONLY (review F3): session_state then judges only a session
    whose WAL is on t2-dev, from t2-dev's evidence, and says unknown for any other. A session runs on the host that holds
    its WAL, so the unseen Mac can hold no live process of it; the one blind spot is a Mac process that carries the
    t2-dev session's marker, which the Mac-side judgement would see (disclosed in docs/operations.md)."""
    if local_is_remote is None:
        local_is_remote = sys.platform.startswith("linux")
    if local_is_remote:
        return LOCAL_ONLY
    cmd = "python3 -I .claude/hooks/ah.py takeover status --from %s --evidence-only --json" % shlex.quote(old)
    try:
        done = runner(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", REMOTE_HOST, cmd],
                      capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
        data = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("version") == TAKEOVER_VERSION else None


# ------------------------------------------------------------------------------------------- orchestration

# ---------------------------------------------------------------------------------- who is calling (review F1)
#
# The caller is never taken from a flag or from the caller's own environment: a command line can set both. It is worked
# out from the process ancestry of the running tool:
#   * Claude: the Claude CLI writes ~/.claude/sessions/<pid>.json with its sessionId and its start time (procStart; macOS:
#     the UTC `ps -o lstart` text, Linux: /proc/<pid>/stat field 22). The nearest ancestor with such a record, whose
#     executable is a Claude binary and whose start time matches, names the caller. Overwriting an existing record is a
#     protected-log overwrite and creating one is refused like a guard file (command_guard policy guard_files).
#   * Codex: there is no app-written pid record. The nearest Codex agent host's tool shell carries CODEX_THREAD_ID in the
#     environment it was started with; every process between it and the tool must agree. This is weaker than the Claude
#     record (T2/T3 are unverified on a live Codex): a Codex caller is accepted only when it is consistent and its WAL
#     exists here, otherwise it is unknown, which refuses every foreign removal.
#   * ssh: with no agent above it and an sshd process above it, the tool was started by the caller's host (ah
#     worktree-remove relays its own derived caller). The flag is the only identity there; the guard's text rule G2 is
#     what keeps an agent from typing that ssh command itself. Disclosed, not closed.
#   * none: no agent and no ssh hop (a user's terminal, or an orphan that escaped its parent): any flag is ignored.

SSHD = re.compile(r"^sshd(?:-session)?\b")
CODEX_FRESH_S = 1800  # a Codex caller's own rollout was written within this window (half the worktree quiet window)
CLAUDE_EXE = re.compile(r"(?:^|/)[^/]*claude[^/]*(?:/|$)", re.I)


def start_token(pid):
    """The process start time in the form the Claude CLI records as procStart, or None."""
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/%d/stat" % int(pid), "rb") as handle:
                text = handle.read(4096).decode("ascii", "replace")
            fields = text[text.rindex(")") + 2:].split()
            return fields[19] if len(fields) > 19 else None  # field 22 (starttime); fields here start at field 3
        done = subprocess.run(["ps", "-o", "lstart=", "-p", str(int(pid))], capture_output=True, text=True, timeout=8,
                              env={"TZ": "UTC", "LC_ALL": "C", "PATH": "/bin:/usr/bin"}, stdin=subprocess.DEVNULL)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    text = " ".join(done.stdout.split())
    return text or None


def exe_path(pid, info=None):
    """The executable of a process: /proc/<pid>/exe on Linux (not settable through argv), the full comm path on macOS."""
    if sys.platform.startswith("linux"):
        try:
            return os.readlink("/proc/%d/exe" % int(pid))
        except (OSError, ValueError):
            return ""
    return (info or {}).get("comm") or ""


def claude_record(home, pid, info, probe=None):
    """The sessionId of the Claude CLI `pid` from its own ~/.claude/sessions/<pid>.json, or None. The record must be a
    small regular file of this user, name this pid, carry a session id, match the live start time, and the process must
    run a Claude executable."""
    path = os.path.join(str(home), ".claude", "sessions", "%d.json" % int(pid))
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > 65536:
        return None
    data = _read_json_file(path, 65536)
    if not isinstance(data, dict) or data.get("pid") != int(pid):
        return None
    sid = data.get("sessionId")
    if not isinstance(sid, str) or not ID_RE.fullmatch(sid):
        return None
    exe = (getattr(probe, "exe_path", None) or (lambda p: exe_path(p, info)))(pid)
    if not exe or not CLAUDE_EXE.search(exe):
        return None
    token = (getattr(probe, "start_token", None) or start_token)(pid)
    recorded = " ".join(str(data.get("procStart") or "").split())
    if not token or not recorded or recorded != " ".join(str(token).split()):
        return None
    return sid


def _wal_known(home, flavor, sid):
    parent = (".claude", "wals") if flavor == "claude" else (".agent-harness", "codex-wals")
    name = sid if flavor == "claude" else _safe_wal_name(sid)
    return os.path.isdir(os.path.join(str(home), *parent, name))


def _safe_wal_name(value):
    """codex/hooks/wal.py safe_id for an id that is already lowercase and well formed (ID_RE): the id itself."""
    return value if ID_RE.fullmatch(value or "") and not value.startswith("z-") else ""


def _codex_flavor(info):
    module = ak()
    if module.desktop_app(info):
        exe, _rest = module._exe_and_rest(info)
        return not re.search(r"(?:^|/)claude[^/]*\.app/", (info.get("comm") or "") + " " + exe, re.I)
    exe, rest = module._exe_and_rest(info)
    names = [os.path.basename(info.get("comm") or "").lower(), os.path.basename(exe).lower()]
    names += [os.path.basename(w).lower() for w in rest[:2]]
    return "codex" in names and "claude" not in names


def derive_caller(home, probe=None, pid=None, environ=None):
    """{"mode": claude|codex|ssh|none, "caller": id or None, "why": text}: who runs this process, from its ancestry.

    Read only. Every failure gives caller None, which the callers treat as unknown (refused for any foreign work dir)."""
    environ = os.environ if environ is None else environ
    probe = probe if probe is not None else ak().Probe()
    start = os.getpid() if pid is None else int(pid)
    chain, current = [], start
    try:
        for _ in range(64):
            info = probe.info(current)
            if not info:
                break
            if current != start:
                sid = claude_record(home, current, info, probe)
                if sid:
                    claimed = environ.get("CLAUDE_CODE_SESSION_ID")
                    if claimed and claimed != sid:
                        return {"mode": "claude", "caller": None, "why": "the environment disagrees with the session record"}
                    if not _wal_known(home, "claude", sid):
                        return {"mode": "claude", "caller": None, "why": "no WAL for the recorded session on this host"}
                    return {"mode": "claude", "caller": sid, "why": "session record of pid %d" % current}
                if ak().is_agent_host(info):
                    if not _codex_flavor(info):
                        return {"mode": "claude", "caller": None, "why": "a Claude host with no valid session record"}
                    return _codex_caller(home, probe, chain, environ, current)
                comm = os.path.basename(info.get("comm") or "")
                if SSHD.match(comm) or SSHD.match(info.get("command") or ""):
                    return {"mode": "ssh", "caller": None, "why": "started over ssh with no agent above"}
            chain.append(info)
            if info.get("ppid", 0) <= 1:
                break
            current = info["ppid"]
    except Exception as error:  # noqa: BLE001 - an ancestry that cannot be read proves nothing
        return {"mode": "none", "caller": None, "why": "ancestry unreadable (%s)" % type(error).__name__}
    return {"mode": "none", "caller": None, "why": "no agent and no ssh hop above this process"}


def _codex_caller(home, probe, chain, environ, host_pid):
    values = set()
    claimed = environ.get("CODEX_THREAD_ID")
    if claimed:
        values.add(claimed)
    for info in chain:
        pairs = probe.session_pairs(info["pid"])
        if pairs is None:
            return {"mode": "codex", "caller": None, "why": "an environment on the chain could not be read"}
        values |= {value for flavor, value in pairs if flavor == "codex"}
    if len(values) != 1:
        return {"mode": "codex", "caller": None, "why": "%d thread ids on the chain under pid %d" % (len(values), host_pid)}
    sid = values.pop()
    if not ID_RE.fullmatch(sid) or not _wal_known(home, "codex", sid):
        return {"mode": "codex", "caller": None, "why": "no WAL for that thread on this host"}
    # macOS hides the environment of platform shells (/bin/zsh, /bin/bash) from ps, so the chain often proves nothing
    # beyond this process's own environment. The app appends the running thread's rollout on every tool call; a thread
    # whose rollout has not been written for CODEX_FRESH_S is not the one calling (a stopped session claimed by id).
    now = time.time()
    if not any(now - _mtime(path) <= CODEX_FRESH_S for path in _transcripts(str(home), sid, "codex")):
        return {"mode": "codex", "caller": None, "why": "the thread's rollout is not being written"}
    return {"mode": "codex", "caller": sid, "why": "thread id of the tool shell under pid %d" % host_pid}


def _mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


FLAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def resolve_caller(home, flag=None, probe=None, pid=None, environ=None):
    """(caller or None, problem or None) for a tool that was handed `--caller-session flag`.

    Under an agent the derived caller is the answer and a flag that names anyone else is `caller_mismatch`. Over ssh with
    no agent above, the flag is the relayed caller (see the block comment above). Otherwise the flag is ignored."""
    if flag and not FLAG_RE.fullmatch(str(flag)):
        return None, "caller_mismatch: --caller-session is not a session id"
    found = derive_caller(home, probe, pid, environ)
    if found["mode"] in ("claude", "codex"):
        if flag and found["caller"] and flag != found["caller"]:
            return None, "caller_mismatch: --caller-session names another session than the calling one"
        return found["caller"], None
    if found["mode"] == "ssh":
        return (flag or None), None
    return None, None


def caller_of(home, environ=None, probe=None):
    """The calling session's id from the process ancestry (derive_caller), or None. Never read from the environment: a
    command line can set CLAUDE_CODE_SESSION_ID or CODEX_THREAD_ID, it cannot change its own ancestors."""
    found = derive_caller(home, probe=probe, environ=environ)
    caller = found.get("caller") if found.get("mode") in ("claude", "codex") else None
    return caller if caller and ID_RE.fullmatch(caller) else None


def validate_ticket(ticket, lookup=None):
    """Format check, then existence through `lookup(ticket)` (ah ticket get). Raises TakeoverError when it cannot be shown."""
    if not isinstance(ticket, str) or not TICKET_RE.fullmatch(ticket):
        raise TakeoverError("bad_ticket", '--ticket must look like "GoodQA <project>#<n>"')
    if lookup is None:
        raise TakeoverError("ticket_unchecked", "the ticket could not be checked")
    try:
        found = lookup(ticket)
    except Exception:  # noqa: BLE001
        raise TakeoverError("ticket_unreachable", "GoodQA could not be reached to check %s; --apply is refused" % ticket)
    if not found:
        raise TakeoverError("ticket_not_found", "ticket %s was not found; --apply is refused" % ticket)


class Context:
    """Everything cleanup() depends on, so tests can replace each piece and nothing reaches ssh, ps or the real home."""

    def __init__(self, home, caller, probe=None, now=time.time, remote_fetch=None, remove=None, kill_local=None,
                 kill_remote=None, tasks_fn=None, spawns_fn=None, ticket_lookup=None, host=None):
        self.home, self.caller, self.now = str(home), caller, now
        self.probe = probe if probe is not None else HostProbe()
        self.remote_fetch = remote_fetch if remote_fetch is not None else fetch_remote_evidence
        self.remove, self.kill_local, self.kill_remote = remove, kill_local, kill_remote
        self.tasks_fn, self.spawns_fn, self.ticket_lookup = tasks_fn, spawns_fn, ticket_lookup
        self.host = host or "local"


def status(old, action, ctx):
    """The verdict from this host's point of view, judged with the other host's evidence."""
    remote = ctx.remote_fetch(old)
    spawns = ctx.spawns_fn(old) if ctx.spawns_fn else None
    return session_state(old, action, ctx.home, ctx.probe, ctx.now(), ctx.caller, remote, ctx.tasks_fn, spawns), remote


def claim(old, ctx, reason, ticket):
    """Record that ctx.caller took `old` over. Needs R1 (a known session) and no live process; R2 is what this satisfies."""
    validate_ticket(ticket, ctx.ticket_lookup)
    if not ID_RE.fullmatch(old or ""):
        raise TakeoverError("bad_id", "--from is not a session id")
    if old == ctx.caller or not ctx.caller:
        raise TakeoverError("self_takeover" if ctx.caller else "caller_unknown", "the caller must be another known session")
    ev = collect_evidence(old, ctx.home, ctx.probe, ctx.now(), ctx.spawns_fn(old) if ctx.spawns_fn else None, ctx.tasks_fn)
    remote = ctx.remote_fetch(old)
    if remote == LOCAL_ONLY:
        evs = [ev]  # a caller on t2-dev: only a session whose WAL is here can be claimed (checked below)
    elif remote is None or not isinstance(remote, dict) or remote.get("version") != TAKEOVER_VERSION:
        raise TakeoverError("remote_unreachable", "the other host could not be read; a claim needs both hosts")
    else:
        evs = [ev, remote]
    if any("bad_dir" in e.get("problems", []) for e in evs) or any(e.get("probe_failed") for e in evs):
        raise TakeoverError("unknown", "the session or the processes could not be read safely")
    holders = [e for e in evs if e.get("flavors")]
    if len(holders) != 1 or len(holders[0]["flavors"]) != 1:
        raise TakeoverError("ambiguous_session" if holders else "session_unknown", "exactly one session WAL is required")
    for e in evs:
        if any(p.get("agent_host") and ctx.caller not in p.get("ids", []) for p in e.get("live", [])):
            raise TakeoverError("session_live", "a live process still carries that session's marker")
    if holders[0] is not ev:
        raise TakeoverError("origin_remote", "the session ran on the other host: claim it from that host")
    data = write_claim(ctx.home, old, ev["flavors"][0], ctx.caller, ticket, ctx.now(), ctx.host)
    audit(ctx.home, {"event": "claim", "session": old, "caller": ctx.caller, "ticket": ticket, "reason": reason,
                     "claimed_at": data["claimed_at"]})
    return {"ok": True, "claimed": True, "session": old, "claimed_at": data["claimed_at"],
            "eligible_worktrees_at": _iso(ctx.now() + QUIET_WORKTREE_S), "eligible_processes_at": _iso(ctx.now() + QUIET_PROCESS_S)}


HEAD_RE = re.compile(r"^[0-9a-f]{40}$")


def _remote_worktrees(remote, old):
    """The other host's worktree proposals that lie one or two levels under its work/<old>/ dir with a full head. The
    other host's verifier checks each again; this keeps a wrong or hostile evidence list from naming any other path."""
    if not isinstance(remote, dict):
        return []
    marker = "/.agent-harness/work/%s/" % old
    rows = []
    for item in remote.get("worktrees", []) or []:
        path, head = (item.get("path"), item.get("head")) if isinstance(item, dict) else (None, None)
        if not isinstance(path, str) or not isinstance(head, str) or not HEAD_RE.fullmatch(head):
            continue
        if not path.startswith("/") or os.path.normpath(path) != path or path.count(marker) != 1:
            continue
        depth = len(path.split(marker, 1)[1].split("/"))
        if 1 <= depth <= 2:
            rows.append((path, head))
    return rows


def plan_worktrees(old, ctx, paths=()):
    """[(host, path, head)] for the worktrees a cleanup may remove, narrowed (never widened) by `paths`."""
    state, remote = status(old, "worktrees", ctx)
    rows = []
    if state["state"] in ("retired", "walless"):
        rows = [("local", p, h) for p, _c, h in worktree_candidates(old, ctx.home)]
        rows += [("t2-dev", p, h) for p, h in _remote_worktrees(remote, old)]
    return state, rows


def cleanup(old, action, ctx, reason, ticket, paths=(), pids=(), apply=False):
    """Plan, or with apply carry out, a cleanup of session `old`'s leftovers. Every target is re-judged immediately
    before it is acted on (R6); the first non-eligible answer stops the run."""
    if action not in ACTIONS + ("stale-helpers",):
        raise TakeoverError("bad_action", "--action must be worktrees, processes or stale-helpers")
    if apply:
        validate_ticket(ticket, ctx.ticket_lookup)
        if not ctx.caller:
            raise TakeoverError("caller_unknown", "the caller's own session could not be determined")
    audit(ctx.home, {"event": "request", "session": old, "caller": ctx.caller, "action": action, "apply": bool(apply),
                     "ticket": ticket, "reason": reason, "paths": list(paths), "pids": list(pids)})
    if action == "stale-helpers":
        return _stale_helpers(ctx, reason, apply)
    state, remote = status(old, action, ctx)
    result = {"ok": False, "session": old, "action": action, "apply": bool(apply), "state": state["state"],
              "reasons": state["reasons"], "eligible_at": state["eligible_at"], "targets": [], "refused": []}
    if state["state"] not in ("retired", "walless") or (state["state"] == "walless" and action != "worktrees"):
        audit(ctx.home, {"event": "refused", "session": old, "action": action, "state": state["state"],
                         "reasons": ",".join(state["reasons"])})
        return result
    if action == "worktrees":
        return _do_worktrees(old, ctx, reason, ticket, paths, apply, result, remote)
    return _do_processes(old, ctx, reason, ticket, pids, apply, result, state, remote)


def _do_worktrees(old, ctx, reason, ticket, paths, apply, result, remote):
    rows = [("local", p, h) for p, _c, h in worktree_candidates(old, ctx.home)]
    rows += [("t2-dev", p, h) for p, h in _remote_worktrees(remote, old)]
    wanted = [os.path.realpath(p) if not p.startswith("/") else p for p in paths]
    if wanted:
        known = {path for _h, path, _hd in rows}
        for path in wanted:
            if path not in known:
                result["refused"].append({"path": path, "why": "not a worktree candidate of this session"})
        rows = [r for r in rows if r[1] in wanted]
    result["targets"] = [{"host": h, "path": p, "head": hd} for h, p, hd in rows]
    if not apply:
        result["ok"] = True
        audit(ctx.home, {"event": "plan", "session": old, "action": "worktrees", "count": len(rows)})
        return result
    removed, kept = [], []
    for host, path, head in rows:
        fresh, _remote = status(old, "worktrees", ctx)  # R6
        if fresh["state"] not in ("retired", "walless"):
            result["refused"].append({"path": path, "why": "re-check: session is now %s (%s)" % (fresh["state"], ",".join(fresh["reasons"]))})
            break
        audit(ctx.home, {"event": "target", "session": old, "action": "worktrees", "host": host, "path": path})
        try:
            answer = ctx.remove(host, path, "takeover of %s: %s: %s" % (old, ticket, reason), expect_head=head,
                                caller_session=ctx.caller)
        except Exception as error:  # noqa: BLE001 - a failed removal is reported and the run goes on to the next
            kept.append({"path": path, "why": "%s: %s" % (getattr(error, "code", type(error).__name__), error)})
            audit(ctx.home, {"event": "result", "session": old, "path": path, "removed": None, "why": str(error)})
            continue
        audit(ctx.home, {"event": "result", "session": old, "path": path, "removed": answer.get("removed"),
                         "why": answer.get("reason") or ""})
        if answer.get("removed") is True:
            removed.append(path)
            if host == "local":
                _update_tombstone(old, ctx, ticket, removed=[path])
        else:
            kept.append({"path": path, "why": answer.get("reason") or "refused by the verifier"})
    result.update(ok=bool(removed) or not kept, removed=removed, kept=kept)
    return result


def _update_tombstone(old, ctx, ticket, removed=(), stopped=()):
    previous, _bad = read_claim(ctx.home, old)
    flavor = (previous or {}).get("flavor") or ("codex" if os.path.isdir(os.path.join(ctx.home, ".agent-harness", "codex-wals", old)) else "claude")
    try:
        write_claim(ctx.home, old, flavor, ctx.caller, ticket, ctx.now(), ctx.host, claimed=False, removed=removed, stopped=stopped)
    except (TakeoverError, OSError):
        pass  # the tombstone is a courtesy to the resumed session; the audit rows are the record


def _do_processes(old, ctx, reason, ticket, pids, apply, result, state, remote):
    last = (state.get("evidence") or {}).get("last_activity")
    if last is None:
        result["refused"].append({"why": "no last-activity time is known for the session"})
        return result
    table = ctx.probe.proc_table()
    exclude = _bg_job_pids(ctx.home, old)  # a registered bg_job of the session is never stopped from here
    spawns = ctx.spawns_fn(old) if ctx.spawns_fn else set()
    spawn_start = getattr(ctx.probe, "spawn_start", None)
    candidates, predicate, _basis = process_candidates(old, ctx.home, ctx.probe, last, table=table, spawns=spawns,
                                                       spawn_start=spawn_start, exclude_pids=exclude, caller=ctx.caller)
    if pids:
        for pid in pids:
            if pid not in candidates:
                result["refused"].append({"pid": pid, "why": "not a candidate of this session"})
        candidates = {p: s for p, s in candidates.items() if p in pids}
    result["targets"] = [{"host": "local", "pid": p, "start": s} for p, s in sorted(candidates.items())]
    remote_cands = {}
    if isinstance(remote, dict) and remote != LOCAL_ONLY:
        for item in remote.get("process_candidates", []):
            if isinstance(item, dict) and type(item.get("pid")) is int and type(item.get("start")) is int \
                    and item["start"] <= last and (not pids or item["pid"] in pids):
                remote_cands[item["pid"]] = item["start"]  # the remote list is a proposal; its host re-checks every pid
        result["targets"] += [{"host": REMOTE_HOST, "pid": p, "start": s} for p, s in sorted(remote_cands.items())]
    if not apply:
        result["ok"] = True
        audit(ctx.home, {"event": "plan", "session": old, "action": "processes", "count": len(result["targets"])})
        return result
    fresh, _remote = status(old, "processes", ctx)  # R6
    if fresh["state"] != "retired":
        result["refused"].append({"why": "re-check: session is now %s (%s)" % (fresh["state"], ",".join(fresh["reasons"]))})
        return result
    stopped = []
    if candidates:
        out = ctx.kill_local(sorted(candidates), "takeover of %s: %s: %s" % (old, ticket, reason), grace=10.0,
                             foreign=True, expect=candidates, predicate=predicate)
        result["local"] = out
        stopped += [{"pid": r["pid"], "start": candidates[r["pid"]]} for r in out["results"]
                    if r["status"] in ("exited", "killed") and r["pid"] in candidates]
    if remote_cands:
        out = ctx.kill_remote(REMOTE_HOST, sorted(remote_cands), "takeover of %s: %s: %s" % (old, ticket, reason), False, 10.0,
                              foreign=True, expect=remote_cands, takeover_of=old)
        result["remote"] = out
    if stopped:
        _update_tombstone(old, ctx, ticket, stopped=stopped)
    audit(ctx.home, {"event": "result", "session": old, "action": "processes", "stopped": len(stopped)})
    result["ok"] = bool(stopped) or not result["targets"]
    return result


def _stale_helpers(ctx, reason, apply):
    """Old-version desktop-app helpers belong to no session: no takeover state is needed, only ah_kill's own gate."""
    module = ak()
    probe = ctx.probe
    table = probe.proc_table()
    pids = []
    for pid, row in sorted(table.items()):
        info = {"pid": pid, "ppid": row["ppid"], "comm": row["comm"], "command": row["command"], "start": None}
        if not module.desktop_app(info):
            continue
        live = probe.info(pid)
        if live and module.stale_app_helper(live, probe):
            pids.append(pid)
    result = {"ok": True, "action": "stale-helpers", "apply": bool(apply), "targets": [{"host": "local", "pid": p} for p in pids]}
    if not apply or not pids:
        return result
    result["local"] = ctx.kill_local(pids, "stale app helpers: %s" % reason, grace=10.0, foreign=True)
    result["ok"] = result["local"].get("ok", False)
    return result
