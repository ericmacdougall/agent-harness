"""The live org and work graph behind the Topology tab (GoodQA goodqa#15950, parent #15920).

One versioned snapshot, `mc.orggraph/1`, is built from real collectors only:

- agents and their state, severity, ticket and last activity: the `ah owners` rows the Owners collector holds;
- parent, type and spawn depth: each sub-agent's transcript meta file (`parentAgentId`, `agentType`, `spawnDepth`);
- model, advisor model and effort: the newest assistant record in the agent's transcript (`message.model`,
  `advisorModel`, `effort`), read from a byte-bounded tail. Only those scalars, timestamps, tool names and the
  target agent id of a SendMessage leave the reader; message text never does;
- machine: Claude Code writes a transcript on the host that runs the agent, so a transcript read here names this
  host (labelled `transcript-host`); anything else is "unknown";
- work items and their dependencies: GoodQA tickets (`parent`, `links.blocks`, `links.blockedBy`, status);
- escalation: the model-ladder state files (`~/.agent-harness/escalation/*.json`) through their dispatch agent ids.

A field with no source is the literal "unknown". Nothing is inferred from free text.
Each snapshot carries `changes`: what moved since the previous one (spawned, finished, state, assigned, reviewer
verdict, message, dag), so the page can animate it.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path

import events as ev
from safeio import Refused, TICKET_RE

SCHEMA = "mc.orggraph/1"
UNKNOWN = "unknown"
AGENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/\[\]@+-]{1,80}$")
TICKET_NUM = re.compile(r"(?:^|\s|GoodQA\s)([a-z0-9][a-z0-9-]{0,39})#([0-9]{1,7})\b")
RESTRICTED = re.compile(r"\b(solve|interview)", re.I)   # as ah.py: fail closed, liveness only
REVIEWER_TYPES = ("red-team", "click-tester", "reviewer")
DEFAULT_HELPERS = ("red-team", "click-tester", "reviewer", "fixer", "Explore", "Plan", "claude-code-guide",
                   "statusline-setup")
TAIL_BYTES = 192 * 1024
META_LIMIT = 65536
MAX_AGENTS = 80
MAX_TICKETS = 40
MAX_CHANGES = 120
TICKET_TTL_S = 300.0
LIVE_STATES = ("live", "working", "quiet", "observed")
DONE_STATUSES = ("done", "closed", "resolved", "released", "verified", "wontfix", "duplicate")


def _value(raw) -> str:
    """A scalar from a transcript is kept only when it looks like a model or effort name."""
    text = str(raw or "").strip()
    return text if SAFE_VALUE.match(text) else UNKNOWN


def ticket_ref(text) -> str:
    """The first `project#N` in a field, normalised to `project#N`, or ''."""
    match = TICKET_NUM.search(str(text or ""))
    if not match:
        return ""
    ref = f"{match.group(1)}#{match.group(2)}"
    return ref if TICKET_RE.match(ref) else ""


def helper_types() -> tuple:
    """The helper types from model_tiers.json (the same table the owner cap reads), else the shipped default."""
    try:
        import model_tiers  # noqa: PLC0415 - a hook module; absent in a bare checkout
        policy = model_tiers.load_policy()
        caps = (policy or {}).get("caps", {}) if isinstance(policy, dict) else {}
        found = caps.get("helper_types")
        if isinstance(found, list) and all(isinstance(x, str) for x in found):
            return tuple(found)
    except Exception:  # noqa: BLE001 - policy unavailable: the shipped list
        pass
    return DEFAULT_HELPERS


# ---------------------------------------------------------------- transcript facts (bounded, allowlisted)

class Transcripts:
    """Reads transcript meta files and bounded tails under one projects root. Caches by (inode, size, mtime)."""

    def __init__(self, root: Path, *, tail_bytes: int = TAIL_BYTES):
        self.root = Path(os.path.realpath(root))
        self.tail_bytes = tail_bytes
        self.cache: dict[str, tuple] = {}
        self.dirs: dict[str, tuple] = {}   # session -> (when, projects root mtime_ns, [session dirs])

    def _inside(self, path: Path) -> bool:
        real = Path(os.path.realpath(path))
        return self.root in real.parents

    def _open(self, path: Path):
        """O_NOFOLLOW, regular file, inside the root: anything else is refused."""
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not self._inside(path):
            raise Refused(f"{path.name} is not a regular transcript file under the projects root")
        # O_NONBLOCK: a FIFO swapped in after the lstat cannot block the collectors thread (review A-5); the fstat
        # then refuses anything that is not the same regular file the lstat saw
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise Refused(f"{path.name} changed while it was opened")
        except BaseException:
            os.close(fd)
            raise
        return os.fdopen(fd, "rb"), info

    DIRS_TTL_S = 30.0

    def session_dirs(self, session: str) -> list:
        """The session's directory in each project. The projects root holds 590+ dirs, so the scan is kept for
        DIRS_TTL_S (or until the root's mtime changes) instead of running for every agent on every tick (review
        A-3: 60 lookups took 2.3 s)."""
        now = time.monotonic()
        try:
            root_mtime = os.stat(self.root).st_mtime_ns
        except OSError:
            return []
        hit = self.dirs.get(session)
        if hit and now - hit[0] < self.DIRS_TTL_S and hit[1] == root_mtime:
            return hit[2]
        try:
            projects = [Path(e.path) for e in os.scandir(self.root) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return []
        found = [p / session for p in projects if (p / session).is_dir() and not (p / session).is_symlink()]
        if len(self.dirs) > 16:
            self.dirs.clear()
        self.dirs[session] = (now, root_mtime, found)
        return found

    def main_path(self, session: str) -> Path | None:
        for project in self.session_dirs(session):
            candidate = project.parent / f"{session}.jsonl"
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        return None

    def agent_path(self, session: str, agent: str, suffix: str) -> Path | None:
        if not AGENT_RE.match(agent):
            return None
        for project in self.session_dirs(session):
            candidate = project / "subagents" / f"agent-{agent}{suffix}"
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        return None

    def meta(self, session: str, agent: str) -> dict:
        path = self.agent_path(session, agent, ".meta.json")
        if not path:
            return {}
        try:
            handle, info = self._open(path)
            with handle:
                if info.st_size > META_LIMIT:
                    return {}
                raw = json.loads(handle.read(META_LIMIT))
        except (OSError, ValueError, RecursionError, Refused):
            return {}
        if not isinstance(raw, dict):
            return {}
        parent = raw.get("parentAgentId")
        depth = raw.get("spawnDepth")
        return {"type": ev.short(raw.get("agentType"), 40), "parent": parent if isinstance(parent, str) and AGENT_RE.match(parent) else None,
                "depth": depth if isinstance(depth, int) and not isinstance(depth, bool) else None,
                "description": ev.short(raw.get("description"), 160), "finished": bool(raw.get("finished"))}

    def facts(self, path: Path | None) -> dict:
        """Newest model, advisor model, effort and timestamp, plus SendMessage targets, from the tail."""
        empty = {"model": UNKNOWN, "advisor_model": UNKNOWN, "effort": UNKNOWN, "last_ts": "", "messages": [],
                 "read": False}
        if not path:
            return empty
        try:
            handle, info = self._open(path)
        except (OSError, Refused):
            return empty
        key = str(path)
        sig = (info.st_ino, info.st_size, info.st_mtime_ns)
        cached = self.cache.get(key)
        if cached and cached[0] == sig:
            handle.close()
            return cached[1]
        with handle:
            start = max(0, info.st_size - self.tail_bytes)
            handle.seek(start)
            data = handle.read(self.tail_bytes)
        lines = data.split(b"\n")
        if start:
            lines = lines[1:]  # the first line of a mid-file window is partial
        out = dict(empty, read=True, messages=[])
        for raw in reversed(lines):
            if not raw.strip() or len(raw) > self.tail_bytes:
                continue
            try:
                rec = json.loads(raw)
            except (ValueError, RecursionError):
                continue  # a truncated, malformed or absurdly nested line is skipped (NEG-1; review: nested JSON)
            if not isinstance(rec, dict):
                continue
            if not out["last_ts"] and isinstance(rec.get("timestamp"), str):
                out["last_ts"] = rec["timestamp"][:40]
            message = rec.get("message") if isinstance(rec.get("message"), dict) else None
            if rec.get("type") == "assistant" and message:
                if out["model"] == UNKNOWN and message.get("model") and message.get("model") != "<synthetic>":
                    out["model"] = _value(message.get("model"))
                if out["advisor_model"] == UNKNOWN and rec.get("advisorModel"):
                    out["advisor_model"] = _value(rec.get("advisorModel"))
                if out["effort"] == UNKNOWN and rec.get("effort"):
                    out["effort"] = _value(rec.get("effort"))
                content = message.get("content") if isinstance(message.get("content"), list) else []
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_use":
                        continue
                    name, args = block.get("name"), block.get("input") if isinstance(block.get("input"), dict) else {}
                    target = str(args.get("to") or "")
                    if name == "SendMessage" and AGENT_RE.match(target) and len(out["messages"]) < 20:
                        out["messages"].append({"id": ev.short(block.get("id"), 64), "to": target,
                                                "at": str(rec.get("timestamp") or "")[:40]})
        out["messages"].reverse()
        self.cache[key] = (sig, out)
        if len(self.cache) > 400:
            for stale in list(self.cache)[:100]:
                del self.cache[stale]
        return out


def escalations(root: Path | None, *, max_files: int = 200, max_age_s: float = 86400.0, now: float | None = None,
                limit: int = 262144) -> dict:
    """agent id -> {level, to, reason} from model-ladder state files touched in the last day."""
    out: dict[str, dict] = {}
    if not root:
        return out
    now = time.time() if now is None else now
    try:
        entries = [e for e in os.scandir(root) if e.name.endswith(".json") and e.is_file(follow_symlinks=False)]
    except OSError:
        return out
    fresh = []
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if now - info.st_mtime <= max_age_s and info.st_size <= limit:
            fresh.append((info.st_mtime, entry.path))
    for _, path in sorted(fresh, reverse=True)[:max_files]:
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as handle:
                state = json.loads(handle.read(limit))
        except (OSError, ValueError, RecursionError):
            continue
        if not isinstance(state, dict):
            continue
        steps = [e for e in state.get("escalations") or [] if isinstance(e, dict)]
        if not steps:
            continue
        last = steps[-1]
        level = len(steps)
        for dispatch in state.get("dispatches") or []:
            agent = dispatch.get("agent_id") if isinstance(dispatch, dict) else None
            if isinstance(agent, str) and AGENT_RE.match(agent):
                if level > out.get(agent, {}).get("level", 0):
                    out[agent] = {"level": level, "to": ev.short(last.get("to"), 12),
                                  "reason": ev.short(last.get("reason"), 80)}
    return out


# ---------------------------------------------------------------- the graph (pure)

def _role(agent: dict, helpers: tuple) -> str:
    kind = agent.get("type") or ""
    if kind in REVIEWER_TYPES:
        return "reviewer"
    cap = agent.get("cap_role")
    if cap == "helper":
        return "subagent"                               # goodqa#15920 owner_role: the cap's own classification
    if cap in ("live", "parked"):
        return "owner" if not agent.get("parent") else "subagent"
    if agent.get("owner_flag") or kind not in helpers:
        # the owner-cap rule (tier_gate.counts_as_owner): only a known helper type is not an owner.
        return "owner" if not agent.get("parent") else "subagent"
    return "subagent"


def _owner_of(agent_id: str, agents: dict) -> str | None:
    """Walk the parent chain to the nearest owner; a cycle or an unknown parent ends the walk (NEG-2)."""
    seen = {agent_id}
    current = agents.get(agent_id, {}).get("parent")
    while current and current not in seen:
        seen.add(current)
        node = agents.get(current)
        if not node:
            return None
        if node["role"] == "owner":
            return current
        current = node.get("parent")
    return None


def build(*, session: str, coordinator: dict, agents: list, tickets: dict, escalation: dict, host: str,
          now: float, helpers: tuple = DEFAULT_HELPERS, stale: dict | None = None) -> dict:
    """agents: dicts with agent_id, type, parent, depth, state, severity, last_activity, task, ticket, restricted,
    owner_flag and the transcript facts. tickets: ref -> {title, status, parent, blocks, blocked_by, children}."""
    by_id: dict[str, dict] = {}
    ordered = sorted(agents, key=lambda a: (str(a.get("state") or "") not in LIVE_STATES, a.get("idle_s") or 0))
    hidden = max(0, len(ordered) - MAX_AGENTS)
    for raw in ordered[:MAX_AGENTS]:                    # NEG-6: live first, then the cap
        agent_id = str(raw.get("agent_id") or "")
        if not AGENT_RE.match(agent_id):
            continue
        agent = dict(raw)
        if not agent.get("parent") and agent.get("serves") and agent.get("cap_role") == "helper":
            agent["parent"] = agent["serves"]           # the owner the collector says this helper serves
        if agent.get("parent") == agent_id:
            agent["parent"] = None
        agent["role"] = _role(agent, helpers)
        by_id[agent_id] = agent
    nodes, edges = [], []
    coord_id = "coordinator"
    nodes.append({"id": "user", "kind": "user", "label": "You", "inbox": coordinator.get("inbox", 0),
                  "inbox_stale": coordinator.get("inbox_stale", 0)})
    nodes.append({"id": coord_id, "kind": "coordinator", "label": "Main", "session": session,
                  "model": coordinator.get("model", UNKNOWN), "advisor_model": coordinator.get("advisor_model", UNKNOWN),
                  "effort": coordinator.get("effort", UNKNOWN), "machine": host if coordinator.get("read") else UNKNOWN,
                  "machine_source": "transcript-host" if coordinator.get("read") else "",
                  "last_activity": coordinator.get("last_ts") or UNKNOWN, "state": "live" if coordinator.get("read") else UNKNOWN})
    edges.append({"from": "user", "to": coord_id, "kind": "inbox"})
    tickets_held: dict[str, list] = {}
    for agent_id, agent in by_id.items():
        role = agent["role"]
        parent = agent.get("parent")
        if parent and parent not in by_id:
            parent_known = False
        else:
            parent_known = True
        owner = agent_id if role == "owner" else _owner_of(agent_id, by_id)
        restricted = bool(agent.get("restricted")) or bool(RESTRICTED.search(str(agent.get("task") or "") + " " +
                                                                            str(agent.get("description") or "")))
        ticket = "" if restricted else (ticket_ref(agent.get("ticket")) or ticket_ref(agent.get("task")))
        state = str(agent.get("state") or UNKNOWN)
        # The task text only: `ah owners` blanks it for a restricted row, and the meta description is never a fallback.
        mission = "" if restricted else ev.short(agent.get("task") or "", 160)
        esc = escalation.get(agent_id) or {}
        node = {"id": agent_id, "kind": role, "label": agent_id[:8], "type": agent.get("type") or UNKNOWN,
                "state": state, "severity": str(agent.get("severity") or "info")[:8],
                "escalation": esc.get("level", 0), "escalation_to": esc.get("to", ""), "escalation_reason": esc.get("reason", ""),
                "model": agent.get("model") or UNKNOWN, "advisor_model": agent.get("advisor_model") or UNKNOWN,
                "effort": agent.get("effort") or UNKNOWN,
                "machine": host if agent.get("read") else UNKNOWN,
                "machine_source": "transcript-host" if agent.get("read") else "",
                "last_activity": agent.get("last_activity") or agent.get("last_ts") or UNKNOWN,
                "task": "restricted" if restricted else (mission or UNKNOWN), "restricted": restricted,
                "mission": ("idle" if state not in LIVE_STATES else (mission or UNKNOWN)) if role == "owner" else "",
                "ticket": ticket, "owner": owner or "", "parent": parent if parent_known else "",
                "parent_known": parent_known,
                # live = holds an owner-cap slot (goodqa#15920 role) when the collector says so, else a running state
                "live": (agent.get("cap_role") == "live") if agent.get("cap_role") in ("live", "parked")
                else state in LIVE_STATES}
        if role == "owner":
            edges.append({"from": coord_id, "to": agent_id, "kind": "spawn"})
        elif parent and parent_known:
            edges.append({"from": parent, "to": agent_id, "kind": "spawn"})
        else:
            edges.append({"from": coord_id, "to": agent_id, "kind": "spawn", "unknown_parent": bool(parent)})
        nodes.append(node)
        if ticket and role != "reviewer" and state in LIVE_STATES:
            tickets_held.setdefault(ticket, []).append(node)
    # Reviewer pairing: only on a real key (same parent and same ticket), else "unknown" (NEG-3).
    agent_nodes = {n["id"]: n for n in nodes if n["kind"] in ("owner", "subagent", "reviewer")}
    for node in [n for n in nodes if n["kind"] == "reviewer"]:
        target, source = None, ""
        if node["ticket"]:
            siblings = [n for n in agent_nodes.values() if n["kind"] == "subagent" and n["ticket"] == node["ticket"]
                        and n["parent"] == node["parent"] and node["parent"]]
            if len(siblings) == 1:
                target, source = siblings[0]["id"], "parent+ticket"
            else:
                holders = [n for n in agent_nodes.values() if n["kind"] in ("owner", "subagent") and n["ticket"] == node["ticket"]]
                subs = [n for n in holders if n["kind"] == "subagent"]
                owners = [n for n in holders if n["kind"] == "owner"]
                if len(subs) == 1:
                    target, source = subs[0]["id"], "ticket"
                elif not subs and len(owners) == 1:
                    target, source = owners[0]["id"], "ticket"
        node["reviews"] = target or UNKNOWN
        node["pairing_source"] = source
        if target:
            edges.append({"from": node["id"], "to": target, "kind": "review"})
            if not node["owner"]:
                node["owner"] = agent_nodes[target]["owner"] or (target if agent_nodes[target]["kind"] == "owner" else "")
    # Work items: each held ticket sits under the deepest live agent holding it; links make the DAG layers.
    work: dict[str, dict] = {}

    def add_work(ref: str, layer: int, via: str) -> dict | None:
        if ref in work:
            work[ref]["layer"] = min(work[ref]["layer"], layer)
            return work[ref]
        if len(work) >= MAX_TICKETS:
            return None
        info = tickets.get(ref) or {}
        status = str(info.get("status") or UNKNOWN)
        item = {"id": f"work:{ref}", "kind": "work", "ref": ref, "label": ref, "title": ev.short(info.get("title"), 120) or UNKNOWN,
                "status": status, "done": status.lower() in DONE_STATUSES, "layer": layer, "via": via,
                "is_blocked": bool(info.get("is_blocked")), "priority": str(info.get("priority") or "")[:12],
                "children": info.get("children") if isinstance(info.get("children"), int) else None,
                "holders": [], "owner": "", "stale": bool((stale or {}).get(ref)), "read": bool(info)}
        work[ref] = item
        return item

    for ref, holders in tickets_held.items():
        item = add_work(ref, 0, "held")
        if not item:
            continue
        holders.sort(key=lambda n: (n["kind"] != "subagent", n["id"]))
        item["holders"] = [n["id"] for n in holders]
        item["owner"] = holders[0]["owner"] or holders[0]["id"]
        edges.append({"from": holders[0]["id"], "to": item["id"], "kind": "works_on"})
    frontier = [(ref, 0) for ref in list(work)]
    while frontier:
        ref, layer = frontier.pop(0)
        info = tickets.get(ref) or {}
        owner = work[ref]["owner"]
        for nxt in info.get("blocks") or []:            # next in line: depends on this item, one layer deeper
            child = add_work(nxt, layer + 1, "blocks")
            if child:
                child["owner"] = child["owner"] or owner
                edges.append({"from": work[ref]["id"], "to": child["id"], "kind": "next"})
                if child["layer"] == layer + 1 and layer < 5:
                    frontier.append((nxt, layer + 1))
        for dep in info.get("blocked_by") or []:        # a prerequisite clusters beside its dependent
            pre = add_work(dep, layer, "blocked_by")
            if pre:
                pre["owner"] = pre["owner"] or owner
                edges.append({"from": pre["id"], "to": work[ref]["id"], "kind": "depends"})
        parent = info.get("parent")
        if parent:
            epic = add_work(parent, -1, "parent")
            if epic:
                epic["owner"] = epic["owner"] or owner
                edges.append({"from": epic["id"], "to": work[ref]["id"], "kind": "parent"})
    nodes.extend(work.values())
    counts = {kind: sum(1 for n in nodes if n["kind"] == kind) for kind in ("owner", "subagent", "reviewer", "work")}
    counts["live_owners"] = sum(1 for n in nodes if n["kind"] == "owner" and n.get("live"))
    counts["hidden_agents"] = hidden
    links = sum(len((tickets.get(r) or {}).get("blocks") or []) + len((tickets.get(r) or {}).get("blocked_by") or [])
                for r in work)
    gaps = []
    if not links:
        gaps.append("No GoodQA dependency links on the held tickets: the planned DAG has no recorded edges yet.")
    if any(n.get("children") for n in work.values()):
        gaps.append("Some tickets have child tickets, but there is no API to list them, so they are counted and not shown.")
    return {"schema": SCHEMA, "generated": ev.iso(now), "session": session, "host_label": host,
            "nodes": nodes, "edges": edges, "counts": counts, "gaps": gaps}


def _index(snapshot: dict | None) -> dict:
    return {n["id"]: n for n in (snapshot or {}).get("nodes") or []}


def diff(previous: dict | None, current: dict, now: float) -> list:
    """What changed between two snapshots, as animation cues. The first snapshot yields no changes."""
    if not previous:
        return []
    before, after = _index(previous), _index(current)
    at = ev.iso(now)
    out = []
    for node_id, node in after.items():
        old = before.get(node_id)
        kind = node["kind"]
        if kind in ("user", "coordinator"):
            continue
        if old is None:
            out.append({"type": "added" if kind == "work" else "spawned", "node": node_id, "kind": kind, "at": at,
                        "from": node.get("parent") or ("coordinator" if kind == "owner" else node.get("owner") or "coordinator")})
            continue
        if kind == "work":
            if old.get("status") != node.get("status"):
                out.append({"type": "progress", "node": node_id, "kind": kind, "at": at, "from_state": old.get("status"),
                            "to_state": node.get("status")})
            if old.get("layer") != node.get("layer") or old.get("holders") != node.get("holders"):
                out.append({"type": "moved", "node": node_id, "kind": kind, "at": at})
            continue
        if old.get("state") != node.get("state"):
            finished = node["state"] in ("done", "returned", "handoff") and old.get("state") in LIVE_STATES
            out.append({"type": "finished" if finished else "state", "node": node_id, "kind": kind, "at": at,
                        "from_state": old.get("state"), "to_state": node.get("state"),
                        "to": node.get("reviews") if kind == "reviewer" and node.get("reviews") != UNKNOWN else node.get("owner") or "coordinator"})
        if old.get("ticket") != node.get("ticket") and node.get("ticket"):
            out.append({"type": "assigned", "node": node_id, "kind": kind, "at": at, "ticket": node["ticket"]})
        for field in ("model", "effort", "escalation"):
            if old.get(field) != node.get(field):
                out.append({"type": "changed", "node": node_id, "kind": kind, "at": at, "field": field,
                            "value": node.get(field)})
    for node_id, old in before.items():
        if node_id not in after and old["kind"] not in ("user", "coordinator"):
            out.append({"type": "removed", "node": node_id, "kind": old["kind"], "at": at})
    old_edges = {(e["from"], e["to"], e["kind"]) for e in previous.get("edges") or []}
    for edge in current.get("edges") or []:
        key = (edge["from"], edge["to"], edge["kind"])
        if key not in old_edges and edge["kind"] in ("next", "depends", "parent"):
            out.append({"type": "dag", "edge": edge, "at": at})
    return out[:MAX_CHANGES]


# ---------------------------------------------------------------- the collector

class OrgGraph:
    """Collector-shaped (name, interval, run via collectors.Collector) so server.py ticks it with the others."""
    name = "org-graph"
    interval = 5.0
    idle_interval = 60.0

    def __init__(self, hub, health, runner, *, owners_fn, session_fn, transcripts: Transcripts,
                 escalation_root: Path | None, host: str, inbox_fn=None):
        from collectors import Collector  # noqa: PLC0415 - avoid an import cycle at module load
        self._base = Collector(hub, health)
        self.hub, self.health, self.runner = hub, health, runner
        self.owners_fn, self.session_fn = owners_fn, session_fn
        self.transcripts, self.escalation_root, self.host = transcripts, escalation_root, host
        self.inbox_fn = inbox_fn or (lambda: (0, 0))
        self.on_initiatives, self.initiatives_sig = None, None
        self.snapshot_data: dict | None = None
        self.metas: dict[str, tuple] = {}   # agent id -> (meta file fingerprint, fields)
        self.tickets: dict[str, dict] = {}
        self.ticket_at: dict[str, float] = {}
        self.ticket_stale: dict[str, bool] = {}
        self.ticket_cursor = 0
        self.messages_seen: set[str] = set()
        self.seeded_messages = False
        self.escalation_cache: tuple[float, dict] = (0.0, {})
        self.seq = 0
        self.helpers = helper_types()

    # Collector protocol, delegated so `due`, `wake` and `run` keep one implementation.
    @property
    def next_at(self):
        return self._base.next_at

    def due(self, now):
        return self._base.due(now)

    def wake(self, now):
        self._base.wake(now)

    def run(self, now):
        base = self._base
        base.next_at = now + (self.interval if base.watched() else max(self.interval, self.idle_interval))
        base.ran_at = now
        try:
            self.health.ok(self.name, self.tick(now))
        except Refused as exc:
            self.health.error(self.name, f"refused: {exc}")
        except Exception as exc:  # noqa: BLE001 - shown, never fatal
            self.health.error(self.name, f"{type(exc).__name__}: {str(exc)[:160]}")

    def _ticket(self, ref: str, now: float) -> None:
        code, out = self.runner.run("ah-ticket-get", ref, timeout=20)
        if code != 0:
            self.ticket_stale[ref] = True            # NEG-5: keep the last good copy, mark it stale
            return
        data = json.loads(out)
        issue = data.get("issue") if isinstance(data, dict) else None
        if not isinstance(issue, dict):
            self.ticket_stale[ref] = True
            return
        project = ref.split("#")[0]

        def refs(values):
            found = []
            for value in values or []:
                number = value.get("number") if isinstance(value, dict) else value
                slug = (value.get("projectSlug") if isinstance(value, dict) else None) or project
                if isinstance(number, int) and not isinstance(number, bool):
                    candidate = f"{slug}#{number}"
                    if TICKET_RE.match(candidate):
                        found.append(candidate)
            return found[:12]

        links = issue.get("links") if isinstance(issue.get("links"), dict) else {}
        parent = issue.get("parent")
        parent_ref = refs([parent])[0] if isinstance(parent, dict) and refs([parent]) else ""
        self.tickets[ref] = {"title": ev.short(issue.get("title"), 120), "status": ev.short(issue.get("status"), 24),
                             "priority": ev.short(issue.get("priority"), 12), "is_blocked": bool(issue.get("isBlocked")),
                             "children": issue.get("childrenCount") if isinstance(issue.get("childrenCount"), int) else None,
                             "blocks": refs(links.get("blocks")), "blocked_by": refs(links.get("blockedBy")),
                             "parent": parent_ref}
        self.ticket_at[ref] = now
        self.ticket_stale[ref] = False

    def _refresh_tickets(self, wanted: list, now: float) -> None:
        """One ticket read per tick, oldest first: about 40 tickets refresh in 3 minutes at the 5 s cadence."""
        known = set(wanted)
        for ref in list(self.tickets):
            known.update(self.tickets[ref].get("blocks") or [])
            known.update(self.tickets[ref].get("blocked_by") or [])
            if self.tickets[ref].get("parent"):
                known.add(self.tickets[ref]["parent"])
        candidates = sorted(known, key=lambda r: self.ticket_at.get(r, 0.0))[:MAX_TICKETS]
        due = [r for r in candidates if now - self.ticket_at.get(r, 0.0) >= TICKET_TTL_S]
        if due:
            try:
                self._ticket(due[0], now)
            except (ValueError, OSError, RecursionError, Refused):
                self.ticket_stale[due[0]] = True
                self.ticket_at[due[0]] = now - TICKET_TTL_S / 2   # retry after half the TTL, not every tick

    def tick(self, now: float):
        session = self.session_fn() or ""
        rows = [r for r in (self.owners_fn() or []) if isinstance(r, dict) and r.get("runtime", "claude") != "codex"
                and AGENT_RE.match(str(r.get("agent_id") or ""))]
        main_path = self.transcripts.main_path(session) if session else None
        coordinator = self.transcripts.facts(main_path)
        inbox = self.inbox_fn()
        # None: the asks source has not reported yet; the page says "loading", never a false 0.
        open_asks, stale_asks = (None, None) if inbox is None else inbox if isinstance(inbox, tuple) else (int(inbox or 0), 0)
        coordinator = dict(coordinator, inbox=open_asks, inbox_stale=stale_asks)
        agents = []
        for row in rows:
            agent_id = str(row["agent_id"])
            # review A-8: the meta is re-read when its file changes (finished, type), not cached for ever
            meta_path = self.transcripts.agent_path(session, agent_id, ".meta.json") if session else None
            try:
                st = os.lstat(meta_path) if meta_path else None
                fp = (st.st_ino, st.st_size, st.st_mtime_ns) if st else None
            except OSError:
                fp = None
            hit = self.metas.get(agent_id)
            if hit and hit[0] == fp and fp is not None:
                meta = hit[1]
            else:
                meta = self.transcripts.meta(session, agent_id) if session else {}
                self.metas[agent_id] = (fp, meta)
            facts = self.transcripts.facts(self.transcripts.agent_path(session, agent_id, ".jsonl") if session else None)
            agents.append({"agent_id": agent_id, "type": row.get("type") or meta.get("type") or "",
                           "parent": meta.get("parent"), "depth": meta.get("depth"), "state": row.get("state"),
                           "severity": row.get("severity"), "last_activity": row.get("last_activity"),
                           "idle_s": row.get("idle_s"), "task": row.get("task") or "", "ticket": row.get("ticket") or "",
                           "restricted": bool(row.get("restricted")), "owner_flag": row.get("owner") is True,
                           "cap_role": row.get("role") if row.get("role") in ("helper", "live", "parked") else None,
                           "serves": row.get("serves") if AGENT_RE.match(str(row.get("serves") or "")) else None,
                           "description": meta.get("description") or "", **facts})
        seen = {a["agent_id"] for a in agents}
        self.metas = {k: v for k, v in self.metas.items() if k in seen}
        wanted = []
        for agent in agents:
            ref = ticket_ref(agent["ticket"]) or ticket_ref(agent["task"])
            if ref and str(agent.get("state")) in LIVE_STATES and ref not in wanted:
                wanted.append(ref)
        self._refresh_tickets(wanted, now)
        if now - self.escalation_cache[0] > 60:
            self.escalation_cache = (now, escalations(self.escalation_root, now=now))
        snapshot = build(session=session, coordinator=coordinator, agents=agents, tickets=self.tickets,
                         escalation=self.escalation_cache[1], host=self.host, now=now, helpers=self.helpers,
                         stale=self.ticket_stale)
        live_rows = [[r.get("agent_id"), r.get("ticket"), r.get("task")] for r in (self.owners_fn() or [])
                     if isinstance(r, dict) and r.get("role") == "live"]
        sig = json.dumps([live_rows, sorted((k, v.get("title"), v.get("status")) for k, v in self.tickets.items())],
                         default=str)
        if sig != self.initiatives_sig and self.on_initiatives:
            self.initiatives_sig = sig
            self.on_initiatives()
        if any(isinstance(r, dict) and r.get("source") == "ah" and (r.get("ah_stale") or r.get("source_stale"))
               for r in (self.owners_fn() or [])):   # as owner-groups ownersStale: Codex native rows do not count
            snapshot["gaps"].insert(0, "The last ah owners read failed: owners and their roles are from the previous good "
                                       "read and may be out of date.")
        if not session:
            snapshot["gaps"].insert(0, "No session is selected yet: ah owners has not reported one.")
        elif main_path is None:
            # ah owners follows the newest main WAL, Codex sessions included (goodqa#15961): say so, never a silent 0.
            snapshot["gaps"].insert(0, f"Following session {session[:8]}, which has no Claude transcript (likely a Codex "
                                       "session that wrote the newest WAL); owners and asks may read 0 (goodqa#15961).")
        changes = diff(self.snapshot_data, snapshot, now)
        # Messages from the coordinator and owners, read from their transcripts' SendMessage targets.
        senders = [("coordinator", coordinator)] + [(a["agent_id"], a) for a in agents]
        node_ids = {n["id"] for n in snapshot["nodes"]}
        for sender, facts in senders:
            for message in facts.get("messages") or []:
                key = f"{sender}:{message['id']}"
                if key in self.messages_seen:
                    continue
                self.messages_seen.add(key)
                if self.seeded_messages and message["to"] in node_ids:
                    changes.append({"type": "message", "from": sender, "to": message["to"], "at": message["at"]})
        self.seeded_messages = True
        if len(self.messages_seen) > 5000:
            self.messages_seen = set(list(self.messages_seen)[-2000:])
        self.seq += 1
        snapshot["seq"] = self.seq
        snapshot["changes"] = changes[:MAX_CHANGES]
        published = self.snapshot_data is None or changes or _shape(self.snapshot_data) != _shape(snapshot)
        self.snapshot_data = snapshot
        if published:
            self.hub.snapshot("orggraph", snapshot)
        counts = snapshot["counts"]
        return f"{counts['live_owners']} live owners, {counts['subagent']} subagents, {counts['reviewer']} reviewers, {counts['work']} work items"

    def snapshot(self) -> dict:
        return self.snapshot_data or {"schema": SCHEMA, "generated": "", "nodes": [], "edges": [], "counts": {},
                                      "gaps": [], "changes": [], "seq": 0}


# ---------------------------------------------------------------- initiatives from live data (pure)

FILE_FRESH_S = 24 * 3600
STATUS_LABELS = {"in_progress": "In progress", "in_review": "In review", "todo": "Not started", "backlog": "Not started",
                 "blocked": "Blocked", "done": "Done", "closed": "Done", "canceled": "Done"}


def derive_initiatives(file_snapshot: dict, owner_rows: list, tickets: dict, now: float) -> dict:
    """The Initiatives panel from live data: one row per GoodQA ticket a live owner holds (the owner cap's role, from
    `ah owners`), titled and stated from GoodQA when read. A file row with the same ticket adds its plan fields; other
    file rows stay only while the hand-written file is under a day old, and the hidden count is reported."""
    snap = file_snapshot or {}
    mtime = snap.get("mtime")
    file_items = [i for i in (snap.get("items") or []) if isinstance(i, dict)]
    by_ticket = {ticket_ref(i.get("ticket")): i for i in file_items if ticket_ref(i.get("ticket"))}
    derived, seen, untracked = [], set(), 0
    for row in owner_rows or []:
        if not isinstance(row, dict) or row.get("role") != "live" or row.get("source", "ah") != "ah":
            continue
        task = str(row.get("task") or "")
        ref = ticket_ref(row.get("ticket")) or ticket_ref(task)
        agent = str(row.get("agent_id") or "")
        if not ref and AGENT_RE.match(agent):
            # A live owner with no ticket still gets a row (linked by its id), flagged: every stream should have one.
            restricted = bool(row.get("restricted")) or bool(RESTRICTED.search(task))
            derived.append({"id": "live-" + agent[:40], "initiative": "Untracked work (no ticket)" if restricted or not task
                            else ev.short(task, 200), "state": "No ticket", "ticket": "", "owner": agent,
                            "source": "live", "updated": str(row.get("last_activity") or "")[:40],
                            "milestones_done": None, "milestones_total": None, "pct": None,
                            "note": "This live owner holds no GoodQA ticket."})
            untracked += 1
            continue
        if not ref or ref in seen or row.get("restricted") or RESTRICTED.search(task):
            continue
        seen.add(ref)
        info = tickets.get(ref) or {}
        status = str(info.get("status") or "")
        base = dict(by_ticket.get(ref) or {})
        title = ev.short(info.get("title") or base.get("initiative") or task or ref, 200)
        base.update({"id": "live-" + re.sub(r"[^A-Za-z0-9._-]", "_", ref)[:58], "initiative": title,
                     "state": STATUS_LABELS.get(status, status.replace("_", " ").capitalize() or "unknown"),
                     "ticket": ref, "owner": str(row.get("agent_id") or "")[:40], "source": "live",
                     "updated": str(row.get("last_activity") or "")[:40]})
        if base.get("pct") is None:
            base.setdefault("milestones_done", None)
            base.setdefault("milestones_total", None)
        derived.append(base)
    fresh = isinstance(mtime, (int, float)) and now - mtime < FILE_FRESH_S
    kept = [dict(i, source="file") for i in file_items if ticket_ref(i.get("ticket")) not in seen] if fresh else []
    hidden = 0 if fresh else sum(1 for i in file_items if ticket_ref(i.get("ticket")) not in seen)
    return {**snap, "items": derived + kept, "derived": len(derived), "untracked": untracked, "hidden_file_rows": hidden}


def _shape(snapshot: dict) -> str:
    """Everything the page shows except the generation time, so an unchanged graph is not re-sent."""
    return json.dumps({k: v for k, v in snapshot.items() if k not in ("generated", "seq", "changes")}, sort_keys=True,
                      default=str)
