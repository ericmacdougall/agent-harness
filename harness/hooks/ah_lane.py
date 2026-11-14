#!/usr/bin/env python3
"""`ah lane ...`: thin entry for the lane factory (GoodQA goodqa#15946, slice S1). All behaviour lives in lane/commands.py.

Run as `python3 ~/.claude/hooks/ah.py lane <command> ...` (ah.py hands the arguments here). The real ports below read
the live harness; the handlers are tested over fake ports. Exit codes: 0 ok, 2 usage, 3 refused, 4 not known,
5 conflict, 6 partial.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lane import auth, commands, kit, lanes, manifest, sources, store as st  # noqa: E402

POLICY_FILES = ("model_tiers.json", "spec_policy.json", "commit_policy.json", "domain_checklists.json")
TICKET_REF = re.compile(r"^GoodQA ([a-z0-9][a-z0-9-]{0,60})#([0-9]{1,9})$")


def _home() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


class TicketPort:
    """GoodQA through the existing adapter. Live behaviour is verified by AC-44 on the installed build."""

    def __init__(self):
        import spec_flow as sf  # noqa: PLC0415
        self.sf = sf
        self.policy = sf.load_spec_policy()
        _, _, self.config = sf.ticket_config(self.policy)
        self._issue = {}

    def _adapter(self, project):
        return self.sf.make_adapter(self.config, self.policy, project, time.monotonic() + 90)

    def _ticket(self, ref):
        match = TICKET_REF.match(ref)
        if not match:
            raise ValueError("bad ticket reference")
        project, number = match.group(1), int(match.group(2))
        ad = self._adapter(project)
        if ref not in self._issue:
            t = ad.lookup(project, number)
            if t is None:
                raise LookupError("ticket not found")
            self._issue[ref] = t
        return ad, self._issue[ref]

    def read(self, ref):
        ad, t = self._ticket(ref)
        return {"title": t.title, "body": getattr(t, "description", "")}

    def list_attachments(self, ref):
        ad, t = self._ticket(ref)
        def name(a):
            meta = a.get("metadata") if isinstance(a.get("metadata"), dict) else {}
            return a.get("filename") or a.get("name") or meta.get("filename")
        # issue_attachments_list answers only files a comment on this issue linked; unlinked uploads never appear
        return [{"id": a.get("id"), "name": name(a), "sha256": a.get("sha256")} for a in ad.attachments(t.id)]

    def upload(self, ref, name, data):
        """A project-surface upload: the file is NOT on the issue until a comment names its id. The caller persists
        the returned id before commenting; nothing is kept in this process."""
        import hashlib  # noqa: PLC0415
        ad, t = self._ticket(ref)
        return ad.upload(t.project_id, name, "text/plain", data, hashlib.sha256(data).hexdigest())

    def comment(self, ref, body, key, attachment_ids=()):
        """Post once per key: the body carries `[op key]` (find_comment reads it back) and GoodQA's operationId is the
        same uuid on every retry, so a lost response is never a second comment."""
        ad, t = self._ticket(ref)
        c = ad.comment_with_files(t.id, "%s\n\n[op %s]" % (body, key), self.sf.op_id(t.id, "lane:" + key),
                                  list(attachment_ids))
        return c["id"]

    def find_comment(self, ref, key):
        ad, t = self._ticket(ref)
        for c in ad.all_comments(t.id):
            if ("[op %s]" % key) in str(c.get("body") or ""):
                return c.get("id")
        return None


class RealPorts:
    def __init__(self):
        import escalation as esc  # noqa: PLC0415
        import model_tiers  # noqa: PLC0415
        self.esc, self.tiers = esc, model_tiers
        self.tier_policy = model_tiers.load_policy()
        # the same resolution `ah` uses (ah.env_session); empty means unknown and the commands that need it refuse
        self.session = os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or ""
        self._caller = {"id": "main"}
        self.host_alias = os.environ.get("AH_HOST_ALIAS", "local")
        self.templates_root = HERE / "lane" / "templates"
        self.default_kit_version = "v1"
        self.escalation_root = Path(os.environ.get("AGENT_HARNESS_ESCALATION_DIR") or _home() / ".agent-harness" / "escalation")
        self._ticket = None

    @property
    def ticket(self):
        if self._ticket is None:
            self._ticket = TicketPort()
        return self._ticket

    # clock, ids, policy digests
    def now(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())  # never an environment override

    def new_id(self):
        return lanes.new_lane_id()

    def policy_files(self):
        out = {}
        for name in POLICY_FILES:
            p = HERE / name
            if p.is_file() and not p.is_symlink():
                out[name] = p.read_bytes()
        return out

    # caller proof: one-shot stamps from the PreToolUse hook only
    def is_main(self, command, key):
        return auth.is_main(command, key)

    def caller(self):
        return {"id": self._caller.get("id"), "session": self.session}

    def set_caller(self, agent_id):
        self._caller = {"id": agent_id}

    def holder_caller(self, lane):
        agent = auth.holder_identity(lane)
        return {"id": agent, "session": self.session} if agent else None

    # sources
    def owners(self):
        return sources.read_owner_rows(_home(), self.session)

    def ledger(self, stream, prior_activity=False):
        return sources.ledger_peek(stream, self.escalation_root, self.tier_policy, prior_activity)

    def grant_for(self, stream, rung):
        return False  # a top-rung grant is checked by approve-top; none is read here, so the packet says "needs approve-top"

    def spawn_spec(self, rung):
        return self.tiers.spawn_spec(self.tier_policy, rung)

    def reviewer_line(self, rung):
        r = self.tiers.reviewer_for(self.tier_policy, rung)
        return "%s %s %s" % (r["rung"], r["harness"], r["effort"])

    def dispatch_task_key(self, agent):
        return self.esc.lookup_agent(self.escalation_root, agent)

    def spawn_observed(self, stream):
        for agent, task in self.esc._read_index(self.escalation_root).items():
            if task == stream:
                return agent
        return None

    def subagent_start_seen(self, agent):
        wal = _home() / ".claude" / "wals" / self.session / "main.jsonl"
        try:
            for line in wal.read_text().splitlines()[-20000:]:
                if '"event":"subagent"' in line.replace(" ", "") and agent in line:
                    return True
        except OSError:
            pass
        return False

    @staticmethod
    def register_source(ticket, task, agent):
        """A Source provenance.resolve accepts (`inferred: from <source> -- <rationale>`), grounded on the lane's
        ticket, the requirement the lane serves. Deterministic, so a retry is the same ah request (a duplicate)."""
        return ("inferred: from ticket:%s -- ah lane bind: main bound agent %s, whose spawn the hook recorded for "
                "stream %s, as the holder of this ticket's lane" % (ticket, agent, task))

    def task_register(self, *, task, agent, ticket, branch, worktree, op):
        argv = [sys.executable, str(HERE / "ah.py"), "task", "register", "--task", task, "--owner-agent", agent,
                "--scope", "lane brief " + task, "--ticket", ticket, "--source", self.register_source(ticket, task, agent),
                "--branch", branch, "--worktree", worktree, "--session", self.session, "--key", op]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if done.returncode:
            try:
                answer = json.loads((done.stdout or "").strip().splitlines()[-1])
            except (ValueError, IndexError):
                answer = {}
            if answer.get("code") == "task_exists":
                raise lanes.LaneRefusal("stream %s is already registered to another holder; reassigning a lane is a "
                                        "later slice (adopt), not a bind" % task)
            raise RuntimeError("task register failed (exit %d, %s)" % (done.returncode, str(answer.get("code"))[:40]))
        body = "Lane holder %s registered for %s." % (agent[:12], task)
        return self.ticket.find_comment(ticket, op) or self.ticket.comment(ticket, body, op)

    def wal_target(self):
        """The caller's session log. checkpoint records it before appending, so a retry writes to the same file."""
        folder = _home() / ".claude" / "wals" / self.session
        agent = self._caller.get("id")
        return str(folder / ("agent-%s.jsonl" % agent if agent and agent != "main" else "main.jsonl"))

    def wal_note(self, lane, kind, note, *, op_key, target):
        """Exactly once per op_key: wal_note dedupes under the session-log file lock and answers the existing id."""
        argv = [sys.executable, str(HERE / "wal_note.py"), "--wal", str(target), "--event", "status",
                "--op-key", op_key, "--note", "lane %s checkpoint %s: %s" % (lane, kind, note)]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        try:
            answer = json.loads(done.stdout)
        except ValueError:
            answer = {}
        if done.returncode or answer.get("status") not in ("WROTE", "DUPLICATE") or not answer.get("id"):
            raise RuntimeError("wal note failed (exit %d)" % done.returncode)
        return answer["id"]

    def make_worktree(self, branch, worktree, repo_path):
        if os.path.lexists(worktree):
            from lane import worktrees  # noqa: PLC0415
            worktrees.verify_worktree(worktree, repo_path, branch)  # raises LaneRefusal unless it is the right worktree
            return
        subprocess.run(["git", "-C", repo_path, "worktree", "add", "-b", branch, worktree], check=True,
                       capture_output=True, timeout=120)

    def last_remote_head(self, lane):
        return None

    def spec_state(self, ref):
        """G2 inputs from spec_flow's own evaluation: a verified spec record, and its required reviews accepted on the
        current core. `ready` (full completion: evidence, logs, live test, sign-off) is used for neither; a status
        without the two fields is unknown, never guessed."""
        import spec_flow as sf  # noqa: PLC0415
        try:
            _, data, _ = sf.ticket_status(ref, sf.load_spec_policy())
        except sf.SpecError as error:
            raise RuntimeError("spec status unreadable (%s)" % str(error)[:80])
        verified, accepted = data.get("spec_verified"), data.get("reviews_accepted")
        if not isinstance(verified, bool) or not isinstance(accepted, bool):
            raise RuntimeError("spec status has no spec_verified/reviews_accepted fields")
        return {"verified": verified, "reviews_accepted": accepted, "core": data.get("spec_core_sha")}

    def ls_remote(self, worktree, branch):
        done = subprocess.run(["git", "-C", worktree, "ls-remote", "--heads", "origin", branch], capture_output=True,
                              text=True, timeout=60)
        if done.returncode:
            raise RuntimeError("ls-remote failed")
        return done.stdout.split()[0] if done.stdout.strip() else ""

    def local_git(self, worktree):
        head = subprocess.run(["git", "-C", worktree, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30)
        dirty = subprocess.run(["git", "-C", worktree, "status", "--porcelain"], capture_output=True, text=True, timeout=30)
        if head.returncode or dirty.returncode:
            raise RuntimeError("local git unreadable")
        return {"head": head.stdout.strip(), "dirty": bool(dirty.stdout.strip()), "base": None}

    def is_ancestor(self, worktree, a, b):
        return subprocess.run(["git", "-C", worktree, "merge-base", "--is-ancestor", a, b], capture_output=True,
                              timeout=30).returncode == 0


def build_parser():
    p = argparse.ArgumentParser(prog="ah lane")
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new")
    n.add_argument("--ticket", required=True)
    n.add_argument("--repo", required=True)
    n.add_argument("--profile", choices=("python-hooks", "generic"), default="generic")
    n.add_argument("--goal")
    n.add_argument("--branch")
    n.add_argument("--worktree")
    n.add_argument("--live-target")
    n.add_argument("--live-kind", choices=("web-origin", "install-hosts"), default="web-origin")
    n.add_argument("--source")
    n.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("set-live-target")
    s.add_argument("--lane", required=True)
    s.add_argument("--kind", choices=("web-origin", "install-hosts"), required=True)
    s.add_argument("--value", required=True)
    s.add_argument("--source")
    s.add_argument("--dry-run", action="store_true")
    t = sub.add_parser("start")
    t.add_argument("--lane", required=True)
    t.add_argument("--reconcile", action="store_true")
    t.add_argument("--release", action="store_true")
    t.add_argument("--reason")
    b = sub.add_parser("bind")
    b.add_argument("--lane", required=True)
    b.add_argument("--agent", required=True)
    c = sub.add_parser("checkpoint")
    c.add_argument("--lane", required=True)
    c.add_argument("--kind", required=True)
    c.add_argument("--note", required=True)
    c.add_argument("--evidence")
    c.add_argument("--key")
    for name in ("refresh", "status", "verify"):
        q = sub.add_parser(name)
        q.add_argument("--lane", required=True)
        q.add_argument("--json", action="store_true")
    g = sub.add_parser("regenerate")
    g.add_argument("--lane", required=True)
    g.add_argument("--version", required=True)
    g.add_argument("--reason", choices=("canary", "rollback"), required=True)
    r = sub.add_parser("resolve-ledger")
    r.add_argument("--lane", required=True)
    r.add_argument("--reset", required=True)
    r.add_argument("--rung", required=True)
    r.add_argument("--reason", required=True)
    r.add_argument("--source")
    return p


def run(args, ports, store) -> "commands.Result":
    c = args.cmd
    if c == "new":
        live = (args.live_kind, args.live_target) if args.live_target else None
        env = {k: os.environ[k] for k in ("LANE_KIT_VERSION",) if k in os.environ}  # honoured only after the main stamp
        return commands.new(ports, store, ticket=args.ticket, repo=args.repo, profile=args.profile, dry_run=args.dry_run,
                            live_target=live, live_source=args.source, branch=args.branch, worktree=args.worktree,
                            env=env)
    if c == "set-live-target":
        return commands.set_live_target(ports, store, lane=args.lane, kind=args.kind, value=args.value, source=args.source,
                                        dry_run=args.dry_run)
    if c == "start":
        return commands.start(ports, store, lane=args.lane, reconcile=args.reconcile, release=args.release, reason=args.reason)
    if c == "bind":
        return commands.bind(ports, store, lane=args.lane, agent=args.agent)
    if c == "checkpoint":
        main = ports.is_main("checkpoint", args.lane)  # the stamp is one-shot: decided once, passed down
        if not main:
            who = ports.holder_caller(args.lane)
            ports.set_caller(who["id"] if who else None)
        return commands.checkpoint(ports, store, lane=args.lane, kind=args.kind, note=args.note, evidence=args.evidence,
                                   key=args.key, main=main)
    if c == "regenerate":
        return commands.regenerate(ports, store, lane=args.lane, version=args.version, reason=args.reason)
    if c == "resolve-ledger":
        return commands.resolve_ledger(ports, store, lane=args.lane, reset=args.reset, rung=args.rung, reason=args.reason,
                                       source=args.source)
    return getattr(commands, c)(ports, store, lane=args.lane)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    ports = RealPorts()
    store = st.Store(_home() / ".agent-harness" / "state" / "lanes")
    try:
        if args.cmd in ("new", "start", "bind", "checkpoint") and not ports.session and not getattr(args, "dry_run", False):
            result = commands.Result(commands.NOT_KNOWN, ["session unknown: set CLAUDE_CODE_SESSION_ID (the session of "
                                                           "the main agent that owns this lane)"])
        else:
            result = run(args, ports, store)
    except (st.StoreError, lanes.LaneRefusal, kit.KitError, manifest.ManifestError) as error:
        result = commands.Result(getattr(error, "exit_code", 3), ["refused: %s" % error])
    except (subprocess.SubprocessError, RuntimeError, OSError, LookupError, ValueError) as error:
        # a real port failed (ticket, git, registry): effects already recorded are kept; the op records make a rerun safe
        result = commands.Result(commands.PARTIAL, ["failed: %s (%s); nothing was guessed, rerun to continue" %
                                                     (type(error).__name__, str(error)[:120])])
    if getattr(args, "json", False):
        print(json.dumps({"code": result.code, "lines": result.lines, "data": result.data}, sort_keys=True, default=str))
    else:
        for line in result.lines:
            print(line)
    return result.code


if __name__ == "__main__":
    sys.exit(main())
