"""Lane creation, kit regeneration (canary and rollback) and verify over the store (S1).

``create_lane`` is atomic from the caller's view: the kit is rendered in memory, then the lane directory is built under
a temporary name inside the store root, then renamed into place, then the index claim is written last. A failure
removes only that temporary directory (resolved inside the store root). ``verify_lane`` is read-only.

Disclosed: a kit regeneration is recorded as a numbered manifest revision (reason ``canary`` or ``rollback``); the
journal's closed kind set (design D-3) has no kind for it, so the journal records only the creation override.
"""
from __future__ import annotations

import difflib
import hashlib
import os
import random
import shutil
from pathlib import Path

from . import identity as ident
from . import kit
from . import manifest as mf
from . import store as st

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class LaneRefusal(Exception):
    exit_code = 3


class HeldTarget(LaneRefusal):
    def __init__(self, rule):
        super().__init__("refused: held target (rule %s); nothing written. Hand to main or the ticket." % rule)
        self.rule = rule


def new_lane_id(now_ms=None, rng=random.SystemRandom()) -> str:
    """``lane_<ULID>``: 48-bit time and 80 random bits in Crockford base32."""
    import time
    t = int(now_ms if now_ms is not None else time.time() * 1000) & ((1 << 48) - 1)
    value = (t << 80) | rng.getrandbits(80)
    chars = []
    for _ in range(26):
        chars.append(CROCKFORD[value & 31])
        value >>= 5
    return "lane_" + "".join(reversed(chars))


def _inputs(m: dict, version: str) -> dict:
    return {"lane_id": m["lane_id"], "ticket": m["ticket"], "stream_key": m["stream_key"], "branch": m["branch"],
            "kit_version": version, "repo_identity": m["repo_identity"]}


def _policy_digests(policy_files):
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted((policy_files or {}).items())}


def _inside(root: Path, path: Path) -> bool:
    return os.path.realpath(str(path)).startswith(os.path.realpath(str(root)) + os.sep)


def _cleanup(root: Path, path: Path) -> None:
    if path.exists() and _inside(root, path):
        shutil.rmtree(str(path), ignore_errors=True)


def create_lane(store: st.Store, *, ticket, repo, profile, host_alias, branch, worktree, session, now, new_id,
                templates_root, env, source, dry_run=False, policy_files=None, default_version="v1",
                live_target=None) -> dict:
    try:
        ticket_ref = ident.normalise_ticket(ticket)
    except ident.IdentityError as error:
        raise LaneRefusal(str(error))
    slug = ticket_ref.split()[1].split("#")[0]
    rule = ident.held_rule(identity=slug)
    if rule:
        raise HeldTarget(rule)
    try:
        rule = ident.held_rule(path=str(repo)) if os.path.isdir(str(repo)) else ident.held_rule(identity=str(repo))
        if rule:
            raise HeldTarget(rule)
        identity, kind = ident.canonical_repo(str(repo))
    except ident.IdentityError as error:
        raise LaneRefusal(str(error))
    rule = ident.held_rule(identity=identity)
    if rule:
        raise HeldTarget(rule)
    key = ident.lane_key(ticket_ref, identity)
    stream = ident.stream_key(key)
    version, overridden = kit.select_version(ticket_ref, {"default": default_version}, env)

    existing = None
    if store.root.exists():
        existing = store.load_index()["lanes"].get(key)
    if dry_run and not existing and not store.root.exists():
        return {"created": False, "dry_run": True, "lane_id": "(new)", "key": key, "stream_key": stream,
                "kit_version": version, "plan": ["render kit %s" % version, "write manifest r0001 and journal created",
                                                 "claim key in index"]}
    if dry_run:
        return {"created": False, "dry_run": True, "lane_id": existing or "(new)", "key": key, "stream_key": stream,
                "kit_version": version, "plan": ["lane exists" if existing else "render kit %s" % version]}

    problems = kit.lint_version(version, templates_root)
    if problems:
        raise LaneRefusal("kit version %s refused by lint: %s" % (version, "; ".join(problems[:3])))
    with store.lock():
        existing = store.load_index()["lanes"].get(key)
        if existing:
            return {"created": False, "lane_id": existing, "key": key, "stream_key": stream}
        lane_id = new_id()
        m = mf.new_manifest(lane_id=lane_id, key=key, ticket=ticket_ref, repo_identity=identity, repo_kind=kind,
                            host_alias=host_alias, branch=branch, worktree=worktree, profile=profile, domains=[],
                            session=session, stream_key=stream, kit_version=version, kit_digests={},
                            template_digest=kit.template_digest(version, templates_root),
                            policy_digests=_policy_digests(policy_files), created_at=now, live_target=live_target)
        files = kit.render_files(version, _inputs(m, version), templates_root)  # raises KitError, nothing created
        m["kit_digests"] = kit.digests(files)
        tmp = store.root / (".tmp-" + lane_id)
        tmp.mkdir(mode=0o700)
        try:
            (tmp / "kit").mkdir(mode=0o700)
            for name, data in files.items():
                target = tmp / "kit" / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                st.atomic_write(target, data)
            mf.write_revision(tmp, m)
            m1 = (tmp / "manifest.r0001.json").read_bytes()
            store.journal_append(tmp, kind="created", lane=lane_id, generation=0,
                                 writer={"id": "main", "session": session}, idem="created", source=source, ts=now,
                                 data={"kit_version": version, "kit_override": overridden, "host_alias": host_alias,
                                       "manifest_sha256": hashlib.sha256(m1).hexdigest()})
            os.rename(str(tmp), str(store.lane_dir(lane_id)))
            store.claim_key(key, lane_id)
        except BaseException:
            _cleanup(store.root, tmp)
            raise
        return {"created": True, "lane_id": lane_id, "key": key, "stream_key": stream, "kit_version": version}


def regenerate_kit(store: st.Store, lane_id, *, version, now, templates_root, reason) -> dict:
    """Canary a kit version on one lane, or roll it back. Rollback is never blocked by lint of any version."""
    if reason not in ("canary", "rollback", "regenerate"):
        raise LaneRefusal("unknown regeneration reason")
    if reason != "rollback":
        problems = kit.lint_version(version, templates_root)
        if problems:
            raise LaneRefusal("kit version %s refused by lint: %s" % (version, "; ".join(problems[:3])))
    lane_dir = store.lane_dir(lane_id)
    with store.lock():
        try:
            m = mf.read_current(lane_dir)
        except mf.ManifestError as error:
            raise LaneRefusal(str(error))
        files = kit.render_files(version, _inputs(m, version), templates_root)
        new_dir = lane_dir / (".kit-new-%d" % os.getpid())
        old_dir = lane_dir / (".kit-old-%d" % os.getpid())
        for leftover in (new_dir, old_dir):
            _cleanup(store.root, leftover)
        new_dir.mkdir(mode=0o700)
        try:
            for name, data in files.items():
                target = new_dir / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                st.atomic_write(target, data)
            os.rename(str(lane_dir / "kit"), str(old_dir))
            os.rename(str(new_dir), str(lane_dir / "kit"))
        except BaseException:
            if old_dir.exists() and not (lane_dir / "kit").exists():
                os.rename(str(old_dir), str(lane_dir / "kit"))
            _cleanup(store.root, new_dir)
            raise
        _cleanup(store.root, old_dir)
        m2 = dict(m, kit_version=version, kit_digests=kit.digests(files),
                  template_digest=kit.template_digest(version, templates_root), revision_reason=reason)
        number = mf.write_revision(lane_dir, m2)
        return {"lane_id": lane_id, "kit_version": version, "revision": number}


def _tree(path: Path) -> dict:
    out = {}
    if path.is_dir():
        for p in sorted(path.rglob("*")):
            if p.is_file() and not p.is_symlink():
                out[str(p.relative_to(path))] = p.read_bytes()
    return out


def verify_lane(store: st.Store, lane_id, *, templates_root, default_version, policy_files=None) -> dict:
    """Read-only drift report. Never writes."""
    lane_dir = store.lane_dir(lane_id)
    report = {"lane_id": lane_id, "state": "ok", "problems": [], "drift_diff": []}
    try:
        m = mf.read_current(lane_dir)
    except mf.NewerSchema:
        report["state"] = "newer schema, unreadable"
        return report
    except (mf.ManifestError, st.StoreError) as error:
        report.update(state="damaged", problems=["manifest: %s" % error])
        return report
    try:
        ok, seq, reason = store.verify_journal(lane_dir)
    except st.StoreError as error:
        ok, seq, reason = False, None, str(error)
    if not ok:
        report["problems"].append("journal: %s" % reason)
    else:
        try:
            first = store._rows(lane_dir)[0]
            r1 = st.read_input(lane_dir / "manifest.r0001.json")
            if first["data"].get("manifest_sha256") != hashlib.sha256(r1).hexdigest():
                report["problems"].append("manifest r0001 was edited in place")
        except (IndexError, KeyError, st.StoreError):
            report["problems"].append("manifest r0001 cannot be compared with the journal")
    on_disk = _tree(lane_dir / "kit")
    recorded = m["kit_digests"]
    for name, digest in recorded.items():
        if name not in on_disk:
            report["problems"].append("kit/%s is missing" % name)
        elif hashlib.sha256(on_disk[name]).hexdigest() != digest:
            report["problems"].append("kit/%s differs from the recorded digest" % name)
    for name in on_disk:
        if name not in recorded:
            report["problems"].append("kit/%s is not in the manifest" % name)
    for name, digest in _policy_digests(policy_files).items():
        if m["policy_digests"].get(name) != digest:
            report["problems"].append("policy file %s changed since generation" % name)
    try:
        if m["kit_version"] != default_version:
            fresh = kit.render_files(default_version, _inputs(m, default_version), templates_root)
            for name in sorted(set(fresh) | set(on_disk)):
                a = on_disk.get(name, b"").decode(errors="replace").splitlines()
                b = fresh.get(name, b"").decode(errors="replace").splitlines()
                report["drift_diff"].extend(difflib.unified_diff(
                    a, b, "kit/%s (%s)" % (name, m["kit_version"]), "kit/%s (%s)" % (name, default_version),
                    lineterm=""))
        elif kit.template_digest(m["kit_version"], templates_root) != m["template_digest"]:
            report["problems"].append("template %s changed since generation (drift)" % m["kit_version"])
    except kit.KitError as error:
        report["problems"].append("kit: %s" % error)
    if report["problems"]:
        report["state"] = "drift"
    return report
