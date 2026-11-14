"""Lane creation, kit regeneration (canary and rollback), crash reconciliation and verify over the store (S1).

Crash contract (a process may be killed between any two steps; no exception cleanup runs):

* create: the kit is rendered in memory, the lane directory is built under ``.tmp-<lane id>`` inside the store root
  (manifest r0001, journal ``created``), renamed into place, and only then claimed in the index. The rename is the
  commit point; the index claim is derived from it. ``reconcile`` (run under the lock at the start of every create)
  removes uncommitted ``.tmp-*`` directories and claims any committed lane whose key is not yet indexed, so a retry
  yields one lane per key.
* regenerate: the new kit is staged in ``.kit-new``, the old kit is kept as ``.kit-old`` until the new manifest
  revision (the commit point) and its head are written; ``reconcile_lane`` restores a missing kit from ``.kit-old``,
  discards a stale ``.kit-new`` and repairs a head left one revision behind. A retry of the same regeneration
  finishes the job; the kit and manifest are never left describing different bytes after a retry.

Disclosed: a kit regeneration is recorded as a numbered manifest revision (reason ``canary`` or ``rollback``); the
journal's closed kind set (design D-3) has no kind for it, so the journal records only the creation override. Every
revision is chained by digest and anchored by ``manifest.head`` (accidental-damage protection, same-user limit).
"""
from __future__ import annotations

import difflib
import hashlib
import os
import random
import shutil
import stat
import time
from pathlib import Path

from . import identity as ident
from . import kit
from . import manifest as mf
from . import store as st

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _crash_hook(point: str) -> None:  # tests replace this to terminate the process at a publication boundary
    return None


class LaneRefusal(Exception):
    exit_code = 3


class HeldTarget(LaneRefusal):
    def __init__(self, rule):
        super().__init__("refused: held target (rule %s); nothing written. Hand to main or the ticket." % rule)
        self.rule = rule


def new_lane_id(now_ms=None, rng=random.SystemRandom()) -> str:
    """``lane_<ULID>``: 48-bit time and 80 random bits in Crockford base32."""
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
    """Remove a directory this module made, only when it is a real directory inside the store root."""
    if os.path.lexists(str(path)) and not os.path.islink(str(path)) and _inside(root, path):
        shutil.rmtree(str(path), ignore_errors=True)


def reconcile(store: st.Store) -> list:
    """Under the lock: complete or discard interrupted creations. Returns what it did."""
    done = []
    if not store.root.exists():
        return done
    with store.lock():
        index = store.load_index()["lanes"]
        indexed = set(index.values())
        for entry in sorted(store.root.iterdir()):
            if entry.name.startswith(".tmp-"):
                _cleanup(store.root, entry)
                done.append("removed uncommitted " + entry.name)
            elif entry.name.startswith("lane_") and entry.is_dir() and not entry.is_symlink() \
                    and entry.name not in indexed:
                try:
                    key = mf.read_current(entry)["key"]
                except (mf.ManifestError, st.StoreError):
                    continue  # damaged: left in place and reported by verify, never guessed
                if store.claim_key(key, entry.name) == entry.name:
                    done.append("claimed " + entry.name)
    return done


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

    if dry_run:  # reads only: not even the store root is created
        existing = store.load_index()["lanes"].get(key) if store.root.exists() else None
        return {"created": False, "dry_run": True, "lane_id": existing or "(new)", "key": key, "stream_key": stream,
                "kit_version": version,
                "plan": ["lane exists" if existing else "render kit %s" % version]
                + ([] if existing else ["write manifest r0001 and journal created", "claim key in index"])}

    problems = kit.lint_version(version, templates_root)
    if problems:
        raise LaneRefusal("kit version %s refused by lint: %s" % (version, "; ".join(problems[:3])))
    store.ensure_root()
    reconcile(store)
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
            _crash_hook("create:after_render")
            mf.write_revision(tmp, m)
            m1 = (tmp / "manifest.r0001.json").read_bytes()
            store.journal_append(tmp, kind="created", lane=lane_id, generation=0,
                                 writer={"id": "main", "session": session}, idem="created", source=source, ts=now,
                                 data={"kit_version": version, "kit_override": overridden, "host_alias": host_alias,
                                       "manifest_sha256": hashlib.sha256(m1).hexdigest()})
            _crash_hook("create:after_journal")
            os.rename(str(tmp), str(store.lane_dir(lane_id)))  # commit point
            _crash_hook("create:after_rename")
            store.claim_key(key, lane_id)
            _crash_hook("create:after_claim")
        except BaseException:
            _cleanup(store.root, tmp)
            raise
        return {"created": True, "lane_id": lane_id, "key": key, "stream_key": stream, "kit_version": version}


def reconcile_lane(store: st.Store, lane_id) -> list:
    """Under the lock: finish or discard an interrupted regeneration of one lane.

    Commitment is decided from the validated manifest and the kit digests, never from which paths exist: the prior
    kit (``.kit-old``) is dropped only once the kit on disk matches the manifest; if the replacement did not commit,
    the prior kit is restored.
    """
    lane_dir = store.lane_dir(lane_id)
    done = []
    with store.lock():
        new_dir, old_dir, kit_dir = lane_dir / ".kit-new", lane_dir / ".kit-old", lane_dir / "kit"
        for tmp in sorted(lane_dir.glob(".manifest.*.tmp")):
            if not tmp.is_symlink():
                tmp.unlink()
                done.append("removed " + tmp.name)
        if not os.path.lexists(str(kit_dir)) and old_dir.is_dir() and not old_dir.is_symlink():
            os.rename(str(old_dir), str(kit_dir))
            done.append("restored kit from .kit-old")
        if os.path.lexists(str(new_dir)):
            _cleanup(store.root, new_dir)
            done.append("discarded stale .kit-new")
        if mf.repair_head(lane_dir):
            done.append("repaired manifest.head")
        if os.path.lexists(str(old_dir)):
            try:
                recorded = mf.read_current(lane_dir)["kit_digests"]
            except (mf.ManifestError, st.StoreError):
                return done  # cannot decide: keep both, report through verify
            current, problems = _tree(kit_dir)
            if not problems and kit.digests(current) == recorded:
                _cleanup(store.root, old_dir)  # committed: the manifest describes the kit on disk
                done.append("removed committed .kit-old")
            else:
                old, old_problems = _tree(old_dir)
                if not old_problems and kit.digests(old) == recorded:
                    _cleanup(store.root, kit_dir)  # uncommitted replacement: restore the prior kit
                    os.rename(str(old_dir), str(kit_dir))
                    done.append("restored prior kit; replacement had not committed")
    return done


def regenerate_kit(store: st.Store, lane_id, *, version, now, templates_root, reason) -> dict:
    """Canary a kit version on one lane, or roll it back. Rollback is never blocked by lint of any version."""
    if reason not in ("canary", "rollback", "regenerate"):
        raise LaneRefusal("unknown regeneration reason")
    lane_dir = store.lane_dir(lane_id)
    reconcile_lane(store, lane_id)  # first: a refused retry must still leave a consistent lane
    if reason != "rollback":
        problems = kit.lint_version(version, templates_root)
        if problems:
            raise LaneRefusal("kit version %s refused by lint: %s" % (version, "; ".join(problems[:3])))
    with store.lock():
        reconcile_lane(store, lane_id)
        try:
            m = mf.read_current(lane_dir)
        except mf.ManifestError as error:
            raise LaneRefusal(str(error))
        files = kit.render_files(version, _inputs(m, version), templates_root)
        new_digests = kit.digests(files)
        on_disk, tree_problems = _tree(lane_dir / "kit")
        if tree_problems:
            raise LaneRefusal("kit directory is unsafe: %s" % tree_problems[0])
        if kit.digests(on_disk) != new_digests:
            new_dir, old_dir = lane_dir / ".kit-new", lane_dir / ".kit-old"
            new_dir.mkdir(mode=0o700)
            for name, data in files.items():
                target = new_dir / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                st.atomic_write(target, data)
            _crash_hook("regen:after_staged")
            os.rename(str(lane_dir / "kit"), str(old_dir))  # prior kit retained until the manifest commits
            _crash_hook("regen:after_old_moved")
            os.rename(str(new_dir), str(lane_dir / "kit"))
            _crash_hook("regen:after_swapped")
        if m["kit_version"] == version and m["kit_digests"] == new_digests:
            number = m["revision"]  # an earlier attempt already committed the manifest
        else:
            m2 = dict(m, kit_version=version, kit_digests=new_digests,
                      template_digest=kit.template_digest(version, templates_root), revision_reason=reason)
            number = mf.write_revision(lane_dir, m2)  # commit point
        _crash_hook("regen:after_manifest")
        _cleanup(store.root, lane_dir / ".kit-old")
        return {"lane_id": lane_id, "kit_version": version, "revision": number}


def _tree(path: Path):
    """``(files, problems)`` of a kit directory using the bounded no-follow reader; never raises on unsafe entries."""
    files, problems = {}, []
    path = Path(path)
    try:
        info = os.lstat(str(path))
    except OSError:
        return files, ["kit directory is missing"]
    if not stat.S_ISDIR(info.st_mode):
        return files, ["kit directory is a symlink or not a directory"]
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        for entry in sorted(os.scandir(str(current)), key=lambda e: e.name):
            rel = str(Path(entry.path).relative_to(path))
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                stack.append(Path(entry.path))
            elif stat.S_ISREG(mode):
                try:
                    data = st.read_input(entry.path)
                except st.StoreError as error:
                    problems.append("kit/%s refused: %s" % (rel, error))
                    continue
                total += len(data)
                if total > st.MAX_LANE_DIR:
                    problems.append("kit exceeds the %d byte lane limit" % st.MAX_LANE_DIR)
                    return files, problems
                files[rel] = data
            else:
                problems.append("kit/%s is a symlink or special file" % rel)
    return files, problems


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
    report["problems"].extend(mf.verify_chain(lane_dir))
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
    on_disk, tree_problems = _tree(lane_dir / "kit")
    report["problems"].extend(tree_problems)
    recorded = m["kit_digests"]
    for name, digest in recorded.items():
        if name not in on_disk:
            report["problems"].append("kit/%s is missing" % name)
        elif hashlib.sha256(on_disk[name]).hexdigest() != digest:
            report["problems"].append("kit/%s differs from the recorded digest" % name)
    for name in on_disk:
        if name not in recorded:
            report["problems"].append("kit/%s is not in the manifest" % name)
    for name in (".kit-new", ".kit-old"):
        if os.path.lexists(str(lane_dir / name)):
            report["problems"].append("interrupted kit regeneration (%s present); rerun the regeneration" % name)
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
