"""Lane manifest ``lane.manifest/1``: closed field classes, numbered revisions never edited in place (S1).

Field classes: ids, paths, digests, numbers, timestamps and closed enumerations. No free text from tickets, no secret,
no credential path, no private hostname (fleet aliases only). An unknown field or a higher schema version parks the
lane as "newer schema, unreadable"; nothing is guessed (NEG-5).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import store as st

SCHEMA = "lane.manifest/1"
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
TICKET = re.compile(r"^GoodQA [a-z0-9][a-z0-9-]{0,60}#[0-9]{1,9}$")
KEY = re.compile(r"^GoodQA [a-z0-9][a-z0-9-]{0,60}#[0-9]{1,9}\|[a-z0-9][a-z0-9./:_-]{0,200}$")
PATH = re.compile(r"^[A-Za-z0-9._/~+:@%=,-]{1,300}$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
KIT_VERSION = re.compile(r"^v[0-9]{1,3}$")
STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
STREAM = re.compile(r"^stream-[0-9a-f]{12}$")
LIVE_VALUE = re.compile(r"^[A-Za-z0-9:/._,-]{1,300}$")
SOURCE = re.compile(r"^(user|answer|ticket|file|wal|queue):[A-Za-z0-9:/#._@-]{1,200}$")
PROFILES = ("python-hooks", "generic")
DOMAINS = ("auth", "delete", "devices", "money", "release", "blockchain")
REPO_KINDS = ("remote", "remote-origin", "local")
REASONS = ("initial", "canary", "rollback", "regenerate")
LIVE_KINDS = ("web-origin", "install-hosts")
FIELDS = ("schema", "revision", "revision_reason", "lane_id", "key", "ticket", "repo_identity", "repo_kind",
          "host_alias", "branch", "worktree", "profile", "domains", "session", "stream_key", "predecessor",
          "live_target", "generation", "kit_version", "kit_digests", "template_digest", "policy_digests",
          "spec_path", "scope_paths", "brief_version", "budget", "created_at")


class ManifestError(ValueError):
    pass


class NewerSchema(ManifestError):
    pass


def _need(cond, field):
    if not cond:
        raise ManifestError("manifest field %r is not in its allowed class" % field)


def _int(value, lo=0, hi=10 ** 9):
    return isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi


def validate(m: dict) -> dict:
    if not isinstance(m, dict):
        raise ManifestError("manifest must be an object")
    schema = m.get("schema")
    if isinstance(schema, str) and schema.startswith("lane.manifest/") and schema != SCHEMA:
        raise NewerSchema("newer schema, unreadable")
    if set(m) - set(FIELDS):
        raise NewerSchema("newer schema, unreadable (unknown field)")
    missing = [f for f in FIELDS if f not in m]
    if missing:
        raise ManifestError("manifest lacks fields: %s" % ", ".join(missing))
    _need(schema == SCHEMA, "schema")
    _need(_int(m["revision"], 1, 9999), "revision")
    _need(m["revision_reason"] in REASONS, "revision_reason")
    _need(isinstance(m["lane_id"], str) and ID.match(m["lane_id"]), "lane_id")
    _need(isinstance(m["key"], str) and KEY.match(m["key"]), "key")
    _need(isinstance(m["ticket"], str) and TICKET.match(m["ticket"]), "ticket")
    _need(isinstance(m["repo_identity"], str) and re.match(r"^[a-z0-9][a-z0-9./:_-]{0,200}$", m["repo_identity"]),
          "repo_identity")
    _need(m["repo_kind"] in REPO_KINDS, "repo_kind")
    _need(isinstance(m["host_alias"], str) and ID.match(m["host_alias"]), "host_alias")
    _need(isinstance(m["branch"], str) and BRANCH.match(m["branch"]), "branch")
    _need(isinstance(m["worktree"], str) and PATH.match(m["worktree"]), "worktree")
    _need(m["profile"] in PROFILES, "profile")
    _need(isinstance(m["domains"], list) and all(d in DOMAINS for d in m["domains"]), "domains")
    _need(isinstance(m["session"], str) and ID.match(m["session"]), "session")
    _need(isinstance(m["stream_key"], str) and STREAM.match(m["stream_key"]), "stream_key")
    _need(m["predecessor"] is None or (isinstance(m["predecessor"], str) and ID.match(m["predecessor"])), "predecessor")
    live = m["live_target"]
    _need(live is None or (isinstance(live, dict) and set(live) == {"kind", "value", "source"}
                           and live["kind"] in LIVE_KINDS and isinstance(live["value"], str)
                           and LIVE_VALUE.match(live["value"]) and isinstance(live["source"], str)
                           and SOURCE.match(live["source"])), "live_target")
    _need(_int(m["generation"], 0, 9999), "generation")
    _need(isinstance(m["kit_version"], str) and KIT_VERSION.match(m["kit_version"]), "kit_version")
    for name, pattern in (("kit_digests", PATH), ("policy_digests", PATH)):
        value = m[name]
        _need(isinstance(value, dict) and len(value) <= 500 and all(
            isinstance(k, str) and pattern.match(k) and isinstance(v, str) and DIGEST.match(v)
            for k, v in value.items()), name)
    _need(isinstance(m["template_digest"], str) and DIGEST.match(m["template_digest"]), "template_digest")
    _need(m["spec_path"] is None or (isinstance(m["spec_path"], str) and PATH.match(m["spec_path"])), "spec_path")
    _need(isinstance(m["scope_paths"], list) and all(isinstance(p, str) and PATH.match(p) for p in m["scope_paths"]),
          "scope_paths")
    _need(_int(m["brief_version"], 0, 999), "brief_version")
    b = m["budget"]
    _need(isinstance(b, dict) and set(b) == {"soft", "hard"} and _int(b["soft"]) and _int(b["hard"]), "budget")
    _need(isinstance(m["created_at"], str) and STAMP.match(m["created_at"]), "created_at")
    return m


def new_manifest(*, lane_id, key, ticket, repo_identity, repo_kind, host_alias, branch, worktree, profile, domains,
                 session, stream_key, kit_version, kit_digests, template_digest, policy_digests, created_at,
                 live_target=None, spec_path=None, scope_paths=(), predecessor=None, reason="initial") -> dict:
    m = {"schema": SCHEMA, "revision": 1, "revision_reason": reason, "lane_id": lane_id, "key": key, "ticket": ticket,
         "repo_identity": repo_identity, "repo_kind": repo_kind, "host_alias": host_alias, "branch": branch,
         "worktree": worktree, "profile": profile, "domains": list(domains), "session": session,
         "stream_key": stream_key, "predecessor": predecessor, "live_target": live_target, "generation": 0,
         "kit_version": kit_version, "kit_digests": dict(kit_digests), "template_digest": template_digest,
         "policy_digests": dict(policy_digests), "spec_path": spec_path, "scope_paths": list(scope_paths),
         "brief_version": 1, "budget": {"soft": 300, "hard": 600}, "created_at": created_at}
    return m


def _revisions(lane_dir):
    found = []
    for p in Path(lane_dir).glob("manifest.r[0-9][0-9][0-9][0-9].json"):
        found.append((int(p.name[10:14]), p))
    return sorted(found)


def write_revision(lane_dir, m: dict, number=None) -> int:
    """Write the next numbered revision; an existing revision is never replaced."""
    lane_dir = Path(lane_dir)
    revs = _revisions(lane_dir)
    number = number if number is not None else (revs[-1][0] + 1 if revs else 1)
    m = dict(m, revision=number)
    validate(m)
    final = lane_dir / ("manifest.r%04d.json" % number)
    tmp = lane_dir / (".manifest.%d.tmp" % os.getpid())
    st.atomic_write(tmp, (st.canonical_json(m) + "\n").encode())
    try:
        os.link(str(tmp), str(final))  # atomic create-if-absent
    finally:
        os.unlink(str(tmp))
    return number


def read_current(lane_dir) -> dict:
    """The highest numbered revision, validated. Raises NewerSchema or ManifestError; never guesses."""
    revs = _revisions(lane_dir)
    if not revs:
        raise ManifestError("lane has no manifest")
    try:
        value = json.loads(st.read_input(revs[-1][1]).decode())
    except ValueError:
        raise ManifestError("manifest is not valid JSON; preserved")
    return validate(value)
