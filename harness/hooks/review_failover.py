#!/usr/bin/env python3
"""Receipted failover of a peer review to the author's own harness (GoodQA #14833, matrix row P19).

When the cross-harness reviewer (normally Codex) times out or is unavailable again and again on one subject, the review
is stuck: the only other options are splitting the packet or claiming a false author harness. `peer_review.py
--failover same-harness` is the explicit, receipted way out. Nothing here ever runs by itself.

A subject is one repository identity, one reviewed HEAD, one packet SHA-256 and one stage. The failover is allowed only
when at least N prior reviews of that subject (default 2) ended in a reconciled provider TIMEOUT or a provider-unavailable
result of the reviewer the tier table would normally pick, and NO prior review of the subject, by either provider, ended in
material findings or invalid output: those are answers about the work, not about availability. The reviewer rung and effort
never change; only the harness does. Stdlib only; reads the usage store through usage_guard.
"""
from __future__ import annotations

import hashlib
import re

import model_tiers as tiers
from usage_guard import GuardError, file_bytes

MODES = ("same-harness",)
DEFAULT_AFTER = 2
MAX_AFTER = 10
MAX_RUNS = 65536
RUN_ID = re.compile(r"[0-9a-f]{32}")
UNAVAILABLE = {"TRANSIENT_INFRA"}  # peer_review records an unavailable provider CLI under this reason


def _check_need(need) -> int:
    if type(need) is not int or not 1 <= need <= MAX_AFTER:
        raise ValueError("--failover-after must be a whole number from 1 to %d" % MAX_AFTER)
    return need


def _finals(store):
    """Every final receipt in the store as (run_id, record), skipping anything unreadable or malformed."""
    runs = store.root / "runs"
    try:
        names = sorted(path.name for path in runs.iterdir())
    except OSError:
        return
    for number, name in enumerate(names):
        if number >= MAX_RUNS:
            return
        if not RUN_ID.fullmatch(name):
            continue
        try:
            body = file_bytes(runs / name / "final.json")
            record = store.load_ref({"run_id": name, "record": "final", "sha256": hashlib.sha256(body).hexdigest()})
        except (GuardError, OSError, ValueError):
            continue
        yield name, record


def _same_subject(record, repository, head, stage, packet_sha256) -> bool:
    subject, invocation = record.get("subject"), record.get("invocation")
    if not isinstance(subject, dict) or not isinstance(invocation, dict):
        return False
    return (subject.get("repository") == repository and subject.get("head") == head
            and invocation.get("stage") == stage.upper().replace("-", "_")
            and invocation.get("packet_digest") == packet_sha256
            and str(invocation.get("purpose", "")).startswith("peer-review-"))


def _material(record) -> bool:
    review = record.get("review")
    return (record.get("reason") == "CODE_FINDINGS" or record.get("result") == "CHECK_FAILED"
            or (isinstance(review, dict) and review.get("verdict") == "BLOCK"))


def evaluate(store, *, repository, head, stage, packet_sha256, primary_provider, need=DEFAULT_AFTER) -> dict:
    """Whether the history of this subject allows a same-harness failover. Never launches or writes anything."""
    need = _check_need(need)
    qualifying, unreconciled, material, invalid, reasons = [], [], [], [], {}
    for run_id, record in _finals(store):
        if not _same_subject(record, repository, head, stage, packet_sha256):
            continue
        reason = record.get("reason")
        if _material(record):
            material.append(run_id)
        elif reason == "INVALID_OUTPUT":
            invalid.append(run_id)
        elif (record.get("invocation") or {}).get("provider") != primary_provider:
            continue  # the failed reviewer is the one being replaced; other providers' availability is not its history
        elif reason == "TIMEOUT":
            try:
                reconciled = store._reconciliation(store._run_directory(run_id), run_id)
            except (GuardError, OSError, ValueError):
                reconciled = False
            (qualifying if reconciled else unreconciled).append(run_id)
            reasons[run_id] = "TIMEOUT"
        elif reason in UNAVAILABLE:
            qualifying.append(run_id)
            reasons[run_id] = reason
    out = {"ok": False, "need": need, "run_ids": sorted(qualifying),
           "runs": [{"run_id": run, "reason": reasons[run]} for run in sorted(qualifying)], "unreconciled": sorted(unreconciled),
           "material": sorted(material), "invalid": sorted(invalid), "refusal": None, "reason": None}
    if material:
        out["refusal"] = ("failover refused: %d prior review(s) of this subject ended in material findings (%s); "
                          "those are answers about the work, not reviewer unavailability" % (len(material), ", ".join(sorted(material)[:4])))
    elif invalid:
        out["refusal"] = ("failover refused: %d prior review(s) of this subject ended in invalid output (%s); "
                          "fix the packet or the provider call first" % (len(invalid), ", ".join(sorted(invalid)[:4])))
    elif len(qualifying) < need:
        out["refusal"] = ("failover needs %d prior reviews of this subject that ended in a reconciled provider TIMEOUT or a "
                          "provider-unavailable result, found %d" % (need, len(qualifying)))
        if unreconciled:
            out["refusal"] += ("; %d timeout(s) are not reconciled yet (%s): reconcile them with usage_guard.py reconcile first"
                               % (len(unreconciled), ", ".join(sorted(unreconciled)[:4])))
    else:
        out["ok"] = True
        out["reason"] = ("%d prior reviews of this subject ended in a reconciled TIMEOUT or provider-unavailable result "
                         "(threshold %d)" % (len(qualifying), need))
    return out


def failover_selection(policy, author_rung, author_harness, available, normal):
    """(selection, refusal): the same reviewer rung and effort on the author's own harness."""
    if not isinstance(normal, dict) or normal.get("harness") is None or normal.get("rung") is None:
        return None, "failover refused: there is no normal reviewer to replace"
    if author_harness not in ("claude", "openai"):
        return None, "failover refused: it needs a known author harness (--author-harness claude or openai)"
    if normal["harness"] == author_harness:
        return None, ("failover refused: the normal reviewer already runs on the author's harness (%s); "
                      "there is nothing to fail over to" % author_harness)
    if not (available or {}).get(author_harness):
        return None, "failover refused: the author's harness (%s) is not available" % author_harness
    try:
        spec = tiers.spawn_spec(policy, normal["rung"], author_harness)
    except tiers.TierError as error:
        return None, "failover refused: no model for rung %s on %s (%s)" % (normal["rung"], author_harness, error)
    chosen = {**spec, "author_unknown": normal.get("author_unknown", False), "cross_harness": False,
              "why": "%s; failover same-harness: the cross-harness reviewer (%s) failed repeatedly on this subject"
                     % (normal.get("why", ""), normal["harness"])}
    return chosen, None


def receipt_lines(info) -> str:
    """The report header lines that make a failover visible in the receipt."""
    if not info:
        return ""
    reason = re.sub(r"\s+", " ", str(info.get("reason", ""))).strip()[:300]
    detail = info.get("runs")
    if detail:  # each prior run with its final reason, so a reader sees why the provider was judged unavailable
        runs = ", ".join("%s (%s)" % (r["run_id"], "TIMEOUT, reconciled" if r["reason"] == "TIMEOUT" else r["reason"])
                         for r in detail)
    else:
        runs = ",".join(str(run) for run in info.get("run_ids", []))
    return "Failover: %s\nFailover-Reason: %s\nFailover-Prior-Runs: %s\n" % (info.get("mode", "same-harness"), reason, runs)
