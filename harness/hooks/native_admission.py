"""Validate and preview an inert proposal. No enrollment or grant API exists.

This module does not read an active registry, write policy, create a stamp or
launch an operation. Human/native-policy bootstrap is a separate future gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from native_context import MAX_INPUT, decode_candidate_json
from native_user_source import _label
from redact import find
from safe_input import InputRejected, read_stdin_bounded

FIELDS = {"schema", "state", "generation", "activation_profile", "automatic_native_main",
          "operation_grants", "runtime_observation", "proposed_roles", "user_source_evidence", "bootstrap_status"}


def preview(proposal):
    if not isinstance(proposal, dict) or set(proposal) != FIELDS:
        raise ValueError("unexpected proposal fields")
    if (type(proposal["schema"]) is not int or proposal["schema"] != 1
            or proposal["state"] != "PROPOSED_NOT_ADMITTED" or proposal["generation"] is not None
            or proposal["activation_profile"] != "operator_exact_operation_only"
            or proposal["automatic_native_main"] is not False or proposal["operation_grants"] != []):
        raise ValueError("proposal must be inert")
    observation = proposal["runtime_observation"]
    if not isinstance(observation, dict) or set(observation) - {
            "pid", "parent_pid", "start_local", "disk_identifier", "disk_team_identifier", "running_guest_attestation"}:
        raise ValueError("invalid runtime observation")
    # Diagnostic data is never used to confer identity; retain only bounded
    # primitive fields in the hashed candidate. No paths/registry refs are accepted.
    for key, value in observation.items():
        if key in {"pid", "parent_pid"}:
            if type(value) is not int or not 1 < value < 2 ** 31:
                raise ValueError("invalid runtime observation number")
        elif not isinstance(value, str) or not value or len(value) > 160:
            raise ValueError("invalid runtime observation text")
    roles = proposal["proposed_roles"]
    if not isinstance(roles, list) or not 1 <= len(roles) <= 8:
        raise ValueError("invalid proposed roles")
    seen = set()
    for role in roles:
        if not isinstance(role, dict) or set(role) != {"host", "thread", "role", "admitted"}:
            raise ValueError("invalid proposed role fields")
        key = (_label(role["host"]), _label(role["thread"]))
        if key in seen or role["role"] not in {"orchestrator", "project_owner"} or role["admitted"] is not False:
            raise ValueError("duplicate or admitted role")
        seen.add(key)
    source = proposal["user_source_evidence"]
    if not isinstance(source, dict) or set(source) != {
            "platform", "host", "thread", "turn", "item", "evidence_only", "individual_message_time", "native_human_origin_attestation"}:
        raise ValueError("invalid source evidence fields")
    if (source["platform"] != "codex" or source["evidence_only"] is not True
            or source["individual_message_time"] is not None or source["native_human_origin_attestation"] is not None):
        raise ValueError("native evidence must remain weak")
    for key in ("host", "thread", "turn", "item"):
        _label(source[key])
    status = proposal["bootstrap_status"]
    if not isinstance(status, str) or not status or len(status) > 512:
        raise ValueError("invalid bootstrap status")
    canonical = json.dumps(proposal, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(canonical.encode()) > MAX_INPUT or find(canonical):
        raise ValueError("unsafe proposal content")
    return {"schema": 1, "state": "PREVIEW_ONLY", "candidate_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "active_generation": None, "automatic_native_main": False, "operation_grants": [],
            "proposed_roles": roles, "installed_changes": [], "authority": "none",
            "activation_blockers": ["human_native_policy_approval", "protected_helper_not_implemented",
                                    "authenticated_native_event_adapter_unavailable"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["preview"])
    parser.parse_args()
    try:
        print(json.dumps(preview(decode_candidate_json(read_stdin_bounded(MAX_INPUT))), sort_keys=True))
    except (InputRejected, ValueError, TypeError):
        print("native admission proposal rejected", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
