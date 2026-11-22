#!/usr/bin/env python3
"""Account-local Codex Desktop PR review receipts for the normal merge gate."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

import git_safety
import spec_flow

PREFIX = "NATIVE_PR_WITNESS_V1 "
ROLES = {"owner": "harness_owner", "acceptance": "harness_reviewer", "adversarial": "harness_red_team"}
OID = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
IDENT = re.compile(spec_flow.UUID.lower())
MAX_FILE = 2_000_000
MAX_COMMITS = 128
MAX_AGE = 3600
CONTEXT_FIELDS = {"version", "repo", "pr", "head", "base", "base_ref", "head_ref", "commits", "packet_sha256", "tests_sha256",
                  "no_ci", "tickets", "evidence_authors"}
MAX_TICKETS = 8
PROOF_FIELDS = {"agent", "started", "ended", "report"}
CONTRIBUTOR_ROLE = "worker"
MAX_CONTRIBUTORS = 8
MAX_CONTRIBUTED_PATHS = 256


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def context_digest(context):
    return digest(canonical(context).encode())


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _identifier(value):
    return _matches(IDENT, value) and value == value.lower()


NATIVE_CALL_LIMIT = 32_000_000
NATIVE_CALL_TAIL = 1_000_000
NATIVE_CALL_FIELDS = {"session", "tool_use_id", "call_id", "transcript", "file", "offset", "sha256", "command_sha256"}
PROVIDER_CALL = re.compile(r"call_[A-Za-z0-9_-]{1,128}")
EXEC_CALL = re.compile(r"exec-" + spec_flow.UUID.lower())
CALL_ITEMS = {"function_call", "custom_tool_call"}
CALL_RESULTS = {"function_call_output", "custom_tool_call_output"}


def _root_rollout(home, uid, session):
    """Look up only the canonical, current Desktop root and its rollout path."""
    import sqlite3
    import native_main

    checked = native_main._read_thread(home, uid, session)
    if checked is None or checked[0] != (session, "vscode", "user", "Codex Desktop", None, None, None, 0):
        raise ValueError("native Desktop root is not available")
    db = home / ".codex/state_5.sqlite"
    before = spec_flow._native_database_binding(home, uid)
    if before != checked[1]:
        raise ValueError("native root database changed")
    deadline = time.monotonic() + 0.20
    connection = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=0.05)
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 100)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        table = connection.execute("PRAGMA main.table_list('threads')").fetchmany(2)
        if len(table) != 1 or table[0][:3] != ("main", "threads", "table"):
            raise ValueError("native root thread table unavailable")
        plain = connection.execute("SELECT count(*) FROM pragma_table_xinfo('threads','main') "
                                   "WHERE name='rollout_path' AND hidden=0").fetchone()
        if plain != (1,):
            raise ValueError("native root rollout column unavailable")
        rows = connection.execute(
            "SELECT CASE WHEN typeof(rollout_path)='text' AND length(CAST(rollout_path AS BLOB))<=1024 "
            "THEN rollout_path END FROM main.threads WHERE id=? AND source='vscode' AND thread_source='user' "
            "AND originator='Codex Desktop' AND archived=0 AND agent_path IS NULL AND agent_role IS NULL "
            "AND attached_thread_parent_id IS NULL LIMIT 2", (session,)).fetchmany(2)
    finally:
        connection.close()
    if (len(rows) != 1 or not isinstance(rows[0][0], str)
            or time.monotonic() > deadline or spec_flow._native_database_binding(home, uid) != before):
        raise ValueError("native root rollout path unavailable")
    path = Path(rows[0][0])
    relative = path.relative_to(home / ".codex")
    if (not re.fullmatch(r"sessions/[0-9]{4}/[0-9]{2}/[0-9]{2}", str(relative.parent))
            or not re.fullmatch(rf"rollout-[0-9T-]+-{re.escape(session)}\.jsonl", path.name)):
        raise ValueError("native root rollout path is not canonical")
    return path


def _direct_provider_command(item):
    """Project commands from one direct shell invocation, never evaluate tool input."""
    kind, name = item.get("type"), item.get("name")
    if kind == "custom_tool_call" and name == "exec":
        source = item.get("input")
        if not isinstance(source, str) or len(source) > 8192:
            return None
        # Require exactly one awaited tools.exec_command call and strict JSON arguments.
        match = re.fullmatch(r"\s*text\(await tools\.exec_command\((\{.*\})\)\);?\s*", source, re.S)
        if not match:
            return None
        blob = match[1]
    elif kind == "function_call" and name in ("Bash", "exec_command"):
        blob = item.get("arguments")
        if not isinstance(blob, str):
            return None
    else:
        return None
    data = spec_flow._native_json(blob, 8192)
    if set(data) - {"cmd", "command", "workdir", "yield_time_ms", "max_output_tokens"}:
        return None
    commands = [data[key] for key in ("cmd", "command") if key in data]
    return commands[0] if len(commands) == 1 and isinstance(commands[0], str) else None


def _root_header(lines, session):
    first = spec_flow._native_json(lines[0], 4_000_000)
    payload = first.get("payload")
    if (first.get("type") != "session_meta" or not isinstance(payload, dict)
            or payload.get("id") != session or payload.get("session_id") != session
            or payload.get("source") != "vscode" or payload.get("originator") != "Codex Desktop"
            or payload.get("thread_source") != "user"
            or any(payload.get(key) is not None for key in ("parent_thread_id", "forked_from_id", "agent_path", "agent_role"))):
        raise ValueError("native rollout header is not the authenticated root")


def _open_provider_call(data, session):
    lines = data.splitlines()
    _root_header(lines, session)
    calls = {}
    for raw in lines[1:]:
        if b'"response_item"' not in raw or not any(label in raw for label in (b'"function_call', b'"custom_tool_call')):
            continue
        entry = spec_flow._native_json(raw, 4_000_000)
        item = entry.get("payload")
        if entry.get("type") != "response_item" or not isinstance(item, dict):
            continue
        kind, call = item.get("type"), item.get("call_id")
        if kind in CALL_ITEMS and _matches(PROVIDER_CALL, call):
            if call in calls:
                raise ValueError("native provider call is duplicated")
            calls[call] = item
        elif kind in CALL_RESULTS and isinstance(call, str):
            calls.pop(call, None)
    if len(calls) != 1:
        raise ValueError("there is no unique open native provider call")
    call, item = next(iter(calls.items()))
    command = _direct_provider_command(item)
    if not command:
        raise ValueError("the open native provider call is not one direct command")
    return call, command


def native_call_binding(payload, command):
    """Prepare a call-liveness binding for an already authenticated Desktop root hook."""
    import pwd
    import sqlite3
    import native_main

    try:
        session = native_main._current_session(payload)
        tool = payload.get("tool_use_id")
        if not _identifier(session) or not _matches(EXEC_CALL, tool) or not isinstance(command, str) or not command:
            return None
        uid = os.getuid()
        home = Path(pwd.getpwuid(uid).pw_dir)
        path = _root_rollout(home, uid, session)
        if payload.get("transcript_path") not in (None, str(path)):
            return None
        file = spec_flow._native_path(path, uid, maximum=NATIVE_CALL_LIMIT)
        data = spec_flow._native_read(path, {"home": home, "uid": uid}, NATIVE_CALL_LIMIT, binding=file)
        if not data.endswith(b"\n"):
            return None
        provider_call, observed = _open_provider_call(data, session)
        if observed != command:
            return None
        return {"session": session, "tool_use_id": tool, "call_id": provider_call, "transcript": str(path),
                "file": list(file), "offset": len(data), "sha256": digest(data),
                "command_sha256": digest(command.encode())}
    except (OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError, sqlite3.Error, spec_flow.SpecError):
        return None


def _terminal_native_event(entry, binding):
    payload = entry.get("payload")
    if not isinstance(payload, dict):
        return True
    if entry.get("type") in ("session_meta", "turn_context"):
        return True
    if entry.get("type") == "response_item":
        kind = payload.get("type")
        return kind in CALL_ITEMS or kind in CALL_RESULTS
    if entry.get("type") == "event_msg":
        kind = payload.get("type")
        item = payload.get("item")
        return (kind in ("turn_aborted", "task_complete", "task_started")
                or (kind == "item_completed" and isinstance(item, dict) and item.get("id") == binding["tool_use_id"]))
    return False


def native_call_still_running(binding, *, match_command=None):
    """Reject spent, redirected, damaged or ambiguous account-local native call bindings."""
    import pwd
    import sqlite3

    try:
        if (not isinstance(binding, dict) or set(binding) != NATIVE_CALL_FIELDS
                or not _identifier(binding["session"]) or not _matches(EXEC_CALL, binding["tool_use_id"])
                or not _matches(PROVIDER_CALL, binding["call_id"]) or not _matches(DIGEST, binding["sha256"])
                or not _matches(DIGEST, binding["command_sha256"])
                or type(binding["offset"]) is not int or not 0 < binding["offset"] <= NATIVE_CALL_LIMIT
                or not isinstance(binding["file"], list) or len(binding["file"]) != 4
                or any(type(field) is not int for field in binding["file"])):
            return False
        uid = os.getuid()
        home = Path(pwd.getpwuid(uid).pw_dir)
        path = _root_rollout(home, uid, binding["session"])
        if str(path) != binding["transcript"]:
            return False
        data = spec_flow._native_read(path, {"home": home, "uid": uid}, NATIVE_CALL_LIMIT, binding=tuple(binding["file"]))
        offset = binding["offset"]
        if (not offset <= len(data) <= offset + NATIVE_CALL_TAIL
                or digest(data[:offset]) != binding["sha256"] or not data.endswith(b"\n")):
            return False
        call, command = _open_provider_call(data[:offset], binding["session"])
        if (call != binding["call_id"] or digest(command.encode()) != binding["command_sha256"]
                or (match_command is not None and not match_command(command))):
            return False
        for raw in data[offset:].splitlines():
            entry = spec_flow._native_json(raw, NATIVE_CALL_TAIL)
            if _terminal_native_event(entry, binding):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError, sqlite3.Error, spec_flow.SpecError):
        return False


def _object(path):
    return spec_flow._native_json(spec_flow.read_regular(Path(path), MAX_FILE), MAX_FILE)


def _git(path, *args):
    code, data = git_safety._bounded_git(Path(path), list(args), git_safety.git_environment(isolated=True),
                                         timeout=15, limit=1_000_000)
    if code:
        raise ValueError("candidate Git metadata is unavailable")
    return data.decode("utf-8", "strict").strip()


def _repo_origin(repo):
    return _git(repo, "config", "--local", "--get", "remote.origin.url")


def _github_origin(repo):
    origin = _repo_origin(repo)
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
                         r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?", origin, flags=re.I)
    if match is None:
        raise ValueError("candidate repository must have a credential-free GitHub origin")
    return match[1].lower()


def github_runner(args, timeout, cwd=None, *, run=None):
    """Pin the native read-only runner to GitHub.com without changing legacy CLI behavior."""
    import merge_gate

    args = list(args)
    if len(args) == 2 and args[0] == "api" and args[1].startswith("repos/"):
        args[1:1] = ["--hostname", "github.com"]
    elif (len(args) >= 5 and args[:2] in (["pr", "view"], ["pr", "checks"])
          and args.count("-R") == 1 and not any(arg.startswith("--repo") for arg in args)):
        index = args.index("-R") + 1
        if index >= len(args):
            raise ValueError("native GitHub PR read has no repository")
        repository = merge_gate.repo_key(args[index])
        if not repository or "/" not in args[index] or args[index].lower() != repository:
            raise ValueError("native GitHub PR read needs a canonical repository")
        args[index] = "github.com/" + repository
    else:
        raise ValueError("unsupported native GitHub read")
    return (run or merge_gate.SubprocessGh())(args, timeout, cwd)


def github_client(deadline, cwd=None):
    import merge_gate

    return merge_gate.Client(github_runner, deadline, cwd)


def _branch_ref(value):
    if not _matches(re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._/-]{0,127}"), value) or value.startswith("-") or ".." in value:
        return False
    return all(part and not part.startswith(".") and not part.endswith((".", ".lock")) for part in value.split("/"))


def require_current_refs(client, repository, base_ref, base, head_ref, head):
    if not _branch_ref(base_ref) or not _branch_ref(head_ref) or base_ref == head_ref:
        raise ValueError("the GitHub base and source refs must be valid and distinct")
    for label, branch, expected in (("base", base_ref, base), ("source", head_ref, head)):
        if not _matches(OID, expected):
            raise ValueError("the reviewed GitHub ref identity is invalid")
        row = client.json(["api", f"repos/{repository}/git/ref/heads/{branch}"], f"the authoritative {label} ref")
        target = row.get("object") if isinstance(row, dict) else None
        if (not isinstance(target, dict) or row.get("ref") != f"refs/heads/{branch}"
                or target.get("type") != "commit" or target.get("sha") != expected):
            raise ValueError(f"the authoritative GitHub {label} ref changed or did not verify")


def _remote(client, repository, pr, head, base):
    import merge_gate

    details, problems = merge_gate.evaluate_pr(client, repository, pr)
    if (merge_gate.repo_key(details["slug"]) != repository or details["number"] != pr or details["head"] != head
            or problems or details.get("unsettled")):
        raise ValueError("current GitHub head or CI is not eligible for independent native review")
    row = client.json(["api", f"repos/{repository}/pulls/{pr}"], "the reviewed base and head")
    if not isinstance(row, dict) or row.get("number") != pr or row.get("state") != "open":
        raise ValueError("the reviewed GitHub PR is no longer open")
    base_branch, head_branch = row.get("base"), row.get("head")
    if (not isinstance(base_branch, dict) or not isinstance(head_branch, dict)
            or base_branch.get("sha") != base or head_branch.get("sha") != head):
        raise ValueError("the GitHub PR base or head changed")
    for branch in (base_branch, head_branch):
        origin = branch.get("repo")
        if not isinstance(origin, dict) or merge_gate.repo_key(origin.get("full_name")) != repository:
            raise ValueError("native review requires base and head in the same GitHub repository")
    base_ref, head_ref = base_branch.get("ref"), head_branch.get("ref")
    if not _branch_ref(base_ref) or not _branch_ref(head_ref) or base_ref == head_ref:
        raise ValueError("the GitHub base and source refs must be valid and distinct")
    no_ci = details.get("no_ci")
    if type(no_ci) is not bool:
        raise ValueError("the GitHub workflow classification is unavailable")
    require_current_refs(client, repository, base_ref, base, head_ref, head)
    return base_ref, head_ref, no_ci


def _is_ancestor(repo, older, newer):
    if not _matches(OID, older) or not _matches(OID, newer):
        return False
    code, _ = git_safety._bounded_git(Path(repo), ["merge-base", "--is-ancestor", older, newer],
                                      git_safety.git_environment(isolated=True), timeout=5, limit=4096)
    return code == 0


def _tracker_claims(repo, repository, commits, head):
    import commit_policy

    policy = commit_policy.load_policy()
    configured = spec_flow.load_spec_policy()
    refs = set()
    for commit in commits:
        body = _git(repo, "show", "-s", "--format=%B", commit)
        found = commit_policy._commit_refs(body, policy)
        if not found or any(system != "goodqa" or not project or type(number) is not int
                            for system, project, number in found):
            raise ValueError("each candidate commit must bind its actual GoodQA ticket")
        refs.update((project, number) for _, project, number in found)
    if not 1 <= len(refs) <= MAX_TICKETS:
        raise ValueError("too many or no verified candidate tickets")
    claims, writers = [], set()
    for project, number in sorted(refs):
        ticket = spec_flow.Session(f"GoodQA {project}#{number}", configured, deadline_seconds=8)
        records, ignored, index = ticket.records()
        spec = ticket.latest_spec(records, index)
        issue = ticket.adapter.issue(ticket.ticket.id)
        if not isinstance(issue, dict) or not isinstance(issue.get("status"), str):
            raise ValueError("the candidate ticket status is unavailable")
        evaluation_issue = dict(issue, _label=ticket.ticket.label)
        result = spec_flow.evaluate(records, index, evaluation_issue, ignored)
        premerge = spec_flow.evaluate(records, index, evaluation_issue, ignored, staged_commit=head,
                                      staged_repo="github.com/" + repository)
        current = [r for r in spec_flow.verified(records, index, "evidence")[0]
                   if r.get("spec_core_sha") == spec["spec_core_sha"]]
        evidence_commits = {c.get("sha") for r in current for c in r.get("commits") or []}
        missing = list(premerge["missing"])
        if head not in evidence_commits:
            missing.append("commits: no current structured evidence names the exact candidate")
        if len(evidence_commits) > MAX_COMMITS:
            missing.append("commits: too many current evidence commits for bounded ancestry verification")
        elif any(not _is_ancestor(repo, sha, head) for sha in evidence_commits):
            missing.append("commits: current evidence includes a commit outside the exact candidate ancestry")
        authors = {r.get("actor") for r in current} | {spec.get("author")}
        writers.update(value.partition(":")[2] for value in authors
                       if isinstance(value, str) and value.startswith("agent:") and _identifier(value.partition(":")[2]))
        gates = [r for r in records if r.get("spec_core_sha") == spec["spec_core_sha"]
                 and r["kind"] in ("click_test", "signoff")]
        attachment_ids = {a.get("id") for r in gates for a in r.get("attachments") or []
                          if isinstance(a, dict) and isinstance(a.get("id"), str)}
        gate_index = {ident: index.get(ident) for ident in attachment_ids}
        claims.append({"ticket": ticket.ticket.label, "state": issue["status"],
                       "spec_core_sha": spec["spec_core_sha"],
                       "review_sha256": digest(canonical(spec.get("reviews") or []).encode()),
                       "evidence_sha256": digest(canonical(current).encode()),
                       "release_records_sha256": digest(canonical([gates, gate_index]).encode()),
                       "missing": result["missing"], "premerge_missing": missing})
    return claims, sorted(writers)


def _validate_context(context):
    import merge_gate

    if (set(context) != CONTEXT_FIELDS or type(context["version"]) is not int or context["version"] != 1
            or not isinstance(context["repo"], str) or merge_gate.repo_key(context["repo"]) != context["repo"]
            or type(context["pr"]) is not int or context["pr"] <= 0
            or not all(_matches(OID, context[k]) for k in ("head", "base")) or context["head"] == context["base"]
            or not all(_branch_ref(context[key]) for key in ("base_ref", "head_ref"))
            or context["base_ref"] == context["head_ref"]
            or not all(_matches(DIGEST, context[k]) for k in ("packet_sha256", "tests_sha256"))
            or type(context["no_ci"]) is not bool or not isinstance(context["tickets"], list)
            or not 1 <= len(context["tickets"]) <= MAX_TICKETS
            or not isinstance(context["evidence_authors"], list)
            or not all(_identifier(agent) for agent in context["evidence_authors"])):
        raise ValueError("review context is invalid")
    for claim in context["tickets"]:
        if (not isinstance(claim, dict)
                or set(claim) != {"ticket", "state", "spec_core_sha", "review_sha256", "evidence_sha256",
                                  "release_records_sha256", "missing", "premerge_missing"}
                or not isinstance(claim["ticket"], str) or not isinstance(claim["state"], str)
                or not all(_matches(DIGEST, claim[k]) for k in ("spec_core_sha", "review_sha256", "evidence_sha256", "release_records_sha256"))
                or any(not isinstance(claim[key], list) or not all(isinstance(x, str) for x in claim[key])
                       for key in ("missing", "premerge_missing"))):
            raise ValueError("candidate ticket claims are invalid")
    commits = context["commits"]
    if (not isinstance(commits, list) or not 1 <= len(commits) <= MAX_COMMITS
            or not all(_matches(OID, sha) for sha in commits) or len(set(commits)) != len(commits)
            or commits[-1] != context["head"]):
        raise ValueError("candidate commit set is invalid")


def build_context(repo, repository, pr, head, base, packet, tests, client):
    import merge_gate

    repository = merge_gate.repo_key(repository)
    if not repository or not _matches(OID, head) or not _matches(OID, base) or type(pr) is not int or pr <= 0:
        raise ValueError("review context is invalid")
    if _github_origin(repo) != repository:
        raise ValueError("candidate repository origin does not match GitHub")
    git_safety.require_safe_source(repo, git_safety.git_environment(isolated=True))
    if _git(repo, "rev-parse", "HEAD") != head or _git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("review needs the exact clean candidate checkout")
    if _git(repo, "rev-parse", "--verify", base + "^{commit}") != base:
        raise ValueError("review base is missing")
    commits = _git(repo, "rev-list", "--reverse", "--topo-order", "--max-count=129", base + ".." + head).splitlines()
    packet_bytes = spec_flow.read_regular(Path(packet), MAX_FILE)
    tests_bytes = spec_flow.read_regular(Path(tests), MAX_FILE)
    if not packet_bytes.strip() or not tests_bytes.strip():
        raise ValueError("review packet and test evidence must both be nonempty")
    base_ref, head_ref, no_ci = _remote(client, repository, pr, head, base)
    if not 1 <= len(commits) <= MAX_COMMITS:
        raise ValueError("candidate commit set is invalid")
    tickets, evidence_authors = _tracker_claims(repo, repository, commits, head)
    context = {"version": 1, "repo": repository, "pr": pr, "head": head, "base": base,
               "base_ref": base_ref, "head_ref": head_ref, "commits": commits, "packet_sha256": digest(packet_bytes), "tests_sha256": digest(tests_bytes), "no_ci": no_ci,
               "tickets": tickets, "evidence_authors": evidence_authors}
    _validate_context(context)
    return context, no_ci


def witness_line(context, role, agent, started, ended, report_bytes):
    _validate_context(context)
    if role not in (*ROLES, "contributor") or not _identifier(agent) or spec_flow._native_stamp(started) > spec_flow._native_stamp(ended):
        raise ValueError("invalid role, identity or review interval")
    return PREFIX + canonical({"agent": agent, "role": role, "context_sha256": context_digest(context),
                               "report_sha256": digest(report_bytes), "started": started, "ended": ended})


def _authors(report, owner, parent, commits):
    """The owner declares authors; the observed Git events prove commit production only."""
    value = spec_flow._native_json(report, MAX_FILE)
    if set(value) != {"owner", "authors"} or value["owner"] != owner or not isinstance(value["authors"], dict):
        raise ValueError("owner declaration is invalid")
    if set(value["authors"]) != set(commits):
        raise ValueError("owner declaration does not cover the complete candidate")
    declared = {}
    for commit, identities in value["authors"].items():
        if (not isinstance(identities, list) or not 1 <= len(identities) <= MAX_CONTRIBUTORS + 2
                or not all(_identifier(agent) for agent in identities)
                or len(set(identities)) != len(identities) or owner not in identities):
            raise ValueError("candidate authors must identify the owner and any distinct contributors")
        for agent in identities:
            if agent not in (owner, parent):
                declared.setdefault(agent, set()).add(commit)
    if len(declared) > MAX_CONTRIBUTORS:
        raise ValueError("too many candidate contributors")
    return declared


def _contribution_path(path):
    if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,1024}", path):
        return False
    parsed = PurePosixPath(path)
    return not parsed.is_absolute() and str(parsed) == path and all(part != ".." for part in parsed.parts) and path != "."


def _changed_paths(repo, commit):
    paths = _git(repo, "diff-tree", "--root", "-m", "--no-commit-id", "--no-renames", "--name-only", "-r", "-z",
                 commit).split("\0")
    return {path for path in paths if path}


def _contributor_report(report, agent, expected_commits, repo, changed_paths):
    claim = spec_flow._native_json(report, MAX_FILE)
    if (set(claim) != {"contributor", "commits"} or claim["contributor"] != agent
            or not isinstance(claim["commits"], dict) or set(claim["commits"]) != expected_commits):
        raise ValueError("contributor commit membership differs from the owner's declaration")
    count = 0
    for commit, paths in claim["commits"].items():
        if (not isinstance(paths, list) or not paths or not all(_contribution_path(path) for path in paths)
                or len(set(paths)) != len(paths)):
            raise ValueError("contributor must identify distinct changed paths")
        count += len(paths)
        if count > MAX_CONTRIBUTED_PATHS:
            raise ValueError("too many contributor paths")
        if commit not in changed_paths:
            changed_paths[commit] = _changed_paths(repo, commit)
        if not set(paths) <= changed_paths[commit]:
            raise ValueError("contribution names a path outside the declared commit's changes")


def _native_command_cwd(value):
    if not isinstance(value, str) or len(value) > 4096:
        return None
    desktop_uri = value.startswith("file:")
    try:
        if desktop_uri:
            uri = urlsplit(value)
            if uri.netloc or uri.query or uri.fragment:
                return None
            path = unquote(uri.path, errors="strict")
        else:
            path = value
        if (not path.startswith("/") or path.startswith("//") or "\\" in path
                or any(ord(char) < 32 or ord(char) == 127 for char in path)):
            return None
        current = Path(path)
        if ".." in current.parts or (desktop_uri and ("%" in path or current.as_uri() != value)):
            return None
        return current
    except ValueError:
        return None


def _literal_git_paths(paths):
    return (1 <= len(paths) <= 128 and len(set(paths)) == len(paths)
            and all(not path.startswith("-") and _contribution_path(path) for path in paths))


def _message_path(word, base):
    if re.fullmatch(r"[A-Za-z0-9_./][A-Za-z0-9_./-]*", word):
        return word
    if base is not None and re.fullmatch(r"\$base/[A-Za-z0-9_./-]+", word):
        return f'"{word}"'
    return None


def _native_commit_message(line, words, base):
    amend = words[2:4] == ["--amend", "-F"]
    message_at = 4 if amend else 3
    if len(words) <= message_at or words[message_at - 1] != "-F":
        return None
    message = _message_path(words[message_at], base)
    scope = words[message_at + 1:]
    if message is None or line != " ".join([*words[:message_at], message, *scope]):
        return None
    if scope and (amend or scope[:2] != ["--only", "--"] or not _literal_git_paths(scope[2:])):
        return None
    return message


def _literal_message_edit(body):
    """Recognize the retained literal message edit without evaluating it."""
    expected = """
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text().replace("", "").replace("", "")
p.write_text(s)
"""
    try:
        tree = ast.parse("\n".join(body))
    except (SyntaxError, ValueError, RecursionError):
        return False
    for index, node in enumerate(ast.walk(tree)):
        if index == 64:
            return False
        if isinstance(node, ast.Constant) and type(node.value) is str:
            node.value = ""
    return ast.dump(tree) == ast.dump(ast.parse(expected))


def _native_message_setup(line, words, lines, base, current, home):
    if len(words) != 4 or words[:2] not in (["cat", ">"], ["python3", "-"]):
        return None
    name = re.fullmatch(r"\$base/(commit-message-[A-Za-z0-9_-]+\.txt)", words[2])
    if not name or base is None or base != current.parent:
        return None
    try:
        relative = base.relative_to(home / ".agent-harness/work")
        if len(relative.parts) < 2 or not _identifier(relative.parts[0]):
            return None
        _, _, _, base_mode = spec_flow._native_path(base, os.getuid(), directory=True)
        _, _, _, file_mode = spec_flow._native_path(base / name[1], os.getuid(), maximum=MAX_FILE)
        if (base_mode | file_mode) & 0o077:
            return None
    except (OSError, ValueError):
        return None
    message = _message_path(words[2], base)
    terminator = re.fullmatch(r"<<([A-Za-z_][A-Za-z0-9_]*)", words[3])
    if message is None or not terminator:
        return None
    delimiter = terminator[1]
    if line != f"{words[0]} {words[1]} {message} <<'{delimiter}'":
        return None
    body = []
    for raw in lines:
        if raw == delimiter:
            return message if words[0] == "cat" or _literal_message_edit(body) else None
        body.append(raw)
    return None


def _native_git_preparation(line, words):
    if line in ("umask 077", "git diff --check"):
        return True
    if words[:2] == ["git", "add"] and line == " ".join(words):
        return _literal_git_paths(words[3:] if words[2:3] == ["--"] else words[2:])
    if re.fullmatch(r'test "\$\(git rev-parse HEAD\)" = [0-9a-f]{40}', line):
        return True
    remote = re.fullmatch(r'test -z "\$\(git ls-remote --heads origin ([A-Za-z0-9._/-]+)\)"', line)
    return bool(remote and _branch_ref(remote[1]))


def _shell_commit_directory(command, cwd, home):
    """Recognize the finite commit/readback command shape without executing any input."""
    if (not isinstance(command, list) or len(command) != 3 or not all(isinstance(word, str) for word in command)
            or command[0] not in ("/bin/bash", "/usr/bin/bash", "/bin/zsh", "/bin/sh")
            or command[1] not in ("-c", "-lc")
            or len(command[2]) > 16_000):
        return None
    current = _native_command_cwd(cwd)
    if current is None:
        return None
    base = None
    changed_dir = False
    prepared_message = None
    directory = None
    readback = False
    lines = iter(command[2].split("\n"))
    if next(lines).strip(" \t") not in ("set -e", "set -eu"):
        return None
    for line in lines:
        stripped = line.strip(" \t")
        if not stripped or stripped.startswith("#"):
            continue
        try:
            words = shlex.split(stripped)
        except ValueError:
            return None
        if not words:
            continue
        if readback:
            if stripped != " ".join(words) or words not in (
                             ["git", "status", "--short"], ["git", "status", "-sb"], ["git", "diff", "--check"],
                             ["git", "diff", "--check", "HEAD^", "HEAD"], ["git", "diff", "--stat", "HEAD^", "HEAD"],
                             ["git", "show", "--check", "--oneline", "HEAD"]):
                return None
            continue
        assignment = re.fullmatch(r"base=(~?/[A-Za-z0-9_./-]+)", stripped)
        change = re.fullmatch(r'cd (?:"\$base(/[A-Za-z0-9_./-]+)"|(/[A-Za-z0-9_./-]+))', stripped)
        if assignment and base is None and not changed_dir and directory is None and prepared_message is None:
            path = assignment[1]
            base = _native_command_cwd(str(home / path[2:]) if path.startswith("~/") else path)
            if base is None:
                return None
        elif change and not changed_dir and directory is None and prepared_message is None:
            relative, absolute = change.groups()
            current = _native_command_cwd(absolute or (str(base) + relative if base is not None else None))
            if current is None:
                return None
            changed_dir = True
        elif words[:2] == ["git", "commit"]:
            message = _native_commit_message(stripped, words, base)
            if directory is not None or message is None or (prepared_message and message != prepared_message):
                return None
            directory = current.resolve()
        elif words == ["git", "rev-parse", "HEAD"]:
            if directory is None or stripped != " ".join(words):
                return None
            readback = True
        elif directory is None and prepared_message is None and _native_git_preparation(stripped, words):
            continue
        elif words[0] in ("cat", "python3") and directory is None and prepared_message is None:
            prepared_message = _native_message_setup(stripped, words, lines, base, current, home)
            if prepared_message is None:
                return None
        else:
            return None
    return directory if readback else None


def _commit_from_event(entry, agent, repo, home, subjects):
    payload = entry.get("payload")
    if (entry.get("type") != "event_msg" or not isinstance(payload, dict)
            or payload.get("type") != "item_completed" or payload.get("thread_id") != agent):
        return None
    item = payload.get("item")
    if (not isinstance(item, dict) or item.get("type") != "CommandExecution"
            or item.get("source") != "unified_exec_startup" or item.get("status") != "completed"
            or type(item.get("exit_code")) is not int or item["exit_code"] != 0):
        return None
    output = item.get("aggregated_output")
    if not isinstance(output, str) or len(output) > 32_768:
        return None
    rows = output.splitlines()
    matches = [sha for sha in subjects if rows.count(sha) == 1
               and any(re.fullmatch(r"\[[A-Za-z0-9_./-]+ " + sha[:7] + r"\] " + re.escape(subjects[sha]), line) for line in rows)]
    if len(matches) != 1:
        return None
    authored_repo = _shell_commit_directory(item.get("command"), item.get("cwd"), home)
    if authored_repo is None:
        return None
    if authored_repo != repo.resolve():
        try:
            # The history may predate this candidate worktree. Separate clones only sharing the URL do not qualify.
            if (_git(authored_repo, "rev-parse", "--show-toplevel") != str(authored_repo)
                    or _git(authored_repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
                    != _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
                    or _github_origin(authored_repo) != _github_origin(repo)):
                return None
        except (OSError, ValueError, subprocess.SubprocessError, spec_flow.SpecError):
            return None
    return matches[0]


def _pure_review(report):
    from peer_review import finding_ids

    body = report.decode("utf-8", "strict").strip()
    if (not body or body.splitlines()[0] != "VERDICT: PASS" or finding_ids(body) != ["UNSPECIFIED"]
            or len(re.findall(r"(?mi)^\s*VERDICT:", body)) != 1 or "TICKETED:" in body.upper()):
        raise ValueError("native reviewer did not record a pure PASS")


def _witness_scope(context_sha):
    def matches(line):
        statement = spec_flow._native_json(line.removeprefix(PREFIX), 4000)
        fields = {"agent", "role", "context_sha256", "report_sha256", "started", "ended"}
        if set(statement) != fields or not _matches(DIGEST, statement["context_sha256"]):
            raise ValueError("native PR witness scope is malformed")
        return statement["context_sha256"] == context_sha
    return matches


def require_premerge(context):
    """Require the same formal acceptance gates for native review and dispatch."""
    _validate_context(context)
    if any(claim["premerge_missing"] for claim in context["tickets"]):
        raise ValueError("current GoodQA pre-merge verification is incomplete")


def verify_bundle(path, expected_context, repo, *, root=None, now=None, expected_digest=None):
    require_premerge(expected_context)
    raw = spec_flow.read_regular(Path(path), MAX_FILE)
    if expected_digest is not None and (not _matches(DIGEST, expected_digest) or digest(raw) != expected_digest):
        raise ValueError("native review bundle digest changed")
    bundle = spec_flow._native_json(raw, MAX_FILE)
    keys = {"root", "context", "proofs"}
    if set(bundle) not in (keys, keys | {"contributors"}) or bundle["context"] != expected_context:
        raise ValueError("native review bundle does not bind the fresh candidate context")
    parent, proofs = bundle["root"], bundle["proofs"]
    contributors = bundle.get("contributors", [])
    if not isinstance(contributors, list) or len(contributors) > MAX_CONTRIBUTORS:
        raise ValueError("contributor proof set is invalid")
    if (not _identifier(parent) or (root is not None and root != parent)
            or not isinstance(proofs, dict) or set(proofs) != set(ROLES)):
        raise ValueError("bundle root or proof set is invalid")
    if any(not isinstance(p, dict) or set(p) != PROOF_FIELDS or not _identifier(p["agent"])
           or not isinstance(p["report"], str) for p in [*proofs.values(), *contributors]):
        raise ValueError("bundle proof inputs are incomplete")
    agents = {p["agent"] for p in [*proofs.values(), *contributors]}
    if len(agents | {parent}) != 4 + len(contributors):
        raise ValueError("owner, main, contributors and the two reviewers must have distinct identities")
    if set(expected_context["evidence_authors"]) & {proofs[name]["agent"] for name in ("acceptance", "adversarial")}:
        raise ValueError("an independent reviewer is a ticket author or evidence producer")
    import pwd
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    main = home / ".agent-harness/codex-wals" / parent / "main.jsonl"
    hashes = {}
    not_after = None
    reviewed_context_sha = context_digest(expected_context)
    witness_scope = _witness_scope(reviewed_context_sha)
    subjects = {sha: _git(repo, "show", "-s", "--format=%s", sha) for sha in expected_context["commits"]}
    supplied_contributors = {p["agent"] for p in contributors}
    declared = {}
    changed_paths = {}
    checks = [(role, proof) for role, proof in proofs.items() if role != "owner"]
    checks = [("owner", proofs["owner"]), *checks, *(("contributor", proof) for proof in contributors)]
    for role, proof in checks:
        report = spec_flow.read_regular(Path(proof["report"]), MAX_FILE)
        if role == "owner":
            declared = _authors(report, proof["agent"], parent, expected_context["commits"])
            if set(declared) != supplied_contributors:
                raise ValueError("the verified contributors must exactly match the author's declaration")
        elif role == "contributor":
            _contributor_report(report, proof["agent"], declared[proof["agent"]], repo, changed_paths)
        else:
            _pure_review(report)
        line = witness_line(expected_context, role, proof["agent"], proof["started"], proof["ended"], report)
        typed_role = CONTRIBUTOR_ROLE if role == "contributor" else ROLES[role]
        identity = spec_flow._native_agent_source(main, proof["agent"], typed_role, purpose="pr-review")
        if identity is None:
            raise ValueError("native reviewer identity not available on this account")
        created = set()

        def observe(entry):
            sha = _commit_from_event(entry, proof["agent"], repo, home, subjects)
            if sha and spec_flow._native_stamp(entry.get("timestamp")) <= spec_flow._native_stamp(proof["ended"]):
                created.add(sha)

        observed = spec_flow._native_authored_witness(identity, proof["agent"], typed_role, PREFIX, line,
                                                      proof["started"], proof["ended"], require_fork_boundary=True,
                                                      observe=observe if role == "owner" else None,
                                                      witness_scope=witness_scope)
        if role == "owner" and created != set(subjects):
            raise ValueError("the owner history does not prove creation of every candidate commit")
        current = time.time() if now is None else now
        began = spec_flow._native_stamp(proof["started"]).timestamp()
        expires = began + MAX_AGE
        if not began <= observed.timestamp() <= current < expires:
            raise ValueError("native PR witness is stale or has a future timestamp")
        not_after = expires if not_after is None else min(not_after, expires)
        hashes[role if role != "contributor" else f"contributor:{proof['agent']}"] = digest(line.encode())
    if not_after is None or (time.time() if now is None else now) >= not_after:
        raise ValueError("native PR witness expired during verification")
    return {"context_sha256": reviewed_context_sha, "proofs": hashes, "not_after": not_after}


def add_context_args(parser):
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--github-repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--tests", required=True, type=Path)


def cli_context(args, client):
    return build_context(args.repo, args.github_repo, args.pr, args.head, args.base, args.packet, args.tests, client)


def main(argv=None):
    import merge_gate

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True)
    add_context_args(actions.add_parser("context", allow_abbrev=False))
    proof = actions.add_parser("verify", allow_abbrev=False)
    add_context_args(proof)
    proof.add_argument("--bundle", required=True, type=Path)
    witness = actions.add_parser("witness", allow_abbrev=False)
    witness.add_argument("--context", required=True, type=Path)
    witness.add_argument("--role", choices=[*ROLES, "contributor"], required=True)
    witness.add_argument("--agent", required=True)
    witness.add_argument("--started", required=True)
    witness.add_argument("--ended", required=True)
    witness.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "witness":
            line = witness_line(_object(args.context), args.role, args.agent, args.started, args.ended,
                                spec_flow.read_regular(args.report, MAX_FILE))
            print(line)
        else:
            client = github_client(time.monotonic() + 20)
            context, _ = cli_context(args, client)
            print(canonical(context if args.action == "context" else verify_bundle(args.bundle, context, args.repo)))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, StopIteration, subprocess.SubprocessError,
            spec_flow.SpecError, merge_gate.GateError):
        print("native PR review refused: context, remote state or independent witness did not verify", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
