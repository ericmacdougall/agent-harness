#!/usr/bin/env python3
"""Account-local Codex Desktop PR review receipts for the normal merge gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

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
CONTEXT_FIELDS = {"version", "repo", "pr", "head", "base", "base_ref", "commits", "packet_sha256", "tests_sha256",
                  "no_ci", "tickets", "evidence_authors"}
MAX_TICKETS = 8
PROOF_FIELDS = {"agent", "started", "ended", "report"}


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


def _remote(client, repository, pr, head, base):
    import merge_gate

    details, problems = merge_gate.evaluate_pr(client, repository, pr)
    if (merge_gate.repo_key(details["slug"]) != repository or details["number"] != pr or details["head"] != head
            or problems or details.get("unsettled")):
        raise ValueError("current GitHub head or CI is not eligible for independent native review")
    row = client.json(["api", f"repos/{repository}/pulls/{pr}"], "the reviewed base and head")
    if (not isinstance(row, dict) or row.get("number") != pr or row.get("state") != "open"
            or (row.get("base") or {}).get("sha") != base or (row.get("head") or {}).get("sha") != head):
        raise ValueError("the GitHub PR base or head changed")
    ref = (row.get("base") or {}).get("ref")
    if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", ref) or ref.startswith("-"):
        raise ValueError("the GitHub base branch is invalid")
    no_ci = details.get("no_ci")
    if type(no_ci) is not bool:
        raise ValueError("the GitHub workflow classification is unavailable")
    return ref, no_ci


def _tracker_claims(repo, commits):
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
        result = spec_flow.evaluate(records, index, dict(issue, _label=ticket.ticket.label), ignored)
        current = [r for r in spec_flow.verified(records, index, "evidence")[0]
                   if r.get("spec_core_sha") == spec["spec_core_sha"]]
        authors = {r.get("actor") for r in current} | {spec.get("author")}
        writers.update(value.partition(":")[2] for value in authors
                       if isinstance(value, str) and value.startswith("agent:") and _identifier(value.partition(":")[2]))
        claims.append({"ticket": ticket.ticket.label, "state": issue["status"],
                       "spec_core_sha": spec["spec_core_sha"],
                       "review_sha256": digest(canonical(spec.get("reviews") or []).encode()),
                       "evidence_sha256": digest(canonical(current).encode()),
                       "missing": result["missing"]})
    return claims, sorted(writers)


def _validate_context(context):
    import merge_gate

    if (set(context) != CONTEXT_FIELDS or type(context["version"]) is not int or context["version"] != 1
            or not isinstance(context["repo"], str) or merge_gate.repo_key(context["repo"]) != context["repo"]
            or type(context["pr"]) is not int or context["pr"] <= 0
            or not all(_matches(OID, context[k]) for k in ("head", "base")) or context["head"] == context["base"]
            or not _matches(re.compile(r"[A-Za-z0-9._/-]{1,128}"), context["base_ref"]) or context["base_ref"].startswith("-")
            or not all(_matches(DIGEST, context[k]) for k in ("packet_sha256", "tests_sha256"))
            or type(context["no_ci"]) is not bool or not isinstance(context["tickets"], list)
            or not 1 <= len(context["tickets"]) <= MAX_TICKETS
            or not isinstance(context["evidence_authors"], list)
            or not all(_identifier(agent) for agent in context["evidence_authors"])):
        raise ValueError("review context is invalid")
    for claim in context["tickets"]:
        if (not isinstance(claim, dict)
                or set(claim) != {"ticket", "state", "spec_core_sha", "review_sha256", "evidence_sha256", "missing"}
                or not isinstance(claim["ticket"], str) or not isinstance(claim["state"], str)
                or not all(_matches(DIGEST, claim[k]) for k in ("spec_core_sha", "review_sha256", "evidence_sha256"))
                or not isinstance(claim["missing"], list) or not all(isinstance(x, str) for x in claim["missing"])):
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
    base_ref, no_ci = _remote(client, repository, pr, head, base)
    if not 1 <= len(commits) <= MAX_COMMITS:
        raise ValueError("candidate commit set is invalid")
    tickets, evidence_authors = _tracker_claims(repo, commits)
    context = {"version": 1, "repo": repository, "pr": pr, "head": head, "base": base, "base_ref": base_ref,
               "commits": commits, "packet_sha256": digest(packet_bytes), "tests_sha256": digest(tests_bytes), "no_ci": no_ci,
               "tickets": tickets, "evidence_authors": evidence_authors}
    _validate_context(context)
    return context, no_ci


def witness_line(context, role, agent, started, ended, report_bytes):
    _validate_context(context)
    if role not in ROLES or not _identifier(agent) or spec_flow._native_stamp(started) > spec_flow._native_stamp(ended):
        raise ValueError("invalid role, identity or review interval")
    return PREFIX + canonical({"agent": agent, "role": role, "context_sha256": context_digest(context),
                               "report_sha256": digest(report_bytes), "started": started, "ended": ended})


def _authors(report, owner, parent, commits):
    """Require a complete owner declaration; the observed Git events prove commit production only."""
    value = spec_flow._native_json(report, MAX_FILE)
    if set(value) != {"owner", "authors"} or value["owner"] != owner or not isinstance(value["authors"], dict):
        raise ValueError("owner declaration is invalid")
    if set(value["authors"]) != set(commits):
        raise ValueError("owner declaration does not cover the complete candidate")
    for identities in value["authors"].values():
        if (not isinstance(identities, list) or identities not in ([owner], sorted([owner, parent]))):
            raise ValueError("native review v1 requires one declared owner with only optional main contribution")


def _shell_commit_directory(command, cwd, home):
    """Recognize the finite commit/readback command shape without executing any input."""
    if (not isinstance(command, list) or len(command) != 3 or not all(isinstance(word, str) for word in command)
            or Path(command[0]).name not in ("bash", "zsh", "sh") or command[1] not in ("-c", "-lc")
            or not isinstance(cwd, str) or len(command[2]) > 16_000):
        return None
    current = Path(cwd)
    variables = {}
    directory = None
    readback = False
    heredoc = None
    for line in command[2].splitlines():
        if heredoc is not None:
            if line == heredoc:
                heredoc = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        words = shlex.split(stripped)
        if not words:
            continue
        if readback:
            if words not in (["git", "status", "--short"], ["git", "status", "-sb"], ["git", "diff", "--check"],
                             ["git", "diff", "--check", "HEAD^", "HEAD"], ["git", "diff", "--stat", "HEAD^", "HEAD"]):
                return None
            continue
        assignment = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(~/[A-Za-z0-9_./-]+|/[A-Za-z0-9_./-]+)", words[0])
        if assignment and len(words) == 1 and directory is None:
            name, path = assignment.groups()
            if name in variables:
                return None
            variables[name] = str(home / path[2:]) if path.startswith("~/") else path
        elif words[0] == "cd" and len(words) == 2 and directory is None:
            target = re.fullmatch(r"\$([A-Za-z_][A-Za-z0-9_]*)(/[A-Za-z0-9_./-]+)", words[1])
            if target and target[1] in variables:
                current = Path(variables[target[1]] + target[2])
            elif re.fullmatch(r"/[A-Za-z0-9_./-]+", words[1]):
                current = Path(words[1])
            else:
                return None
        elif words[:2] == ["git", "commit"]:
            flags = words[2:-1]
            if (directory is not None or flags not in (["-F"], ["--amend", "-F"])
                    or not re.fullmatch(r"(?:[$][A-Za-z_][A-Za-z0-9_]*/)?[A-Za-z0-9_./-]+", words[-1])
                    or words[-1].startswith("-")):
                return None
            directory = current.resolve()
        elif words == ["git", "rev-parse", "HEAD"]:
            if directory is None or directory != current.resolve():
                return None
            readback = True
        elif words[0] in ("set", "umask", "test") or words[:2] in (["git", "diff"], ["git", "add"]):
            continue
        elif words[0] in ("cat", "python3") and directory is None:
            delim = re.search(r"""<<['"]([A-Za-z_][A-Za-z0-9_]*)['"]$""", stripped)
            if delim is None:
                return None
            heredoc = delim[1]
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


def verify_bundle(path, expected_context, repo, *, root=None, now=None):
    bundle = _object(path)
    if set(bundle) != {"root", "context", "proofs"} or bundle["context"] != expected_context:
        raise ValueError("native review bundle does not bind the fresh candidate context")
    _validate_context(expected_context)
    parent, proofs = bundle["root"], bundle["proofs"]
    if (not _identifier(parent) or (root is not None and root != parent)
            or not isinstance(proofs, dict) or set(proofs) != set(ROLES)):
        raise ValueError("bundle root or proof set is invalid")
    if any(not isinstance(p, dict) or set(p) != PROOF_FIELDS or not _identifier(p["agent"])
           or not isinstance(p["report"], str) for p in proofs.values()):
        raise ValueError("bundle proof inputs are incomplete")
    agents = {p["agent"] for p in proofs.values()}
    if len(agents | {parent}) != 4:
        raise ValueError("owner, main and the two reviewers must have distinct identities")
    if set(expected_context["evidence_authors"]) & {proofs[name]["agent"] for name in ("acceptance", "adversarial")}:
        raise ValueError("an independent reviewer is a ticket author or evidence producer")
    import pwd
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    main = home / ".agent-harness/codex-wals" / parent / "main.jsonl"
    hashes = {}
    subjects = {sha: _git(repo, "show", "-s", "--format=%s", sha) for sha in expected_context["commits"]}
    for role in ROLES:
        proof = proofs[role]
        report = spec_flow.read_regular(Path(proof["report"]), MAX_FILE)
        if role == "owner":
            _authors(report, proof["agent"], parent, expected_context["commits"])
        else:
            _pure_review(report)
        line = witness_line(expected_context, role, proof["agent"], proof["started"], proof["ended"], report)
        typed_role = ROLES[role]
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
                                                      observe=observe if role == "owner" else None)
        if role == "owner" and created != set(subjects):
            raise ValueError("the owner history does not prove creation of every candidate commit")
        current = time.time() if now is None else now
        if not current - MAX_AGE <= spec_flow._native_stamp(proof["started"]).timestamp() <= observed.timestamp() <= current:
            raise ValueError("native PR witness is stale or has a future timestamp")
        hashes[role] = digest(line.encode())
    return {"context_sha256": context_digest(expected_context), "proofs": hashes}


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
    witness.add_argument("--role", choices=list(ROLES), required=True)
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
            client = merge_gate.Client(merge_gate.SubprocessGh(), time.monotonic() + 20)
            context, _ = cli_context(args, client)
            print(canonical(context if args.action == "context" else verify_bundle(args.bundle, context, args.repo)))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, StopIteration, subprocess.SubprocessError,
            spec_flow.SpecError, merge_gate.GateError):
        print("native PR review refused: context, remote state or independent witness did not verify", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
