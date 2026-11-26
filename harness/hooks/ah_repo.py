#!/usr/bin/env python3
"""The merge rule on GitHub, and the `harness/review` status the review runner posts (docs/merge-rule.md).

`ah repo protect owner/repo` writes one ruleset, `harness-merge-rule`, on the default branch: a pull request is
required, force-push and deletion are refused, and the `harness/review` status (plus any `--check` contexts) must
pass on the head commit. GitHub enforces it; no hook reads a merge command. `ah repo status` compares without
writing.

`ah review-status post|show` posts or reads the `harness/review` commit status. Every post is read back from
GitHub and compared before it counts (record intent, act once, read back).

Everything goes through `gh` and its own login; this module never holds or reads a token.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

RULESET_NAME = "harness-merge-rule"
STATUS_CONTEXT = "harness/review"
STATES = ("success", "failure", "error", "pending")
DESCRIPTION_LIMIT = 140  # GitHub's limit for a commit status description
GH_TIMEOUT = 30.0
ADMIN_ROLE_ID = 5  # GitHub's built-in repository role "admin"
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}")
SHA40 = re.compile(r"[0-9a-f]{40}")
PR_URL = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([0-9]+)")
CHECK_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,255}")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
PLAN_REFUSAL = re.compile(r"upgrade to github pro|make this repository public|not available for this plan|"
                          r"your plan|plan does not", re.I)
EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_PLAN = 0, 1, 2, 3


class GitHubError(Exception):
    """A GitHub call failed or its answer differs from what was asked; the message says which."""


class PlanRefused(GitHubError):
    """GitHub answered 403 because the account's plan does not allow rulesets on this (private) repository."""


# ---- gh -----------------------------------------------------------------------------------------------------------

def gh_runner(args, timeout, cwd=None, stdin=None):
    """(code, stdout, stderr) of one `gh` call; never raises. No prompt, no pager, gh's own credentials."""
    env = dict(os.environ, GH_PROMPT_DISABLED="1", GH_PAGER="cat", GIT_TERMINAL_PROMPT="0", NO_COLOR="1")
    try:
        done = subprocess.run(["gh"] + list(args), cwd=cwd if cwd and os.path.isdir(cwd) else None, input=stdin,
                              capture_output=True, text=True, timeout=max(0.5, float(timeout)), env=env)
        return done.returncode, done.stdout, done.stderr
    except (OSError, subprocess.SubprocessError) as error:
        return 127, "", "gh could not run: %s" % type(error).__name__


def clean(text, limit=300):
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _message(out, err):
    """GitHub's own message: the JSON body's "message" when there is one, else gh's last stderr line."""
    try:
        body = json.loads(out)
        if isinstance(body, dict) and isinstance(body.get("message"), str):
            return clean(body["message"])
    except (TypeError, ValueError):
        pass
    lines = [line for line in str(err or "").splitlines() if line.strip()]
    return clean(re.sub(r"^gh:\s*", "", lines[-1]) if lines else "no answer")


def _call(runner, args, what, stdin=None):
    """Parsed JSON of one gh call, or GitHubError (PlanRefused for a plan 403)."""
    runner = runner or gh_runner
    code, out, err = runner(list(args), GH_TIMEOUT, None, stdin) if stdin is not None else runner(list(args), GH_TIMEOUT)
    if code:
        message = _message(out, err)
        if "HTTP 403" in str(err) and PLAN_REFUSAL.search(message + " " + str(err)):
            raise PlanRefused(message)
        raise GitHubError("%s: %s" % (what, message))
    try:
        return json.loads(out) if str(out).strip() else None
    except ValueError:
        raise GitHubError("%s: GitHub's answer is not JSON" % what) from None


def _api(runner, method, path, what, body=None):
    args = ["api", "-X", method, "-H", "Accept: application/vnd.github+json", path]
    if body is not None:
        args += ["--input", "-"]
        return _call(runner, args, what, stdin=json.dumps(body, sort_keys=True))
    return _call(runner, args, what)


# ---- validation ---------------------------------------------------------------------------------------------------

def repo_key(value):
    """Comparable owner/repo (ASCII case fold), or None for anything that is not a plain GitHub owner/name."""
    if not isinstance(value, str) or value.count("/") != 1:
        return None
    owner, name = value.split("/")
    if not (NAME.fullmatch(owner) and NAME.fullmatch(name)) or name in (".", ".."):
        return None
    return value.translate(ASCII_LOWER)


def check_slug(value):
    if repo_key(value) is None:
        raise ValueError("repository must be owner/name (letters, digits, '.', '_', '-'), not %r" % (value,))
    return value


def check_sha(value):
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise ValueError("the commit must be the full 40-character lowercase SHA, not %r" % (value,))
    return value


def check_description(value):
    text = clean(value, DESCRIPTION_LIMIT)
    if not text:
        raise ValueError("the status needs a description")
    return text


# ---- the ruleset --------------------------------------------------------------------------------------------------

def ruleset_body(checks=(), admin_bypass=False):
    """The `harness-merge-rule` ruleset: PR required (no approving review: the owner cannot approve his own PR; the
    independent review is the status), no force-push, no deletion, `harness/review` plus `checks` required."""
    contexts = [STATUS_CONTEXT]
    for name in checks or ():
        if not isinstance(name, str) or not CHECK_NAME.fullmatch(name) or not name.strip():
            raise ValueError("a --check name is 1-255 printable characters, not %r" % (name,))
        if name not in contexts:
            contexts.append(name)
    return {
        "name": RULESET_NAME, "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": ([{"actor_id": ADMIN_ROLE_ID, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}]
                          if admin_bypass else []),
        "rules": [
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": False,
                "require_code_owner_review": False, "require_last_push_approval": False,
                "required_review_thread_resolution": False}},
            {"type": "non_fast_forward"},
            {"type": "deletion"},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": False,
                "required_status_checks": [{"context": c} for c in contexts]}}]}


def differences(wanted, actual):
    """What in `actual` (GitHub's ruleset) differs from `wanted`; GitHub's own added fields are ignored."""
    if not isinstance(actual, dict):
        return ["the ruleset could not be read"]
    found = []
    for key in ("name", "target", "enforcement", "conditions"):
        if actual.get(key) != wanted[key]:
            found.append("%s is %s, wanted %s" % (key, json.dumps(actual.get(key)), json.dumps(wanted[key])))
    bypass = [{k: a.get(k) for k in ("actor_id", "actor_type", "bypass_mode")}
              for a in actual.get("bypass_actors") or [] if isinstance(a, dict)]
    if bypass != wanted["bypass_actors"] or len(actual.get("bypass_actors") or []) != len(bypass):
        found.append("bypass_actors is %s, wanted %s" % (json.dumps(bypass), json.dumps(wanted["bypass_actors"])))
    rules = {r.get("type"): r for r in actual.get("rules") or [] if isinstance(r, dict)}
    for rule in wanted["rules"]:
        have = rules.pop(rule["type"], None)
        if have is None:
            found.append("rule %s is missing" % rule["type"])
            continue
        params = have.get("parameters") or {}
        for key, value in (rule.get("parameters") or {}).items():
            if key == "required_status_checks":
                got = sorted(str(c.get("context")) for c in params.get(key) or [] if isinstance(c, dict))
                if got != sorted(c["context"] for c in value):
                    found.append("required status checks are %s, wanted %s"
                                 % (", ".join(got) or "none", ", ".join(c["context"] for c in value)))
            elif params.get(key) != value:
                found.append("%s.%s is %s, wanted %s" % (rule["type"], key, json.dumps(params.get(key)),
                                                         json.dumps(value)))
    for extra in sorted(str(t) for t in rules):
        found.append("rule %s is not part of the merge rule" % extra)
    return found


def summary(slug, wanted, ruleset_id):
    contexts = ", ".join(c["context"] for c in wanted["rules"][3]["parameters"]["required_status_checks"])
    bypass = ", admin bypass by pull request" if wanted["bypass_actors"] else ""
    return "protected %s: pr, no-force-push, no-delete, status %s%s (ruleset %s)" % (slug, contexts, bypass,
                                                                                    ruleset_id)


def _repository(slug, runner):
    value = _api(runner, "GET", "repos/" + slug, "could not read " + slug)
    if not isinstance(value, dict) or not isinstance(value.get("default_branch"), str):
        raise GitHubError("could not read %s: unexpected answer" % slug)
    return value


def _find(slug, runner):
    listed = _api(runner, "GET", "repos/%s/rulesets?includes_parents=false&per_page=100" % slug,
                  "could not list the rulesets of " + slug)
    if not isinstance(listed, list):
        raise GitHubError("could not list the rulesets of %s: unexpected answer" % slug)
    ours = [r for r in listed if isinstance(r, dict) and r.get("name") == RULESET_NAME
            and r.get("source_type", "Repository") == "Repository" and type(r.get("id")) is int]
    if len(ours) > 1:
        raise GitHubError("%s has %d rulesets named %s; delete all but one in the repository settings"
                          % (slug, len(ours), RULESET_NAME))
    return ours[0]["id"] if ours else None


def _read_ruleset(slug, ruleset_id, runner):
    return _api(runner, "GET", "repos/%s/rulesets/%d" % (slug, ruleset_id), "could not read the ruleset back")


def protect(slug, checks=(), admin_bypass=False, runner=None):
    """Create or replace `harness-merge-rule` on `slug`, read it back and compare: {"repo", "ruleset", "line"}.
    Raises PlanRefused (plan 403), GitHubError (any failure or mismatch) or ValueError (bad input)."""
    check_slug(slug)
    wanted = ruleset_body(checks, admin_bypass)
    repository = _repository(slug, runner)
    if not (repository.get("permissions") or {}).get("admin"):
        raise GitHubError("you need admin permission on %s to set its merge rule; ask its owner" % slug)
    existing = _find(slug, runner)
    if existing is None:
        written = _api(runner, "POST", "repos/%s/rulesets" % slug, "could not create the ruleset", wanted)
    else:
        written = _api(runner, "PUT", "repos/%s/rulesets/%d" % (slug, existing), "could not update the ruleset", wanted)
    ruleset_id = written.get("id") if isinstance(written, dict) else None
    if type(ruleset_id) is not int or (existing is not None and ruleset_id != existing):
        raise GitHubError("GitHub did not answer with the ruleset it wrote")
    problems = differences(wanted, _read_ruleset(slug, ruleset_id, runner))
    if problems:
        raise GitHubError("the ruleset read back differs: " + "; ".join(problems))
    return {"repo": slug, "ruleset": ruleset_id, "protected": True, "line": summary(slug, wanted, ruleset_id)}


def status(slug, checks=(), admin_bypass=False, runner=None):
    """The same comparison as protect, without writing: {"repo", "protected", "ruleset", "problems", "line"}."""
    check_slug(slug)
    wanted = ruleset_body(checks, admin_bypass)
    _repository(slug, runner)
    ruleset_id = _find(slug, runner)
    if ruleset_id is None:
        return {"repo": slug, "protected": False, "ruleset": None,
                "problems": ["no ruleset named %s" % RULESET_NAME], "line": None}
    problems = differences(wanted, _read_ruleset(slug, ruleset_id, runner))
    return {"repo": slug, "protected": not problems, "ruleset": ruleset_id, "problems": problems,
            "line": None if problems else summary(slug, wanted, ruleset_id)}


# ---- the review status --------------------------------------------------------------------------------------------

def newest_review_status(repo, sha, runner=None):
    """The newest `harness/review` status on `sha` (GitHub lists newest first), or None."""
    check_slug(repo)
    check_sha(sha)
    listed = _api(runner, "GET", "repos/%s/commits/%s/statuses?per_page=100" % (repo, sha),
                  "could not read the statuses of " + sha[:12])
    if not isinstance(listed, list):
        raise GitHubError("could not read the statuses of %s: unexpected answer" % sha[:12])
    for entry in listed:
        if isinstance(entry, dict) and entry.get("context") == STATUS_CONTEXT:
            return entry
    return None


def post_review_status(repo, sha, state, description, target_url=None, runner=None):
    """Post `harness/review` = `state` on the exact commit `sha`, then read the statuses back and confirm the newest
    `harness/review` entry is the one sent. Returns that entry. ValueError for bad input (nothing is sent);
    GitHubError when the post fails or the readback differs."""
    check_slug(repo)
    check_sha(sha)
    if state not in STATES:
        raise ValueError("state must be one of " + ", ".join(STATES))
    text = check_description(description)
    if target_url is not None and not re.fullmatch(r"https://[^\s\x00-\x1f\x7f]{1,2000}", str(target_url)):
        raise ValueError("--target-url must be an https:// URL")
    body = {"state": state, "context": STATUS_CONTEXT, "description": text}
    if target_url is not None:
        body["target_url"] = target_url
    sent = _api(runner, "POST", "repos/%s/statuses/%s" % (repo, sha), "could not post %s" % STATUS_CONTEXT, body)
    entry = newest_review_status(repo, sha, runner)
    if entry is None:
        raise GitHubError("read back: no %s status on %s after the post" % (STATUS_CONTEXT, sha[:12]))
    posted_id = sent.get("id") if isinstance(sent, dict) else None
    mismatch = [key for key in ("state", "description") if entry.get(key) != body[key]]
    if target_url is not None and entry.get("target_url") != target_url:
        mismatch.append("target_url")
    if posted_id is not None and entry.get("id") != posted_id:
        mismatch.append("id (a newer %s status was posted by someone else)" % STATUS_CONTEXT)
    if mismatch:
        raise GitHubError("read back: the newest %s status on %s differs in %s (it says %s: %s)"
                          % (STATUS_CONTEXT, sha[:12], ", ".join(mismatch), entry.get("state"),
                             clean(entry.get("description"), 140)))
    return entry


def pr_head(repo, number, runner=None):
    """{"repo", "pr", "head", "state"} of pull request `number` as GitHub reports it. The answer's URL must name
    github.com, this repository (ASCII case-insensitive) and this number, or GitHubError."""
    check_slug(repo)
    if type(number) is not int or number <= 0:
        raise ValueError("the pull request number must be a positive integer")
    value = _call(runner, ["pr", "view", str(number), "-R", repo, "--json", "number,url,headRefOid,state"],
                  "could not read pull request %s#%d" % (repo, number))
    if not isinstance(value, dict):
        raise GitHubError("pull request %s#%d is unreadable" % (repo, number))
    match = PR_URL.fullmatch(str(value.get("url") or ""))
    head = value.get("headRefOid")
    if (not match or repo_key(match.group(1) + "/" + match.group(2)) != repo_key(repo)
            or int(match.group(3)) != number or type(value.get("number")) is not int or value["number"] != number):
        raise GitHubError("GitHub answered for a different pull request than %s#%d" % (repo, number))
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise GitHubError("pull request %s#%d has no readable head commit" % (repo, number))
    return {"repo": repo_key(repo), "pr": number, "head": head, "state": str(value.get("state") or "").upper()}


# ---- owner override -----------------------------------------------------------------------------------------------

def owner_override_approval(repo, pr, approval_id, env=None, home=None):
    """The live `merge` approval `approval_id` for repo#pr, when run by a person outside any agent. Raises
    ValueError naming the one command that proceeds."""
    import ah_approvals  # noqa: PLC0415 - a sibling module
    if ah_approvals.in_agent(env):
        raise ValueError("--owner-override runs only outside an agent, in the owner's own terminal")
    facts = {"repo": repo, "pr": pr}
    record = ah_approvals.allowed("merge", home=home, **facts)
    if record is None or record.get("id") != approval_id:
        found = next((r for r in ah_approvals.records(home) if r.get("id") == approval_id), None)
        record = found if found is not None and ah_approvals.covers(found, "merge", facts) else None
    if record is None:
        raise ValueError("no live merge approval %s for %s#%s; the owner runs `%s` first"
                         % (approval_id, repo, pr, ah_approvals.command_hint("merge", project=repo, pr=pr)))
    return record


# ---- command lines ------------------------------------------------------------------------------------------------

def _print_json(value):
    json.dump(value, sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")


def main(argv=None, runner=None) -> int:
    """`ah repo protect|status owner/repo`."""
    parser = argparse.ArgumentParser(prog="ah repo", description="The merge rule on GitHub (docs/merge-rule.md).")
    sub = parser.add_subparsers(dest="action", required=True)
    for name, text in (("protect", "create or update the harness-merge-rule ruleset, then read it back"),
                       ("status", "compare the ruleset with the merge rule; writes nothing")):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("repo", metavar="OWNER/REPO")
        cmd.add_argument("--check", action="append", default=[], metavar="NAME",
                         help="also require this status check (the repository's own CI); repeatable")
        cmd.add_argument("--admin-bypass", action="store_true",
                         help="let repository admins merge without the checks, through a pull request only")
        cmd.add_argument("--json", action="store_true")
        if name == "protect":
            cmd.add_argument("--dry-run", action="store_true", help="print the ruleset body and call nothing")
    args = parser.parse_args(argv)
    try:
        check_slug(args.repo)
        body = ruleset_body(args.check, args.admin_bypass)
    except ValueError as error:
        print("ah repo: %s" % error, file=sys.stderr)
        return EXIT_USAGE
    if args.action == "protect" and args.dry_run:
        _print_json(body)
        return EXIT_OK
    try:
        if args.action == "protect":
            result = protect(args.repo, args.check, args.admin_bypass, runner=runner)
        else:
            result = status(args.repo, args.check, args.admin_bypass, runner=runner)
    except PlanRefused as error:
        if args.json:
            _print_json({"repo": args.repo, "protected": False, "plan_refused": True, "message": str(error)})
        print("not protected: %s" % error, file=sys.stderr)
        return EXIT_PLAN
    except GitHubError as error:
        if args.json:
            _print_json({"repo": args.repo, "protected": False, "message": str(error)})
        print("not protected %s: %s" % (args.repo, error), file=sys.stderr)
        return EXIT_FAILED
    if args.json:
        _print_json(result)
    if result["protected"]:
        if not args.json:
            print(result["line"])
        return EXIT_OK
    print("not protected %s: %s" % (args.repo, "; ".join(result["problems"])), file=sys.stderr)
    return EXIT_FAILED


def review_status_main(argv=None, runner=None) -> int:
    """`ah review-status post|show`."""
    parser = argparse.ArgumentParser(prog="ah review-status",
                                     description="Post or read the harness/review commit status (docs/merge-rule.md).")
    sub = parser.add_subparsers(dest="action", required=True)
    post = sub.add_parser("post", help="post harness/review on one commit, then read it back")
    show = sub.add_parser("show", help="print the newest harness/review status on one commit")
    for cmd in (post, show):
        cmd.add_argument("--repo", required=True, metavar="OWNER/REPO")
        cmd.add_argument("--sha", required=True, help="the full 40-character commit SHA")
        cmd.add_argument("--json", action="store_true")
    post.add_argument("--state", required=True, choices=STATES)
    post.add_argument("--description", required=True, help="at most 140 characters; longer text is cut")
    post.add_argument("--target-url", help="an https:// link shown beside the status")
    post.add_argument("--owner-override", action="store_true",
                      help="the owner's path for a pull request the reviewer blocked: needs --approval and --pr, "
                           "and runs only outside an agent")
    post.add_argument("--approval", help="the live `ah approve merge --project OWNER/REPO --pr N` record id")
    post.add_argument("--pr", type=int, help="the pull request the approval names")
    args = parser.parse_args(argv)
    try:
        check_slug(args.repo)
        check_sha(args.sha)
        if args.action == "post":
            description = args.description
            if args.owner_override or args.approval:
                if not (args.owner_override and args.approval and args.pr):
                    raise ValueError("--owner-override needs --approval ID and --pr N together")
                record = owner_override_approval(args.repo, args.pr, args.approval)
                description = "owner override, approval %s: %s" % (record["id"], description)
            entry = post_review_status(args.repo, args.sha, args.state, description, args.target_url, runner=runner)
        else:
            entry = newest_review_status(args.repo, args.sha, runner=runner)
    except ValueError as error:
        print("ah review-status: %s" % error, file=sys.stderr)
        return EXIT_USAGE
    except GitHubError as error:
        print("ah review-status: %s" % error, file=sys.stderr)
        return EXIT_FAILED
    if args.json:
        _print_json(entry)
    elif entry is None:
        print("no harness/review status on %s in %s" % (args.sha[:12], args.repo))
    else:
        print("%s %s on %s in %s: %s (%s)" % (STATUS_CONTEXT, entry.get("state"), args.sha[:12], args.repo,
                                             clean(entry.get("description"), 140), entry.get("created_at") or "?"))
    return EXIT_OK if entry is not None else EXIT_FAILED


if __name__ == "__main__":
    if sys.argv[1:2] == ["review-status"]:
        sys.exit(review_status_main(sys.argv[2:]))
    sys.exit(main(sys.argv[1:]))
