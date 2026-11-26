#!/usr/bin/env python3
"""Merge gate: one real check before a pull request lands on a protected branch.

The rule (the user, 2026-11-24): a merge into a protected branch needs a passing independent review of that PR, or
an approval. Everything else the old gate did (CI checks, head pinning, stamps, analysing every shell spelling) is
gone; GitHub branch protection enforces required checks server side.

  hook    PreToolUse on shell tools. Reads the command; only `gh pr merge`, `gh api .../pulls/N/merge` (PUT),
          GraphQL merge mutations and `git push` to a protected branch are merges. Heredoc bodies and quoted strings
          are text, not commands. A command it cannot parse, that is too large, or that runs past the analyser budget
          is ALLOWED with one line on stderr and in ~/.agent-harness/logs/merge-gate.log.
  check   the same decision for --repo/--pr, printed, never recorded.
  waive   record a merge waiver for a PR (or one exact head). Free-text reason, any approver text, ticket optional.
  report  list recent waivers.

A merge is allowed when the PR's base is not protected, or a PASS PR review receipt (peer_review.py pr, read from
the usage store) covers it: the receipt is for the current head, or the change since the reviewed head is small
(policy `small_change_lines`, default 150, and no file matching `sensitive_paths`), or an approval exists
(ah_approvals when installed, else this gate's waiver log). Approvals and waivers bind to the PR, not the commit,
unless the record names an exact head. Otherwise the hook refuses with one message listing what is missing and the
command for each way to proceed.

Policy: the "merge_gate" object of commit_policy.json, overlaid by the same key in commit_policy.local.json.
Stdlib only, Python 3.9.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

POLICY = {
    "protected_branches": ["main", "master"],
    "small_change_lines": 150,
    "sensitive_paths": [".github/workflows/*", "*migrations/*", "*.sql", "*secret*", "*credential*",
                        "package-lock.json", "*/package-lock.json", "*.lock", "*/auth/*", "auth/*"],
    "receipt_max_age_days": 30,
    "require_other_harness": False,
    "waiver_ttl_hours": 24,
    "analyser_seconds": 2.0,
    "lookup_seconds": 20.0,
}
MAX_INPUT = 4 * 1024 * 1024
MAX_COMMAND = 1024 * 1024
MAX_DEPTH = 4
REASON_CAP = 4000
WAIVER_FILE = "merge-gate-waivers.jsonl"
SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
# Cheap first pass: without one of these words nothing below runs.
HINT = re.compile(r"merge|push|waive", re.I)
SHELL_TOOLS = {"bash", "shell", "local_shell", "exec_command", "unified_exec", "container.exec"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
WRAPPERS = {"env", "command", "builtin", "exec", "nohup", "time", "nice", "timeout", "sudo", "stdbuf", "caffeinate"}
PUNCT = set(";&|()<>")
GRAPHQL_MERGE = re.compile(r"mergePullRequest|enablePullRequestAutoMerge|enqueuePullRequest")
NODE_ID = re.compile(r"\bPR_[A-Za-z0-9_-]{6,}")
HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][\w.-]*)\1")
PR_URL = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)")
GH_PR_VALUE = {"-R", "--repo", "-b", "--body", "-F", "--body-file", "-t", "--subject", "-A", "--author-email",
               "--match-head-commit"}
GH_API_VALUE = {"-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "-q", "--jq", "--input",
                "--hostname", "--cache", "-p", "--preview", "-t", "--template"}
PUSH_VALUE = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}


class Unsure(Exception):
    """The analyser could not read the command: the hook allows and logs."""


class GhError(Exception):
    """A GitHub lookup failed: a real merge is refused, naming the failure."""


def repo_key(value):
    """Comparable owner/repo (ASCII case fold), or None for anything that is not a plain GitHub name."""
    if not isinstance(value, str) or not REPO_NAME.fullmatch(value):
        return None
    return value.translate(ASCII_LOWER)


def clean(text, limit=200):
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def load_policy():
    policy = dict(POLICY)
    for name in ("commit_policy.json", "commit_policy.local.json"):
        try:
            with open(HERE / name, encoding="utf-8") as handle:
                data = json.loads(handle.read(1 << 20))
        except (OSError, ValueError):
            continue
        extra = data.get("merge_gate") if isinstance(data, dict) else None
        if isinstance(extra, dict):
            policy.update({k: v for k, v in extra.items() if k in POLICY})
    return policy


def log_line(text, home=None, stderr=True):
    """One line to the gate log (and stderr unless told otherwise). Never raises."""
    line = "merge-gate: " + clean(text, 400)
    try:
        if stderr:
            sys.stderr.write(line + "\n")
    except Exception:
        pass
    try:
        folder = Path(home or Path.home()) / ".agent-harness" / "logs"
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / "merge-gate.log", "a", encoding="utf-8") as handle:
            handle.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + line + "\n")
    except OSError:
        pass


# ------------------------------------------------------------------------------------------------ analyser

class Action:
    """One thing the command would do that the gate cares about."""

    def __init__(self, kind, **kw):
        self.kind = kind  # pr | push | graphql | unknown_target | waive
        self.repo = kw.get("repo")
        self.target = kw.get("target")
        self.cwd = kw.get("cwd")
        self.remote = kw.get("remote")
        self.branch = kw.get("branch")
        self.src = kw.get("src")
        self.node = kw.get("node")
        self.why = kw.get("why", "")
        self.argv = kw.get("argv", [])

    def __repr__(self):
        return "Action(%s %s %s %s)" % (self.kind, self.repo, self.target or self.branch or self.node, self.why)


def strip_heredocs(text):
    """Drop heredoc bodies unless a shell reads them as its script. An unterminated heredoc is left as is."""
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        delims = [m.group(2) for m in HEREDOC.finditer(line)]
        if not delims:
            continue
        words = re.findall(r"[\w./-]+", line)
        feeds_shell = any(os.path.basename(w) in SHELLS or w == "eval" for w in words)
        for delim in delims:
            end = next((k for k in range(i, len(lines)) if lines[k].strip() == delim), None)
            if end is None:
                return "\n".join(out + lines[i:])
            if feeds_shell:
                out.extend(lines[i:end])
            out.append(";")
            i = end + 1
    return "\n".join(out)


def strip_comments(text):
    """Drop shell comments (an unquoted # at a word start up to the newline); quote aware."""
    out, quote, i, n = [], None, 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(c)
                i += 1
                c = text[i]
            elif c == quote:
                quote = None
        elif c == "\\" and i + 1 < n:
            out.append(c)
            i += 1
            c = text[i]
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|()"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def substitutions(text):
    """Bodies of $( ... ) and `...` outside single quotes (they run even inside double quotes)."""
    found, i, n, quote = [], 0, len(text), None
    while i < n:
        c = text[i]
        if quote == "'":
            quote = None if c == "'" else quote
        elif c == "\\":
            i += 1
        elif c == "'" and quote is None:
            quote = "'"
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "`":
            end = text.find("`", i + 1)
            if end > i:
                found.append(text[i + 1:end])
                i = end
        elif text.startswith("$(", i) and not text.startswith("$((", i):
            depth, k = 1, i + 2
            while k < n and depth:
                depth += {"(": 1, ")": -1}.get(text[k], 0)
                k += 1
            if depth == 0:
                found.append(text[i + 2:k - 1])
                i = k - 1
        i += 1
    return found


def tokens(text):
    """shlex words with separators kept; raises Unsure on unbalanced quotes."""
    text = text.replace("\\\n", " ").replace("\n", "\n;")
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
    lex.whitespace = " \t\r\n"
    lex.whitespace_split = True
    lex.commenters = ""  # strip_comments already removed real comments; '#' inside a word is text
    try:
        return list(lex)
    except ValueError as error:
        raise Unsure("could not parse the command (%s)" % error) from None


def segments(words):
    """Simple commands: lists of words between separators, with redirect targets dropped."""
    out, current, skip = [], [], False
    for word in words:
        if word and set(word) <= PUNCT:
            if set(word) & set(";&|()"):
                if current:
                    out.append(current)
                current, skip = [], False
            else:
                skip = True  # <, >, >>: the next word is a file
            continue
        if skip:
            skip = False
            continue
        current.append(word)
    if current:
        out.append(current)
    return out


def command_start(seg):
    """Index of the program word: skips NAME=value, wrappers and their options."""
    i = 0
    while i < len(seg):
        word = seg[i]
        base = os.path.basename(word)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word):
            i += 1
        elif base in WRAPPERS:
            i += 1
            while i < len(seg) and (seg[i].startswith("-") or re.match(r"^\d+[smhd]?$", seg[i])
                                    or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i])):
                i += 2 if seg[i] in ("-u", "-n", "-s", "-k", "-g") else 1
        else:
            return i
    return len(seg)


def _positionals(args, value_flags):
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(args[i + 1:])
            break
        if a in value_flags:
            i += 2
            continue
        if not a.startswith("-") or a == "-":
            out.append(a)
        i += 1
    return out


def _flag(args, *names):
    for i, a in enumerate(args):
        for name in names:
            if a == name and i + 1 < len(args):
                return args[i + 1]
            if name.startswith("--") and a.startswith(name + "="):
                return a[len(name) + 1:]
            if not name.startswith("--") and a.startswith(name) and len(a) > len(name):
                return a[len(name):]
    return None


def _gh(args, cwd, assigns):
    if any(a in ("-h", "--help") for a in args):
        return []
    pos = _positionals(args, GH_PR_VALUE | GH_API_VALUE)
    if pos[:2] == ["pr", "merge"]:
        if "--disable-auto" in args:
            return []
        rest = args[args.index("merge") + 1:]
        targets = _positionals(rest, GH_PR_VALUE)
        target = targets[0] if targets else ""
        target = assigns.get(target[1:].strip("{}"), target) if target.startswith("$") else target
        repo = _flag(rest, "-R", "--repo")
        if (target and re.search(r"[$`*?]", target)) or (repo and "$" in repo):
            return [Action("unknown_target", why="the PR is named by a variable", argv=["gh"] + args)]
        url = PR_URL.match(target)
        if url:
            repo, target = url.group(1), url.group(2)
        return [Action("pr", repo=repo, target=target, cwd=cwd)]
    if pos[:1] == ["api"]:
        rest = args[args.index("api") + 1:]
        path = (_positionals(rest, GH_API_VALUE) or [""])[0].lstrip("/").split("?")[0]
        method = (_flag(rest, "-X", "--method") or "").upper()
        values = [rest[i + 1] for i, a in enumerate(rest[:-1]) if a in ("-f", "-F", "--field", "--raw-field")]
        values += [a.split("=", 1)[1] for a in rest if a.startswith(("--field=", "--raw-field="))]
        if path == "graphql":
            joined = " ".join(values)
            if not GRAPHQL_MERGE.search(joined):
                return []
            node = NODE_ID.search(joined)
            if not node:
                return [Action("unknown_target", why="the GraphQL merge does not name its pull request id literally")]
            return [Action("graphql", node=node.group(0), cwd=cwd)]
        m = re.fullmatch(r"repos/([^/]+)/([^/]+)/pulls/(\d+)/merge", path)
        if m and method == "PUT":
            owner, name = m.group(1), m.group(2)
            repo = None if "{" in owner + name else owner + "/" + name
            return [Action("pr", repo=repo, target=m.group(3), cwd=cwd)]
    return []


def _git(args, cwd, policy):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            cwd = os.path.join(cwd or "", os.path.expanduser(args[i + 1]))
            i += 2
        elif args[i] in ("-c", "--git-dir", "--work-tree", "--namespace"):
            i += 2
        else:
            i += 1
    if i >= len(args) or args[i] != "push":
        return []
    rest = args[i + 1:]
    if any(a in ("-n", "--dry-run", "-d", "--delete", "-h", "--help") for a in rest):
        return []
    pos = _positionals(rest, PUSH_VALUE)
    every = any(a in ("--all", "--mirror", "--branches") for a in rest)
    remote = pos[0] if pos else None
    specs = pos[1:] or ([] if every else ["HEAD"])
    found = []
    for spec in specs + (["*all*"] if every else []):
        src, _, dst = spec.lstrip("+").partition(":")
        dst = dst or src
        found.append(Action("push", remote=remote, src=src, branch=dst, cwd=cwd))
    return found


def _waive(seg, start):
    """`python3 .../merge_gate.py waive ...` (or the script run directly): the waive CLI is about to run."""
    words = seg[start:]
    k = 0
    if words and re.fullmatch(r"python[0-9.]*", os.path.basename(words[0])):
        k = 1
        while k < len(words) and words[k].startswith("-"):
            k += 1
    if k < len(words) and os.path.basename(words[k]) == "merge_gate.py":
        rest = words[k + 1:]
        if "waive" in rest[:3]:
            return [Action("waive", repo=_flag(rest, "--repo"), argv=rest)]
    return []


def analyse(command, cwd=None, policy=None, deadline=None, depth=0):
    """[Action] the command would run. Raises Unsure when it cannot be read in time."""
    policy = policy or POLICY
    deadline = deadline or time.monotonic() + float(policy["analyser_seconds"])
    if depth > MAX_DEPTH:
        raise Unsure("commands nested too deeply")
    if len(command) > MAX_COMMAND:
        raise Unsure("command larger than %d bytes" % MAX_COMMAND)
    if not HINT.search(command):
        return []
    text = strip_comments(strip_heredocs(command))
    if not HINT.search(text):
        return []
    found = []
    for inner in substitutions(text):
        found += analyse(inner, cwd, policy, deadline, depth + 1)
    assigns = {}
    for seg in segments(tokens(text)):
        if time.monotonic() > deadline:
            raise Unsure("analyser ran past its %.1f s budget" % float(policy["analyser_seconds"]))
        start = command_start(seg)
        if start == len(seg):
            for word in seg:  # NAME=literal on its own: remembered for a later $NAME target
                name, _, value = word.partition("=")
                if not re.search(r"[$`]", value):
                    assigns[name] = value
            continue
        word, args = os.path.basename(seg[start]), seg[start + 1:]
        if word in ("cd", "pushd"):
            target = args[0] if args else "~"
            cwd = None if re.search(r"[$`]", target) or target == "-" else os.path.normpath(
                os.path.join(cwd or os.getcwd(), os.path.expanduser(target)))
        elif word == "gh":
            found += _gh(args, cwd, assigns)
        elif word == "git":
            found += _git(args, cwd, policy)
        elif word in SHELLS:
            for k, a in enumerate(args[:-1]):
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a):
                    found += analyse(args[k + 1], cwd, policy, deadline, depth + 1)
                    break
        elif word == "eval":
            found += analyse(" ".join(args), cwd, policy, deadline, depth + 1)
        elif word == "ssh" and args:
            for a in analyse(args[-1], None, policy, deadline, depth + 1):
                found.append(a if a.repo or a.kind != "pr" else
                             Action("unknown_target", why="the merge runs over ssh without -R owner/repo"))
        elif word == "xargs" or word == "parallel":
            inner = args[command_start(args):] if args else []
            inner = [a for a in inner if not a.startswith("-")]
            if inner[:1] == ["gh"] and "merge" in inner:
                found.append(Action("unknown_target", why="xargs supplies the PR at run time"))
        else:
            found += _waive(seg, start)
    return found


# ------------------------------------------------------------------------------------------------ lookups

def run(args, cwd=None, timeout=10.0):
    """(code, stdout, stderr) of a gh or git call; never raises."""
    try:
        done = subprocess.run(args, cwd=cwd if cwd and os.path.isdir(cwd) else None, capture_output=True,
                              text=True, timeout=max(0.5, timeout), env=dict(os.environ, GH_PROMPT_DISABLED="1",
                                                                             GIT_TERMINAL_PROMPT="0"))
        return done.returncode, done.stdout, done.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return 124, "", type(error).__name__


class Lookup:
    def __init__(self, runner, seconds):
        self.runner = runner or run
        self.deadline = time.monotonic() + float(seconds)

    def left(self):
        return max(0.5, self.deadline - time.monotonic())

    def json(self, args, cwd=None):
        code, out, err = self.runner(args, cwd=cwd, timeout=self.left())
        if code:
            raise GhError("`%s` failed: %s" % (" ".join(args[:3]), clean(err or out or code, 160)))
        try:
            return json.loads(out)
        except ValueError:
            raise GhError("`%s` returned no JSON" % " ".join(args[:3])) from None

    def text(self, args, cwd=None):
        code, out, _ = self.runner(args, cwd=cwd, timeout=self.left())
        return out.strip() if code == 0 else ""


def slug_from_url(url):
    m = re.search(r"github\.com[:/]+([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url or "")
    return m.group(1) + "/" + m.group(2) if m else None


def usage_root():
    return Path(os.environ.get("AGENT_HARNESS_USAGE_DIR") or Path.home() / ".agent-harness" / "usage").expanduser()


def receipts(repo, pr, commits, policy, deadline, root=None):
    """PASS PR review receipts that belong to this PR, newest first: bound to repo#pr, or unbound with a head that
    is one of the PR's commits. Read straight from the usage store (runs/<id>/final.json + settled.json)."""
    runs = (root or usage_root()) / "runs"
    cutoff = time.time() - float(policy["receipt_max_age_days"]) * 86400
    try:
        entries = sorted(((e.stat().st_mtime, e.path) for e in os.scandir(runs) if e.is_dir()), reverse=True)
    except OSError:
        return []
    want, found = repo_key(repo), []
    for mtime, path in entries:
        if mtime < cutoff or time.monotonic() > deadline:
            break
        try:
            with open(os.path.join(path, "final.json"), "rb") as handle:
                body = handle.read(2 * 1024 * 1024)
        except OSError:
            continue
        if b'"PR"' not in body or b'"ACCEPT' not in body:
            continue
        try:
            final = json.loads(body)
            with open(os.path.join(path, "settled.json"), "rb") as handle:
                settled = json.loads(handle.read(65536))
        except (OSError, ValueError):
            continue
        if not isinstance(final, dict) or not isinstance(settled, dict):
            continue
        review = final.get("review")
        usage = final.get("usage") if isinstance(final.get("usage"), dict) else {}
        if (not isinstance(review, dict) or os.path.exists(os.path.join(path, "invalidated.json"))
                or (settled.get("reference") or {}).get("sha256") != hashlib.sha256(body).hexdigest()
                or final.get("execution") != "COMPLETED" or final.get("result") != "CHECK_OK"
                or review.get("stage") != "PR" or review.get("verdict") not in ("ACCEPT", "ACCEPT_WITH_TICKETS")
                or not isinstance(review.get("head"), str) or not SHA.fullmatch(review["head"])
                or not isinstance(usage.get("provider_launches"), int) or usage["provider_launches"] < 1):
            continue
        if policy.get("require_other_harness") and (
                review.get("reviewer_harness") not in ("claude", "openai")
                or review.get("reviewer_harness") == review.get("author_harness")):
            continue
        if "repo" in review:
            if repo_key(review.get("repo")) != want or review.get("pr") != pr:
                continue
        elif review["head"] not in commits:
            continue
        found.append({"head": review["head"], "run": os.path.basename(path), "reviewer": review.get("reviewer"),
                      "at": final.get("ended_at")})
        if commits and review["head"] == commits[-1]:
            break  # a receipt for the current head: nothing else matters
    return found


def approval(repo, pr, head, payload, state_dir, policy, now):
    """The approval or waiver record that covers this merge, or None."""
    try:
        import ah_approvals  # noqa: PLC0415 - a sibling module; absent on older installs
    except Exception:
        ah_approvals = None
    if ah_approvals is not None:
        try:
            record = ah_approvals.allowed("merge", repo=repo, pr=pr, head=head,
                                          session=(payload or {}).get("session_id"), payload=payload)
        except Exception as error:  # a broken approvals module must not stop the waiver fallback
            log_line("ah_approvals.allowed failed (%s); using the waiver log" % type(error).__name__)
            record = None
        if record:
            return record
    ttl = float(policy["waiver_ttl_hours"]) * 3600
    for record in reversed(read_waivers(state_dir)):
        if (record.get("event") == "waive" and repo_key(record.get("repo")) == repo_key(repo)
                and now < float(record.get("ts") or 0) + ttl
                and (record.get("pr") in (pr, None)) and (record.get("pr") is not None or record.get("head"))
                and record.get("head") in (None, "", head)):
            return record
    return None


# ------------------------------------------------------------------------------------------------ decision

GATE = HERE / "merge_gate.py"


def _ways(repo, pr, head, missing):
    pr_part = "--pr %s" % pr if pr else "--head %s" % head
    lines = ["merge-gate: refused merge of %s%s (head %s)." % (repo, "#%s" % pr if pr else "", head[:12]),
             "Missing: " + missing, "Any one of these lets it through:"]
    if pr:
        lines.append("  - review the current head: python3 ~/.claude/hooks/peer_review.py pr --repo <checkout> "
                     "--packet <packet> --output <report> --expected-head %s --github-repo %s --pr %s"
                     % (head, repo, pr))
    lines.append("  - record a waiver (main agent, Fable/Astra, a supervisor of %s, or you in a terminal): "
                 "python3 %s waive --repo %s %s --reason \"<why>\"" % (repo, GATE, repo, pr_part))
    try:
        import ah_approvals  # noqa: PLC0415
        hint = getattr(ah_approvals, "command_hint", None)
        if callable(hint):
            lines.append("  - ask the user to approve it: " + str(hint("merge", repo=repo, pr=pr, head=head)))
    except Exception:
        pass
    return "\n".join(lines)


def evaluate_pr(repo, pr, head, base, commits, policy, look, payload, state_dir, now):
    """(allowed, message). `commits` are the PR's commit SHAs, oldest first."""
    protected = [str(b) for b in policy["protected_branches"]]
    if base not in protected:
        return True, "base %s is not protected" % base
    found = receipts(repo, pr, commits, policy, look.deadline)
    if any(r["head"] == head for r in found):
        return True, "PASS review receipt for the current head"
    missing = "a passing independent review of %s#%s (no PASS peer_review.py pr receipt for it)" % (repo, pr)
    # The head moved after the review: try the latest reviewed commits of this branch first (at most three).
    order = {sha: i for i, sha in enumerate(commits)}
    for receipt in sorted(found, key=lambda r: order.get(r["head"], -1), reverse=True)[:3]:
        reviewed = receipt["head"]
        try:
            data = look.json(["gh", "api", "repos/%s/compare/%s...%s" % (repo, reviewed, head)])
        except GhError as error:
            missing = "the PASS review covers %s; the change since could not be read (%s)" % (reviewed[:12], error)
            break
        data = data if isinstance(data, dict) else {}
        files = [f for f in data.get("files") or [] if isinstance(f, dict)]
        lines = sum(int(f.get("additions") or 0) + int(f.get("deletions") or 0) for f in files)
        names = [n for f in files for n in (f.get("filename"), f.get("previous_filename")) if n]
        sensitive = sorted({n for n in names for p in policy["sensitive_paths"] if fnmatch.fnmatch(n, p)})
        limit = int(policy["small_change_lines"])
        if data.get("status") in ("ahead", "identical") and lines <= limit and not sensitive and len(files) < 300:
            return True, "PASS review of %s plus a small change since (%d lines)" % (reviewed[:12], lines)
        if data.get("status") not in ("ahead", "identical") and reviewed not in order:
            continue  # a receipt for a head the branch no longer has: try the next one
        why = []
        if data.get("status") not in ("ahead", "identical"):
            why.append("the branch was rewritten since (compare status %s)" % data.get("status"))
        if lines > limit:
            why.append("%d lines changed since (limit %d)" % (lines, limit))
        if sensitive:
            why.append("sensitive file(s) changed: " + ", ".join(sensitive[:5]))
        missing = "the PASS review covers %s, but %s; a review of the current head" % (reviewed[:12], "; ".join(why))
        break
    record = approval(repo, pr, head, payload, state_dir, policy, now)
    if record:
        return True, "approval %s" % clean(record.get("id") or record.get("approval_id") or "recorded", 60)
    return False, _ways(repo, pr, head, missing)


def evaluate(action, payload, state_dir, policy, runner=None, now=None):
    """(allowed, message) for one merge action. GitHub lookups that fail refuse, naming the failure."""
    now = now or time.time()
    look = Lookup(runner, policy["lookup_seconds"])
    if action.kind == "unknown_target":
        return False, ("merge-gate: refused: %s, so the gate cannot tell which PR it merges. Run it as one plain "
                       "command: gh pr merge <number> -R owner/repo" % action.why)
    try:
        if action.kind == "graphql":
            q = "query($id:ID!){node(id:$id){... on PullRequest{number repository{nameWithOwner}}}}"
            node = look.json(["gh", "api", "graphql", "-f", "query=" + q, "-f", "id=" + action.node], action.cwd)
            node = ((node.get("data") or {}).get("node") or {}) if isinstance(node, dict) else {}
            repo, number = (node.get("repository") or {}).get("nameWithOwner"), node.get("number")
            if not repo_key(repo) or not isinstance(number, int):
                raise GhError("the GraphQL pull request id %s did not resolve to a pull request" % action.node)
            action = Action("pr", repo=repo, target=str(number), cwd=action.cwd)
        if action.kind == "push":
            return _evaluate_push(action, payload, state_dir, policy, look, now)
        view = ["gh", "pr", "view"] + ([action.target] if action.target else []) + (
            ["-R", action.repo] if action.repo else []) + ["--json", "number,url,headRefOid,baseRefName,state,commits"]
        data = look.json(view, action.cwd)
        if not isinstance(data, dict):
            raise GhError("`gh pr view` returned no object")
    except GhError as error:
        return False, ("merge-gate: refused: could not read the pull request from GitHub (%s). Retry, or record a "
                       "waiver: python3 %s waive --repo owner/repo --pr N --reason \"<why>\"" % (error, GATE))
    url = PR_URL.match(str(data.get("url") or ""))
    head = str(data.get("headRefOid") or "").lower()
    if not url or not SHA.fullmatch(head):
        return False, "merge-gate: refused: GitHub returned no URL or head for the pull request; retry."
    if str(data.get("state") or "").upper() != "OPEN":
        return True, "the pull request is not open"
    commits = [str(c.get("oid") or "").lower() for c in data.get("commits") or [] if isinstance(c, dict)]
    if head not in commits:
        commits.append(head)
    return evaluate_pr(url.group(1), int(url.group(2)), head, str(data.get("baseRefName") or ""), commits, policy,
                       look, payload, state_dir, now)


def _evaluate_push(action, payload, state_dir, policy, look, now):
    cwd = action.cwd
    branch = action.branch
    if branch == "HEAD":
        branch = look.text(["git", "symbolic-ref", "--short", "HEAD"], cwd)
    branch = re.sub(r"^refs/heads/|^heads/", "", branch or "")
    if branch == "*all*":
        branch = next((b for b in policy["protected_branches"]
                       if look.text(["git", "rev-parse", "--verify", "-q", "refs/heads/" + b], cwd)), "")
        action.src = branch
    if branch not in [str(b) for b in policy["protected_branches"]]:
        return True, "push to an unprotected branch"
    remote = action.remote or look.text(["git", "config", "branch.%s.remote" % branch], cwd) or "origin"
    repo = slug_from_url(remote) or slug_from_url(look.text(["git", "remote", "get-url", "--push", remote], cwd))
    src = action.src if action.src not in ("", "HEAD") else "HEAD"
    head = look.text(["git", "rev-parse", "--verify", "-q", src + "^{commit}"], cwd).lower()
    if not repo or not SHA.fullmatch(head):
        log_line("push to %s allowed: remote or commit not readable here" % branch)
        return True, "push target not readable"
    tracking = "refs/remotes/%s/%s" % (remote, branch)
    if look.runner(["git", "merge-base", "--is-ancestor", head, tracking], cwd=cwd, timeout=look.left())[0] == 0:
        return True, "nothing new lands on %s" % branch
    try:
        prs = look.json(["gh", "pr", "list", "-R", repo, "--state", "open", "--base", branch, "--json",
                         "number,headRefOid", "--limit", "100"], cwd)
    except GhError:
        prs = []
    pr = next((p for p in prs if isinstance(p, dict) and str(p.get("headRefOid") or "").lower() == head), None)
    if pr:
        return evaluate_pr(repo, int(pr["number"]), head, branch, [head], policy, look, payload, state_dir, now)
    record = approval(repo, None, head, payload, state_dir, policy, now)
    if record:
        return True, "approval for head %s" % head[:12]
    return False, _ways(repo, None, head, "a pull request: a push to %s lands %s without one. Push a feature branch "
                        "and open a PR (gh pr create), then merge the reviewed PR" % (branch, head[:12]))


def may_waive(payload, repo):
    """Main agent, Fable/Astra, or a supervisor of a project whose checkout is this repo."""
    try:
        import ah_roles  # noqa: PLC0415
        if ah_roles.is_top_rung(payload):
            return True
        for root in ah_roles.supervised_roots(payload):
            url = run(["git", "-C", str(root), "remote", "get-url", "origin"], timeout=3)[1].strip()
            if repo and repo_key(slug_from_url(url)) == repo_key(repo.strip()):
                return True
    except Exception:
        pass
    try:
        import caller_identity  # noqa: PLC0415
        if caller_identity.is_main(payload):
            return True
        from native_main import is_desktop_review_root  # noqa: PLC0415
        return is_desktop_review_root(payload) is True
    except Exception:
        return False


def decide(payload, state_dir, runner=None, policy=None, now=None):
    """(exit code, message) for one PreToolUse payload."""
    policy = policy or load_policy()
    tool = str(payload.get("tool_name") or "").lower()
    if tool not in SHELL_TOOLS and not tool.startswith(("bash", "shell", "exec")):
        return 0, ""
    value = (payload.get("tool_input") or {}).get("command") if isinstance(payload.get("tool_input"), dict) else None
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        value = value[2] if len(value) >= 3 and os.path.basename(value[0]) in SHELLS and value[1].endswith("c") \
            else " ".join(shlex.quote(v) for v in value)
    if not isinstance(value, str) or not HINT.search(value):
        return 0, ""
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    try:
        actions = analyse(value, cwd, policy)
    except Unsure as why:
        log_line("allowed without checking: %s" % why)
        return 0, ""
    for action in actions:
        if action.kind == "waive":
            if not may_waive(payload, action.repo):
                return 2, ("merge-gate: only the main agent, Fable/Astra or a supervisor of %s may record a merge "
                           "waiver. Ask one of them, or the user, to run it." % (action.repo or "the repo"))
            continue
        allowed, message = evaluate(action, payload, state_dir, policy, runner, now)
        log_line("%s %s: %s" % ("allow" if allowed else "REFUSE", action.kind, message.splitlines()[0]), stderr=False)
        if not allowed:
            return 2, message
    return 0, ""


# ------------------------------------------------------------------------------------------------ waivers

def default_state_dir():
    return Path.home() / ".agent-harness" / "state"


def read_waivers(state_dir):
    rows = []
    try:
        with open(Path(state_dir) / WAIVER_FILE, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 8 * 1024 * 1024))
            for line in handle.read(8 * 1024 * 1024).decode("utf-8", "replace").splitlines()[-5000:]:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except OSError:
        pass
    return rows


def normalise_repo(value):
    text = str(value or "").strip()
    text = re.sub(r"^(?:https?://)?(?:www\.)?github\.com[:/]+", "", text).strip("/")
    text = re.sub(r"\.git$", "", text)
    text = re.sub(r"/pull/\d+.*$", "", text)
    return text.lower()


def add_waiver(state_dir, repo, pr=None, head=None, reason="", approved_by="", ticket=None, now=None):
    """Record a waiver; normalises instead of refusing. Only a missing repo, or neither PR nor head, is an error."""
    repo = normalise_repo(repo)
    if not repo_key(repo):
        raise ValueError("--repo must name the GitHub repository, e.g. owner/name")
    if isinstance(pr, str):
        digits = re.sub(r"\D", "", pr)
        pr = int(digits) if digits else None
    pr = pr if isinstance(pr, int) and pr > 0 else None
    head = (str(head).strip().lower() or None) if head else None
    if pr is None and not head:
        raise ValueError("name the pull request (--pr N) or an exact commit (--head SHA)")
    try:
        import redact  # noqa: PLC0415
        reason = redact.redact(reason)
    except Exception:
        pass
    reason = clean(str(reason or "").strip() or "(no reason given)", REASON_CAP)
    approved_by = clean(str(approved_by or "").strip() or os.environ.get("USER") or "unknown", 200)
    record = {"event": "waive", "id": "mgw-" + uuid.uuid4().hex[:12], "ts": now or time.time(), "repo": repo,
              "pr": pr, "head": head, "reason": reason, "approved_by": approved_by,
              "ticket": clean(ticket, 200) if ticket else None}
    folder = Path(state_dir)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(folder / WAIVER_FILE), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return record


# ---- used by peer_review.py (verify_pr_binding and its stamped path); keep the names stable ----

class Corrupt(Exception):
    """Kept for peer_review.py's except clause; nothing here raises it any more."""


GateError = GhError


class SubprocessGh:
    """gh runner with peer_review's call shape: (args without 'gh', timeout, cwd) -> (code, stdout, stderr)."""

    def __call__(self, args, timeout, cwd=None):
        return run(["gh"] + list(args), cwd=cwd, timeout=timeout)


class Client:
    """peer_review.verify_pr_binding's JSON reader over a SubprocessGh-shaped runner."""

    def __init__(self, runner, deadline, cwd=None):
        self.runner, self.deadline, self.cwd = runner, deadline, cwd

    def json(self, args, what):
        code, out, err = self.runner(list(args), max(0.5, self.deadline - time.monotonic()), self.cwd)
        if code:
            raise GateError("could not read %s: %s" % (what, clean(err or out or code, 160)))
        try:
            return json.loads(out)
        except ValueError:
            raise GateError("%s is not JSON" % what) from None


def report_text(state_dir, policy):
    ttl = float(policy["waiver_ttl_hours"]) * 3600
    rows = [r for r in read_waivers(state_dir) if r.get("event") == "waive"][-30:]
    lines = ["Merge gate waivers (newest last; each covers its PR for %g h)" % (ttl / 3600)]
    for r in rows:
        state = "active" if time.time() < float(r.get("ts") or 0) + ttl else "expired"
        target = ("#%s" % r["pr"]) if r.get("pr") else ""
        head = (" head %s" % str(r["head"])[:12]) if r.get("head") else ""
        lines.append("  %s %s%s%s %s by %s: %s" % (r.get("id"), r.get("repo"), target, head, state,
                                                   clean(r.get("approved_by"), 60), clean(r.get("reason"), 120)))
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------ entry points

def hook_main(state_dir, stdin=None, stdout=None, stderr=None, runner=None):
    stdin = stdin or sys.stdin.buffer
    stderr = stderr or sys.stderr
    try:
        raw = stdin.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            log_line("allowed without checking: hook input larger than %d bytes" % MAX_INPUT)
            return 0
        payload = json.loads(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw)
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
    except (ValueError, OSError) as error:
        log_line("allowed without checking: hook input unreadable (%s)" % type(error).__name__)
        return 0
    try:
        code, message = decide(payload, state_dir, runner=runner)
    except Exception as error:  # a bug in the gate never blocks a command
        log_line("allowed without checking: gate error %s: %s" % (type(error).__name__, clean(error, 120)))
        return 0
    if code:
        stderr.write(message.rstrip() + "\n")
    return code


def main(argv=None, runner=None, stdin=None, stdout=None, stderr=None):
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    parser = argparse.ArgumentParser(description="PR merge gate: hook, check, waive, report.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("hook", "report", "check", "waive"):
        p = sub.add_parser(name)
        p.add_argument("--state-dir", default=None)
        if name == "check":
            p.add_argument("--repo", required=True)
            p.add_argument("--pr", required=True)
        if name == "waive":
            p.add_argument("--repo", required=True)
            p.add_argument("--pr", default=None)
            p.add_argument("--head", default=None)
            p.add_argument("--reason", default="")
            p.add_argument("--approved-by", default="")
            p.add_argument("--ticket", default=None)
    args, extra = parser.parse_known_args(argv)
    state_dir = Path(args.state_dir).expanduser() if args.state_dir else default_state_dir()
    if args.command == "hook":
        if hasattr(signal, "SIGALRM") and stdin is None:
            policy = load_policy()

            def expired(signum, frame):
                log_line("allowed without checking: the hook ran out of time")
                os._exit(0)
            signal.signal(signal.SIGALRM, expired)
            signal.alarm(int(float(policy["analyser_seconds"]) + float(policy["lookup_seconds"])) + 3)
        return hook_main(state_dir, stdin, stdout, stderr, runner)
    if extra:
        stderr.write("merge-gate: ignoring unknown arguments: %s\n" % clean(" ".join(extra), 120))
    policy = load_policy()
    if args.command == "report":
        stdout.write(report_text(state_dir, policy) + "\n")
        return 0
    if args.command == "check":
        repo, digits = normalise_repo(args.repo), re.sub(r"\D", "", str(args.pr))
        allowed, message = evaluate(Action("pr", repo=repo, target=digits), {}, state_dir, policy, runner)
        stdout.write(("merge-gate: allowed (%s)\n" % message) if allowed else message + "\n")
        return 0 if allowed else 2
    try:
        record = add_waiver(state_dir, args.repo, args.pr, args.head, args.reason, args.approved_by, args.ticket)
    except (ValueError, OSError) as error:
        stderr.write("merge-gate: waiver not recorded: %s\n" % error)
        return 3
    target = ("#%s" % record["pr"]) if record["pr"] else " head %s" % record["head"][:12]
    stdout.write("merge-gate: waiver %s recorded for %s%s; it covers that %s for %g h.\n" % (
        record["id"], record["repo"], target, "PR" if record["pr"] else "commit", float(policy["waiver_ttl_hours"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
