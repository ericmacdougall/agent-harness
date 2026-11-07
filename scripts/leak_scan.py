#!/usr/bin/env python3
"""Scan a repository for secrets and personal strings before it is published.

    python3 scripts/leak_scan.py [--repo DIR] [--history] [--denylist FILE]

Checks tracked files (or, with --history, every added line in every commit) against
built-in generic patterns (tokens, private keys, real home-directory names, tailnet
names, private IPv4 addresses) and a local denylist of regexes, one per line, that
holds your own personal strings. The denylist is never committed: by default it is
read from $AGENT_HARNESS_LEAK_DENYLIST or ~/.agent-harness/leak-denylist.txt, and CI
can supply it from a repository secret. Matched text is never printed, only
file:line and the rule name, so a log cannot itself leak the value.

Exit 0 clean, 1 findings, 2 nothing was scanned, a usage/IO/denylist error, or (tree mode) a tracked file
that could not be scanned: binary, over the size cap, or not a regular file when read (never a silent pass).
--history diffs binary blobs as text (git log -a); a skip it still counts does not fail the run, since the
tree scan gates what is committed now.
Allowlisted fixture paths skip the token rules only; network and personal-string rules always apply.
Placeholder names (someone, you, runner, user, example.invalid ...) are allowed.
"""
from __future__ import annotations

import argparse
import stat
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

PLACEHOLDER_USERS = {"someone", "you", "x", "u", "user", "username", "name", "runner", "me", "shared",
                     "test", "tester", "example", "home", "your-name", "yourname", "alice", "bob",
                     "cgremote", "remoteuser", "local"}  # synthetic names used by the command-guard and doctor tests
IPV4 = r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}\.\d{1,3}(?![\d.])"
TOKEN_RULES = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-style-key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),  # header alone: PEM bodies sit on later lines
]
# Network rules always apply, including to allowlisted fixture paths: a test file is exactly where a
# real private address once slipped in (FINDINGS F-008).
NETWORK_RULES = [
    ("tailnet-name", re.compile(r"\.ts\.net\b")),
    ("private-ipv4", re.compile(IPV4)),
]
RULES = TOKEN_RULES + NETWORK_RULES
HOME_PATH = re.compile(r"(?:/Users/|/home/|C:\\Users\\)([A-Za-z0-9][A-Za-z0-9._-]*)")
# Well-known fake credentials used in docs and tests (AWS documentation values).
KNOWN_FAKE = ("AKIAIOSFODNN7EXAMPLE", "AKIAABCDEFGHIJKLMNOP")
ALLOW_FILE = ".leakscan-allow"
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".zip", ".gz", ".woff", ".woff2", ".pdf"}
MAX_BYTES = 2_000_000


class ScanError(Exception):
    """A usage or IO problem. Exit 2, never 1, so a misconfiguration cannot be mistaken for a leak."""


def load_denylist(path: Path | None) -> list[tuple[str, re.Pattern]]:
    """An explicitly named denylist (--denylist or the environment variable) must exist and hold rules.
    Only the default location may be absent, and then the scan runs on the generic rules alone."""
    explicit = path or (Path(os.environ["AGENT_HARNESS_LEAK_DENYLIST"]) if os.environ.get("AGENT_HARNESS_LEAK_DENYLIST") else None)
    if explicit is not None and not explicit.is_file():
        raise ScanError(f"denylist {explicit} does not exist")
    candidates = [explicit] if explicit else [Path.home() / ".agent-harness" / "leak-denylist.txt"]
    for candidate in candidates:
        if candidate and candidate.is_file():
            rules = []
            for number, line in enumerate(candidate.read_text(encoding="utf-8").splitlines(), 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        rules.append((f"denylist#{number}", re.compile(line)))
                    except re.error as error:
                        raise ScanError(f"denylist line {number} is not a valid regex: {error}")
            if not rules:
                raise ScanError(f"denylist {candidate} holds no rules (an empty denylist checks nothing)")
            return rules
    return []


def check_line(line: str, denylist, token_rules: bool = True) -> list[str]:
    for fake in KNOWN_FAKE:
        line = line.replace(fake, "")
    hits = [name for name, pattern in NETWORK_RULES if pattern.search(line)]
    hits += [name for name, pattern in TOKEN_RULES if token_rules and pattern.search(line)]
    for match in HOME_PATH.finditer(line):
        if match.group(1).lower() not in PLACEHOLDER_USERS:
            hits.append("home-directory-name")
            break
    hits += [name for name, pattern in denylist if pattern.search(line)]
    return hits


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if done.returncode:
        raise ScanError(f"git {args[0]} failed: {done.stderr.decode(errors='replace')[:200]}")
    return done.stdout


def label(path: str, denylist) -> str:
    """The path to print. A path that itself matches a rule (a denylisted name, a home directory, a tailnet host)
    is shown as a hash prefix, so the report never carries the value it flags."""
    if check_line(path, denylist, True) or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return "path#" + hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()[:10]
    return path


def load_allow(repo: Path) -> list[str]:
    """Path globs of fixtures that hold deliberately fake tokens (redaction corpora). They skip the
    built-in token rules only: the denylist and the home-directory rule still apply to them."""
    path = repo / ALLOW_FILE
    if not path.is_file():
        return []
    patterns = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]
    for pattern in patterns:  # a pattern such as * would switch the token rules off for the whole repository
        if any(c in pattern for c in "*?[") or pattern.startswith("/"):
            raise ScanError(f"{ALLOW_FILE}: pattern {pattern!r} is not an exact path; globs are not accepted")
    return patterns


def read_capped(path: Path):
    """The file's bytes, or None when it is not a regular file or is over MAX_BYTES. Opens once, checks the
    opened file with fstat and reads at most MAX_BYTES + 1, so an oversized or growing file is never buffered
    whole (audit2 F-018, goodqa#14999). O_NONBLOCK keeps a FIFO swapped in after the is_file check from hanging."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return None
        chunks, total = [], 0
        while total <= MAX_BYTES:
            chunk = os.read(fd, MAX_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return None if total > MAX_BYTES else b"".join(chunks)
    finally:
        os.close(fd)


def scan_tree(repo: Path, denylist):
    """Returns (findings, scanned, skipped). Skipped files (binary, over the size cap) are counted, not hidden."""
    findings, scanned, skipped = [], 0, 0
    allow = load_allow(repo)
    for name in git(repo, "ls-files", "-z").decode("utf-8", "surrogateescape").split("\0"):
        if not name:
            continue
        findings += [(f"path:{label(name, denylist)}", rule) for rule in check_line(name, denylist, True)]
        path = repo / name
        tokens = not name in allow
        if path.is_symlink():  # the target string is what is committed
            scanned += 1
            findings += [(f"{label(name, denylist)}:symlink", rule) for rule in check_line(os.readlink(path), denylist, tokens)]
            continue
        if not path.is_file():
            continue
        try:
            raw = read_capped(path)
        except OSError as error:
            raise ScanError(f"{label(name, denylist)}: cannot read ({error.strerror or error.__class__.__name__})")
        if raw is None or b"\0" in raw:
            skipped += 1
            continue
        scanned += 1
        for number, line in enumerate(raw.decode("utf-8", "replace").split("\n"), 1):
            findings += [(f"{label(name, denylist)}:{number}", rule) for rule in check_line(line, denylist, tokens)]
    return findings, scanned, skipped


def scan_history(repo: Path, denylist, rev_range: str | None = None):
    """Every added line in every commit, merge commits included (-m --first-parent shows what a merge changed)."""
    findings, scanned, skipped = [], 0, 0
    allow = load_allow(repo)
    log = git(repo, "-c", "core.quotePath=false", "log", *([rev_range] if rev_range else ["--all"]), "-p", "-U0",
              "--diff-merges=first-parent", "--no-color", "-a", "--no-textconv", "--format=\x01%h", "--no-ext-diff")
    # -z ends each record with NUL, a byte git cannot store in a message or name; any printable or control
    # delimiter (the previous \x01) could be smuggled inside a message to hide the text after it.
    meta = git(repo, "log", *([rev_range] if rev_range else ["--all"]), "-z", "--format=%h%n%an %ae %cn %ce%n%B")
    for entry in meta.decode("utf-8", "replace").split("\0"):
        sha, _, text = entry.lstrip("\n").partition("\n")
        for line in text.split("\n"):
            findings += [(f"{sha}:commit-message", rule) for rule in check_line(line, denylist, True)]
    commit = path = ""
    in_hunk = False
    # Split on newline only: str.splitlines also breaks on CR, FF, VT, NEL and U+2028, which would hide
    # content after such a character and let it corrupt the hunk state.
    for raw in log.decode("utf-8", "replace").split("\n"):
        if raw.startswith("\x01"):
            commit, scanned, in_hunk = raw[1:], scanned + 1, False
        elif raw.startswith("diff --git "):
            in_hunk = False  # headers follow; an added line that looks like "+++ x" is only content once a hunk starts
        elif not in_hunk and raw.startswith(("rename to ", "copy to ")):
            path = raw.split(" to ", 1)[1]  # a pure rename has no +++ line
            findings += [(f"{commit}:path:{label(path, denylist)}", rule) for rule in check_line(path, denylist, True)]
        elif not in_hunk and raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else raw[4:]
            findings += [(f"{commit}:path:{label(path, denylist)}", rule) for rule in check_line(path, denylist, True)]
        elif not in_hunk and raw.startswith("Binary files ") and raw.endswith(" differ"):
            skipped += 1
        elif raw.startswith("@@"):
            in_hunk = True
        elif in_hunk and raw.startswith("+"):
            tokens = not path in allow
            findings += [(f"{commit}:{label(path, denylist)}", rule) for rule in check_line(raw[1:], denylist, tokens)]
    return findings, scanned, skipped


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--history", action="store_true", help="scan every added line in all history")
    parser.add_argument("--range", dest="rev_range", help="with --history, only this git range (e.g. origin/main..HEAD)")
    parser.add_argument("--denylist", type=Path)
    parser.add_argument("--require-denylist", action="store_true",
                        help="exit 2 unless a non-empty denylist was loaded (the pre-push gate sets this)")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        denylist = load_denylist(args.denylist)
        if args.require_denylist and not denylist:
            raise ScanError("no denylist found; create one or pass --denylist (generic rules alone cannot catch personal names)")
        skipped = 0
        if args.history:
            findings, scanned, skipped = scan_history(repo, denylist, args.rev_range)
        else:
            findings, scanned, skipped = scan_tree(repo, denylist)
    except ScanError as error:
        print(f"leak_scan: {error}", file=sys.stderr)
        return 2
    if not scanned:
        print("leak_scan: nothing was scanned (empty repo?); refusing to report a pass", file=sys.stderr)
        return 2
    for where, rule in dict.fromkeys(findings):
        print(f"LEAK {where} rule={rule}")
    print(f"leak_scan: {'history commits' if args.history else 'files'} scanned={scanned} "
          f"denylist_rules={len(denylist)} skipped={skipped} findings={len(set(findings))}")
    if findings:
        return 1
    if skipped and not args.history:
        print("leak_scan: incomplete scan: skipped tracked files need a separate review; refusing to report a pass",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
