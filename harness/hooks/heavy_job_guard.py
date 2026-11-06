#!/usr/bin/env python3
"""PreToolUse(Bash) guard: keep heavy and runaway work off the user's Mac.

2026-11-04: a hostile-input test (a hook child reading /dev/zero) grew to ~66 GB
and macOS jetsam hard-reset the machine; earlier a local Playwright sweep also
spawned ~84 Chrome renderers. The standing rule is "heavy jobs run on dev2";
this hook is the front door that enforces it, and run_capped.py is the runtime
cap for the work that really must run on the Mac.

Contract
- stdin: Claude Code PreToolUse payload. Deny = exit 2 + message on stderr.
- Fails OPEN: malformed input, deep JSON, any internal error -> exit 0 and a
  logged warning. Register it WITHOUT onFailure=block.
- Only acts on macOS (dev2 is Linux); HARNESS_HEAVY_GUARD_FORCE=1 overrides for tests.
- Escape hatch: prefix the command with HARNESS_LOCAL_OK=<reason>; the reason is
  logged to the session WAL. Browser, adversarial, media and fan-out work must
  ALSO run under run_capped.py; suites and builds only need the hatch.
- Rules: browser, adversarial (hostile-input/fuzz scripts, /dev/zero, mkfifo,
  perl alarm wrappers, scratchpad rt/ scripts), full-suite, build, media, fan-out.
  Big jobs are fine on dev2; nothing here caps them. On the Mac, run_capped.py's cap
  PAUSES a runaway and alerts (netwatch kills only as a last resort).
  Default enforce for browser, full-suite and build (route to dev2); warn for media and
  fan-out; adversarial is advisory ONLY (never denied: breaking things with hostile input
  is the red team's job; the advice is dev2 or run_capped.py group cleanup). Override with
  HARNESS_HEAVY_GUARD=off|warn|enforce or heavy_job_guard.json next to this
  file: {"modes": {"media": "enforce"}}.
- Build tools (goodqa#14459): make/gmake (test|tests|check targets = full-suite; all|build|install|package|dist|release
  and a bare `make` = build), gradle/gradlew (test/check/verify/connected*Test = full-suite; build/assemble/bundle/
  install*/jar/war/publish* = build), mvn/mvnw/mvnd (test, verify, integration-test = full-suite; package, install,
  compile, deploy, site = build), bazel/bazelisk (test, coverage = full-suite; build = build) and xcodebuild (test =
  full-suite; build, archive, or no action = build). Light forms stay allowed: help, clean, version/info/query
  output, `gradle tasks`, `xcodebuild -list`. Filtered forms (`gradle test --tests X`, `mvn -Dtest=X test`) are still
  denied because these tools configure the whole project first. `make -n`/`--dry-run`/`--just-print` is allowed: it only
  prints the recipe (GNU make still executes recipe lines that invoke $(MAKE) under -n; accepted for a careless agent).
  These are also seen through xcrun, script, and `bash ./gradlew ...` / `sh mvnw ...` script launches.
  Wrapper chains deeper than MAX_WRAPPER_DEPTH (12) are denied as "too deep to analyse", even when they end in `ls`.

Threat model: a CARELESS agent, not a hostile one. Wrapper and shell syntax (env/sudo/su/watch/nohup chains, ANSI-C
quotes, eval) is parsed conservatively, with an unparseable form scanned word by word and denied on any heavy
command (a false denial names HARNESS_LOCAL_OK and dev2; a false allow is the bug). Deliberate obfuscation is
best-effort and out of scope: command substitution such as `$(which pytest)`, variable indirection (`p=pytest; $p`),
scripts that launch heavy work internally, and aliases. The runtime backstops (run_capped.py, netwatch) cover those.

Size bounds (GoodQA #14505): a command over 1 MB, more than 256 KiB of text after heredoc bodies are removed, or one
command of more than 2048 words is denied as rule "oversize" (fail closed: the unscanned part could hide a heavy job).
HARNESS_LOCAL_OK does NOT override it; write the work to a script file instead. Tokenizing is linear (posix_split).

Classification looks at the command word of each shell segment, never at quoted
text, so `git commit -m "run pytest"` or `grep pytest` are never flagged.
Stdlib only, Python 3.9 compatible, lazy imports to keep startup small.
"""
from __future__ import annotations

import os
import re
import stat
import time
import sys

MAX_COMMAND_CHARS = 1_000_000
MAX_SCAN_CHARS = 256 * 1024  # command text left after heredoc bodies are removed; ~0.3 s worst case, linear
MAX_SEGMENT_WORDS = 8192  # words in one shell command; bounds the quadratic wrapper-slicing paths
MAX_NESTED_SECONDS = 0.4  # wall-clock budget per decision for nested scans and uncertain-wrapper probes
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
DEFAULT_MODES = {"browser": "enforce", "adversarial": "warn", "full-suite": "enforce",
                 "build": "enforce", "media": "warn", "fan-out": "enforce", "oversize": "enforce", "copy": "enforce",
                 "install": "enforce", "replay": "enforce", "container": "enforce"}
CAPPED_RULES = {"browser", "media", "fan-out"}  # memory hogs: hatch alone is not enough
NEVER_BLOCK = {"adversarial"}  # red-team/fuzz work is legitimate: advise (dev2, group cleanup), never deny
HATCH = "HARNESS_LOCAL_OK"
LOG_PATH = os.path.join(os.path.expanduser("~"), ".agent-harness", "logs", "heavy-job-guard.jsonl")

RULE_HELP = {
    "browser": "browser automation (Playwright/Puppeteer/headless Chrome) can spawn dozens of renderers",
    "adversarial": "hostile-input, fuzz or unbounded-read test code can grow without limit",
    "full-suite": "a full test suite is long and CPU/memory heavy",
    "build": "a production build is CPU/memory heavy",
    "media": "large media work (ffmpeg/whisper) is CPU/memory heavy",
    "fan-out": "parallel fan-out multiplies memory use",
    "install": "a package install (pnpm/npm/yarn/bun) writes and unpacks thousands of files",
    "replay": "a replay, synthetic or load script drives many requests and processes",
    "container": "docker/podman images and containers use gigabytes of disk and memory",
    "copy": "a large copy, clone or worktree fills the Mac disk (it sits near full; work/pp407 grew 9 GB/h this way)",
    "oversize": "the guard cannot scan this whole command, so a heavy job could hide in the part it skips; "
                "write it to a script file and run that (HARNESS_LOCAL_OK does not override this rule)",
}


# ---------------------------------------------------------------- input safety

def load_json_file(path: str, max_bytes: int = 64 * 1024):
    """A small trusted-location config file, still read through safe_input (regular files only, size and depth bounded)."""
    import safe_input
    return safe_input.safe_json_loads(safe_input.read_bounded(path, max_bytes), max_depth=20, max_bytes=max_bytes)


def parse_payload(data: bytes):
    import safe_input
    return safe_input.safe_json_loads(data, max_depth=100, max_bytes=8 * 1024 * 1024)


# ---------------------------------------------------------------- shell scanning

HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][\w.-]*)\2")


def extract_heredocs(text: str):
    """Return (text without heredoc bodies, [bodies]). Unterminated heredocs are left alone.

    Terminator lookup uses a line->indices map built once per mode and bisect, so any number of distinct
    (possibly missing) terminators costs O(lines log lines), not a rescan of every remaining line each (#14505)."""
    from bisect import bisect_left
    lines = text.split("\n")
    out, bodies, i = [], [], 0
    index = {False: None, True: None}  # strip_tabs -> {line text: [line numbers]}
    missing = set()  # terminators proven absent (keyed by text alone, as before: behaviour is unchanged)

    def find(term, start, strip_tabs):
        if index[strip_tabs] is None:
            table = {}
            for number, line in enumerate(lines):
                table.setdefault(line.strip() if strip_tabs else line, []).append(number)
            index[strip_tabs] = table
        found = index[strip_tabs].get(term, ())
        k = bisect_left(found, start)
        return found[k] if k < len(found) else len(lines)

    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for match in HEREDOC.finditer(line):
            if line[max(0, match.start() - 1):match.start()] == "<":  # here-string <<<
                continue
            strip_tabs, term = match.group(1) == "-", match.group(3)
            if term in missing:
                continue
            j = find(term, i, strip_tabs)
            if j < len(lines):
                bodies.append("\n".join(lines[i:j]))
                i = j + 1
            else:
                missing.add(term)
    return "\n".join(out), bodies


def split_segments(text: str):
    """Split on ; && || | & newline and ( ) ` outside quotes."""
    text = text.replace("\\\n", " ")
    segments, buf, quote, i, n = [], [], None, 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch == "\\" and i + 1 < n:
            buf.append(ch + text[i + 1])
            i += 1
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == "#" and (not buf or buf[-1] in " \t"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif ch in ";\n|()`" or (ch == "&" and not (i > 0 and text[i - 1] in "<>") and text[i + 1:i + 2] != ">"):
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")


_WS = " \t\r\n"


def posix_split(text: str):
    """Linear equivalent of shlex.split(text) (posix, whitespace_split, no comments); same ValueError cases.

    GoodQA #14505: shlex builds a token with `self.token += ch`, which is quadratic in CPython 3.9, so a
    single 1 MB token hung every hook for 100 s+. This keeps the same quoting rules with list appends."""
    out, buf, have, i, n = [], [], False, 0, len(text)
    while i < n:
        ch = text[i]
        i += 1
        if ch in _WS:
            if have:
                out.append("".join(buf))
                buf, have = [], False
        elif ch == "\\":
            if i >= n:
                raise ValueError("No escaped character")
            buf.append(text[i])
            i += 1
            have = True
        elif ch == "'":
            end = text.find("'", i)
            if end < 0:
                raise ValueError("No closing quotation")
            buf.append(text[i:end])
            i, have = end + 1, True
        elif ch == '"':
            have = True
            while True:
                if i >= n:
                    raise ValueError("No closing quotation")
                c = text[i]
                i += 1
                if c == '"':
                    break
                if c == "\\":
                    if i >= n:
                        raise ValueError("No escaped character")
                    nxt = text[i]
                    i += 1
                    buf.append(nxt if nxt in '"\\' else "\\" + nxt)
                else:
                    buf.append(c)
        else:
            buf.append(ch)
            have = True
    if have:
        out.append("".join(buf))
    return out


def tokenize(segment: str):
    import shlex
    if "$'" in segment:  # bash ANSI-C quoting: $'pytest\t-x' is one word containing a tab
        import codecs

        def decode(match):
            try:
                return shlex.quote(codecs.decode(match.group(1).encode("latin-1", "replace"), "unicode_escape"))
            except (UnicodeError, ValueError):
                return shlex.quote(match.group(1))
        segment = ANSI_C.sub(decode, segment)
    try:
        return posix_split(segment)
    except ValueError:
        return segment.split()


ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def split_assignments(argv):
    i = 0
    while i < len(argv) and ASSIGN.match(argv[i]):
        i += 1
    return argv[:i], argv[i:]


def base(word: str) -> str:
    return os.path.basename(word.rstrip("/"))


def positional(args, value_flags=()):
    """Non-flag tokens, skipping the value of known value-taking flags."""
    out, skip = [], False
    for token in args:
        if skip:
            skip = False
        elif token in value_flags:
            skip = True
        elif not token.startswith("-"):
            out.append(token)
    return out


# ---------------------------------------------------------------- large copies (P12 / goodqa#14817)
# 2026-11-05: work/pp407 grew ~9 GB/h on the Mac from cp, tar, rsync, git clone and worktree review trees (one release
# clone was 6.7 GB) with the disk at 94%. A copy is classified by ESTIMATED size, never by command name alone:
# a bounded walk of the local source, `ssh host du` for a remote source, the GitHub repo size for a clone. At or above
# the threshold (default 1 GiB, HARNESS_COPY_GIB) it is routed to dev2/T2. A source that cannot be measured inside
# its time bound counts as heavy (unknown = heavy on an interactive host), except a shallow/filtered clone.

GIB = 1024 ** 3
COPY_WALK_SECONDS = 1.0
COPY_WALK_ENTRIES = 300_000
REMOTE_SPEC = re.compile(r"^(?:[\w.+-]+@)?(?:\[[0-9a-fA-F:]+\]|[\w.-]+):(?!//)")
GITHUB_URL = re.compile(r"(?:github\.com[:/])([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
GH_SLUG = re.compile(r"^([\w.-]+)/([\w.-]+)$")
COMPRESSED = re.compile(r"\.(?:t?gz|bz2|tbz2?|xz|txz|zst|lz4|lzma|z)$", re.I)


def copy_threshold_bytes() -> int:
    value = 1.0
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy_job_guard.json")
        if os.path.exists(path):
            value = float(load_json_file(path).get("copy_gib", value))
    except Exception:
        pass
    env = os.environ.get("HARNESS_COPY_GIB", "")
    if re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,3})?", env):
        value = float(env)
    return int(max(value, 0.001) * GIB)


def path_size(path: str, cap: int = None, seconds: float = COPY_WALK_SECONDS):
    """(bytes on disk, complete). Symlinks are not followed, hard links count once, the walk stops at `cap` bytes
    (a known lower bound is enough to call a copy heavy) or at the time/entry bound (complete=False)."""
    deadline = time.monotonic() + seconds
    total, seen, entries, stack = 0, set(), 0, [path]
    while stack:
        current = stack.pop()
        try:
            st = os.lstat(current)
        except OSError:
            continue
        entries += 1
        if stat.S_ISDIR(st.st_mode):
            if entries > COPY_WALK_ENTRIES or time.monotonic() > deadline:
                return total, False
            try:
                with os.scandir(current) as it:
                    stack.extend(e.path for e in it)
            except OSError:
                pass
            continue
        if st.st_nlink > 1:
            if (st.st_dev, st.st_ino) in seen:
                continue
            seen.add((st.st_dev, st.st_ino))
        total += getattr(st, "st_blocks", 0) * 512 or st.st_size
        if cap is not None and total >= cap:
            return total, True
        if entries > COPY_WALK_ENTRIES or time.monotonic() > deadline:
            return total, False
    return total, True


def measured_hosts():
    """Hosts the guard may `ssh du` to size a remote source: the fleet (dev2/T2) plus heavy_job_guard.json
    "measure_hosts". Any other host is not contacted and its source is not counted."""
    hosts = {"dev2", "t2", "t2-dev"}
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy_job_guard.json")
        if os.path.exists(path):
            hosts |= {h for h in load_json_file(path).get("measure_hosts", []) if isinstance(h, str)}
    except Exception:
        pass
    return hosts


def remote_path_size(spec: str):
    """Bytes of host:path via a read-only `ssh host du -sk`, bounded to 4 s; None when it cannot be measured."""
    import subprocess
    host, _, remote = spec.partition(":")
    if not remote or remote.startswith("-") or host.startswith("-") or host.rpartition("@")[2] not in measured_hosts():
        return None  # a PreToolUse hook runs before the user approves: only ever connect to the user's own fleet
    try:
        out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", "--", host, "du", "-sk", "--", remote],
                             capture_output=True, text=True, timeout=4).stdout
        first = out.split("\t", 1)[0].strip()
        return int(first) * 1024 if first.isdigit() else None
    except Exception:
        return None


def github_repo_bytes(owner: str, repo: str):
    """GitHub's reported repository size (KiB -> bytes), cached 24 h; None when unknown (offline, no auth)."""
    import json
    import subprocess
    key = f"{owner}/{repo}".lower()
    cache_path = os.path.join(state_dir(), "repo-size-cache.json")
    cache = {}
    try:
        cache = load_json_file(cache_path, 1024 * 1024)
        hit = cache.get(key)
        if isinstance(hit, dict) and time.time() - float(hit.get("at", 0)) < 86400:
            return int(hit["bytes"])
    except Exception:
        cache = {}
    try:
        out = subprocess.run(["gh", "api", f"repos/{owner}/{repo}", "--jq", ".size"], capture_output=True, text=True,
                             timeout=2.5).stdout.strip()
        if not out.isdigit():
            return None
        size = int(out) * 1024
        cache[key] = {"bytes": size, "at": time.time()}
        os.makedirs(state_dir(), mode=0o700, exist_ok=True)
        tmp = f"{cache_path}.{os.getpid()}.tmp"
        with open(tmp, "w") as handle:
            json.dump(dict(list(cache.items())[-500:]), handle)
        os.replace(tmp, cache_path)
        return size
    except Exception:
        return None


def tracked_tree_bytes(repo_dir: str):
    """Sum of blob sizes at HEAD (what `git worktree add` checks out); None if git cannot say within 2 s."""
    import subprocess
    try:
        env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
        out = subprocess.run(["git", "-C", repo_dir, "ls-tree", "-r", "-l", "HEAD"], capture_output=True, text=True,
                             timeout=2, env=env).stdout
        total = 0
        for line in out.splitlines():
            meta = line.split("\t", 1)[0].split()
            if len(meta) == 4 and meta[3].isdigit():
                total += int(meta[3])
        return total
    except Exception:
        return None


def fmt_gib(n: float) -> str:
    return f"{n / GIB:.1f} GiB" if n >= GIB // 10 else f"{n / 1048576:.1f} MiB"


def sum_sources(sources, ctx, thr, remote_ok=False, deref=False, budget_s=2.5):
    """(bytes, unmeasured_detail) over local and (scp/rsync only) host:path sources, stopping at the threshold.

    The whole sizing is bounded by budget_s so a glob of many matches or several slow remotes cannot stall the hook;
    running out of time counts as unmeasurable (heavy). A remote host outside the fleet is not contacted (the hook
    runs before the user approves) and its source is not counted."""
    import glob as globmod
    started = time.monotonic()
    total = 0
    for src in sources:
        if time.monotonic() - started > budget_s:
            return total, f"sizing took longer than {budget_s:g}s"
        if remote_ok and REMOTE_SPEC.match(src) and not src.startswith(("/", ".", "~")):
            if src.partition(":")[0].rpartition("@")[2] not in measured_hosts():
                continue
            size = remote_path_size(src)
            if size is None:
                return total, f"cannot measure {src.split(':')[0]}:... within the time bound"
            total += size
        else:
            path = resolve(os.path.expanduser(src), ctx.cwd)
            paths = globmod.glob(path)[:500] if any(c in path for c in "*?[") else [path]
            for one in paths:
                if time.monotonic() - started > budget_s:
                    return total, f"sizing took longer than {budget_s:g}s"
                if deref and os.path.islink(one):
                    one = os.path.realpath(one)  # cp -L / rsync -L copy what the link points at
                size, complete = path_size(one, cap=thr - total, seconds=min(COPY_WALK_SECONDS, max(0.1, budget_s - (time.monotonic() - started))))
                total += size
                if total >= thr:
                    return total, None
                if not complete:
                    return total, f"{os.path.basename(one) or one} is too large to measure within {COPY_WALK_SECONDS:g}s"
        if total >= thr:
            return total, None
    return total, None


def finish_copy(label, total, unknown, thr, extra=""):
    if total >= thr:
        return ("copy", f"{label} copies at least {fmt_gib(total)} onto this Mac (limit {fmt_gib(thr)}){extra}")
    if unknown:
        return ("copy", f"{label}: {unknown} (unknown size counts as heavy; limit {fmt_gib(thr)})")
    return None


RSYNC_VALUE_FLAGS = ("-e", "--rsh", "-f", "--filter", "--exclude", "--include", "--exclude-from", "--include-from",
                     "--files-from", "--max-size", "--min-size", "--bwlimit", "--log-file", "--port", "--partial-dir",
                     "--backup-dir", "--link-dest", "--compare-dest", "--copy-dest", "-B", "--block-size", "-T",
                     "--temp-dir", "--timeout", "--contimeout", "--chmod", "--usermap", "--groupmap", "--iconv",
                     "--rsync-path", "--out-format", "--info", "--debug", "--suffix", "--address", "--sockopts",
                     "--password-file", "--stop-after", "--stop-at", "--compress-level", "--skip-compress")
SCP_VALUE_FLAGS = ("-P", "-i", "-F", "-l", "-o", "-c", "-J", "-S", "-D")
CP_VALUE_FLAGS = ("-t", "--target-directory", "-S", "--suffix")
CLONE_VALUE_FLAGS = ("-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference",
                     "--reference-if-able", "--separate-git-dir", "--template", "--filter", "-j", "--jobs",
                     "-u", "--upload-pack", "--server-option", "--shallow-since", "--shallow-exclude", "--revision",
                     "--ref-format", "--bundle-uri")
TAR_ARG_LETTERS = "fCXTIbgL"  # bundled letters that consume the next word, in order of appearance
TAR_LONG_VALUES = ("--directory", "--exclude", "--files-from", "--exclude-from", "--use-compress-program", "--transform",
                   "--strip-components", "--newer", "--listed-incremental", "--owner", "--group", "--mode", "--format")


def parse_tar(args):
    """(mode 'x'|'c'|None, archive, [source words]) for old-style (`tar xzf a.tgz`) and dashed forms, flags in any order."""
    mode, archive, sources, i = None, None, [], 0
    to_stdout = False
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            sources.extend(args[i:])
            break
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name == "--to-stdout":
                to_stdout = True
            if name in ("--extract", "--get"):
                mode = "x"
            elif name == "--create":
                mode = mode or "c"
            elif name == "--file":
                archive = val if eq else (args[i] if i < len(args) else None)
                i += 0 if eq else 1
            elif name in TAR_LONG_VALUES and not eq:
                i += 1
            continue
        if (a.startswith("-") and len(a) > 1) or (i == 1 and not a.startswith("-") and re.fullmatch(r"[A-Za-z]+", a)):
            wants = []
            for ch in a.lstrip("-"):
                if ch == "O":
                    to_stdout = True
                if ch == "x":
                    mode = "x"
                elif ch == "c":
                    mode = mode or "c"
                if ch in TAR_ARG_LETTERS:
                    wants.append(ch)
            for ch in wants:
                value = args[i] if i < len(args) else None
                i += 1
                if ch == "f":
                    archive = value
            continue
        sources.append(a)
    return mode, archive, sources, to_stdout


def classify_copy(low, args, ctx):
    """Return ("copy", detail) when this command would write an estimated >= threshold onto the Mac, else None."""
    thr = copy_threshold_bytes()
    if low in ("cp", "ditto", "scp", "rsync"):
        if low == "rsync" and any(a == "--dry-run" or re.match(r"^-[A-Za-z]*n[A-Za-z]*$", a) for a in args):
            return None
        target = None
        flagged = [a for a in args if a in ("-t", "--target-directory")]
        if low == "cp" and flagged and args.index(flagged[0]) + 1 < len(args):
            target = args[args.index(flagged[0]) + 1]
        values = {"rsync": RSYNC_VALUE_FLAGS, "scp": SCP_VALUE_FLAGS, "cp": CP_VALUE_FLAGS}.get(low, ())
        pos = positional(args, values)
        if target is None and len(pos) < 2:
            return None
        sources, dest = (pos, target) if target else (pos[:-1], pos[-1])
        remote_tool = low in ("scp", "rsync")
        if dest == "/dev/null" or dest.startswith("rsync://"):
            return None
        if remote_tool and REMOTE_SPEC.match(dest) and not dest.startswith(("/", ".", "~")):
            return None  # the copy lands on another host
        if os.path.realpath(os.path.expanduser(dest)).startswith("/Volumes/"):
            return None  # an external or network volume, not the Mac's own disk
        deref = any(a in ("--copy-links", "--dereference") or re.match(r"^-[A-Za-z]*[LH][A-Za-z]*$", a) for a in args
                    if a.startswith("-") and a not in values)
        total, unknown = sum_sources(sources, ctx, thr, remote_ok=remote_tool, deref=deref)
        return finish_copy(low, total, unknown, thr)
    if low == "tar" and args:
        mode, archive, srcs, to_stdout = parse_tar(args)
        if to_stdout and mode == "x":
            return None  # extracting to stdout writes nothing to disk
        if mode is None or archive in (None, "-") or REMOTE_SPEC.match(archive) and not archive.startswith(("/", ".", "~")):
            return None  # a pipe or a listing: the other end decides (tar czf - . | ssh dev2 'tar x')
        if mode == "x":
            size, _complete = path_size(resolve(os.path.expanduser(archive), ctx.cwd))
            return finish_copy("tar extract", size * (4 if COMPRESSED.search(archive) else 1), None, thr)
        total, unknown = sum_sources(srcs, ctx, thr)
        return finish_copy("tar create", total, unknown, thr)
    if low == "gh":
        pos = positional(args)
        if pos[:2] == ["repo", "clone"] and len(pos) > 2:
            return clone_estimate(pos[2], list(args), ctx, thr, "gh repo clone")
        return None
    if low == "git":
        cwd, i, rest = ctx.cwd, 0, list(args)
        while i < len(rest) and rest[i].startswith("-"):
            if rest[i] == "-C" and i + 1 < len(rest):
                cwd = resolve(os.path.expanduser(rest[i + 1]), cwd)
                i += 2
            elif rest[i] in ("-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"):
                i += 2
            else:
                i += 1
        rest = rest[i:]
        if not rest:
            return None
        if rest[0] == "clone":
            pos = positional(rest[1:], CLONE_VALUE_FLAGS)
            if not pos:
                return None
            return clone_estimate(pos[0], rest[1:], ctx, thr, "git clone")
        if rest[0] == "worktree" and rest[1:2] == ["add"]:
            size = tracked_tree_bytes(cwd)
            if size is None:
                return finish_copy("git worktree add", 0, "git could not size the tracked tree in time", thr)
            return finish_copy("git worktree add", size, None, thr, " (tracked tree at HEAD)")
    return None


def clone_is_shallow(flags):
    """A real --depth N (1..50) given as its own option, not the value of another option (`--template --depth`)."""
    i, depth = 0, None
    while i < len(flags):
        f = flags[i]
        if f == "--depth":
            depth = flags[i + 1] if i + 1 < len(flags) else ""
            i += 2
            continue
        if f.startswith("--depth="):
            depth = f[8:]
        i += 2 if f in CLONE_VALUE_FLAGS else 1
    return depth is not None and depth.isdigit() and 0 < int(depth) <= 50  # the last --depth wins, as in git


def clone_estimate(url, flags, ctx, thr, label):
    shallow = clone_is_shallow(flags)
    factor = 0.5 if shallow else 2.0
    local = resolve(os.path.expanduser(url.replace("file://", "")), ctx.cwd)
    if os.path.isdir(local):
        size, complete = path_size(local, cap=thr)
        return finish_copy(label, int(size * (0.5 if shallow else 1.0)), None if (complete or shallow) else
                           "source is too large to measure", thr)
    match = GITHUB_URL.search(url) or (GH_SLUG.match(url) if label == "gh repo clone" else None)
    if match:
        size = github_repo_bytes(match.group(1), match.group(2))
        if size is not None:
            return finish_copy(label, int(size * factor), None, thr, f" (repository {fmt_gib(size)} as reported by GitHub)")
    if shallow:
        return None  # a shallow or filtered clone is bounded by construction, so an unknown size is allowed
    return ("copy", f"{label} of {url[:80]}: size unknown (no GitHub size available, and any other host is not measured; "
                    f"unknown size counts as heavy; limit {fmt_gib(thr)})")


# ---------------------------------------------------------------- classification

REMOTE_CMDS = {"ssh", "scp", "sftp", "rsync", "mosh", "sshpass"}
PYTHON = re.compile(r"^(?:python|pypy)[\d.]*$")
NODE_RUNNERS = {"node", "nodejs", "tsx", "ts-node", "deno", "esno"}
PM = {"npm", "pnpm", "yarn", "bun", "bunx"}
SHELL_KEYWORDS = {"do", "then", "else", "elif", "{", "}", "!", "if", "while", "until", "coproc"}
# Wrapper flag tables: (flags that take no value, flags that consume the next token). A flag in neither table
# (unknown, bundled like -iu, or a value we cannot place) makes the parse UNCERTAIN, and the guard then scans every
# remaining word for a heavy command instead of guessing which word is the command. A false denial of an odd wrapper
# form is acceptable (the message names HARNESS_LOCAL_OK and dev2); a false allow is not.
WRAPPER_FLAGS = {
    "env": ({"-i", "--ignore-environment", "-0", "--null", "-v", "--debug"}, {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}),
    "sudo": ({"-n", "--non-interactive", "-S", "--stdin", "-i", "--login", "-s", "--shell", "-E", "--preserve-env", "-H",
              "--set-home", "-k", "-K", "-b", "--background", "-A", "-B", "-P", "-e", "-l", "-v"},
             {"-u", "--user", "-g", "--group", "-C", "--close-from", "-h", "--host", "-p", "--prompt", "-r", "--role",
              "-t", "--type", "-T", "--command-timeout", "-U", "--other-user", "-D", "--chdir", "-R", "--chroot"}),
    "doas": ({"-n", "-s"}, {"-u", "-C"}),
    "nice": (set(), {"-n", "--adjustment"}),
    "time": ({"-p", "-v", "-a", "--portability", "--verbose", "--append"}, {"-f", "--format", "-o", "--output"}),
    "caffeinate": ({"-d", "-i", "-m", "-s", "-u"}, {"-t", "-w"}),
    "stdbuf": (set(), {"-i", "-o", "-e"}),
    "exec": ({"-c", "-l"}, {"-a"}),
    "watch": ({"-d", "-t", "-b", "-e", "-g", "-c", "-x", "-p", "-q"}, {"-n", "--interval"}),
    "unbuffer": ({"-p"}, set()),
    "taskpolicy": (set(), set()),
    "arch": ({"-arm64", "-x86_64", "-i386", "-arm64e", "-x86_64h"}, set()),
    "nohup": (set(), set()),
    "setsid": ({"-f", "-w", "-c"}, set()),
    "builtin": (set(), set()),
    "command": ({"-p"}, set()),
}
WRAPPERS = set(WRAPPER_FLAGS)
BROWSER_BINS = {"chromium", "chromium-browser", "chrome", "google-chrome", "google-chrome-stable",
                "google chrome", "google chrome for testing", "chrome-headless-shell", "chromedriver",
                "geckodriver", "msedge", "microsoft edge"}
PY_BROWSER_IMPORT = re.compile(
    r"(?m)^[ \t]*(?:from|import)[ \t]+(?:playwright|selenium|pyppeteer|puppeteer)\b")
# An import alone (a version probe such as `python -c "import playwright"`) launches nothing.
BROWSER_LAUNCH = re.compile(r"sync_playwright|async_playwright|webdriver\.|\.launch\(|launch_persistent_context|connect_over_cdp")
JS_BROWSER_IMPORT = re.compile(
    r"""(?:require\(\s*|from\s+|import\(\s*|import\s+)['"](?:playwright(?:-core|-chromium|-firefox|-webkit)?|"""
    r"""@playwright/test|puppeteer(?:-core)?|selenium-webdriver)['"]""")
HOSTILE = re.compile(r"/dev/(?:zero|u?random)\b|\bmkfifo\b")
SCRATCH_RT = re.compile(r"/scratchpad/(?:[^/\s]+/)*rt(?:/|$)")
FILE_TARGET = re.compile(r"\.(?:py|[cm]?[jt]sx?)(?:::.*)?$|\.(?:test|spec)\.")
PERL_ALARM = re.compile(r"\balarm\b")
PERL_EXEC = re.compile(r"\bexec\b")


LIGHT_XARGS = {"grep", "egrep", "fgrep", "rg", "echo", "cat", "ls", "rm", "mv", "cp", "stat", "wc", "head", "tail",
               "file", "touch", "chmod", "chown", "basename", "dirname", "md5", "md5sum", "shasum", "sha256sum", "test", "true"}


def xargs_inner(args):
    """The command xargs will run: skip its own flags (and their values)."""
    valued = {"-n", "-L", "-I", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--replace", "--delimiter"}
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in valued else 1
    return args[i:]


MAX_WRAPPER_DEPTH = 12


class WorkBudgetExceeded(Exception):
    """Nested scanning used its whole work budget: the command is too tangled to judge, so it fails closed."""


class Ctx:
    def __init__(self, cwd, heredocs, parent=None):
        self.cwd = cwd or os.getcwd()
        self.heredocs = heredocs
        self.capped = False
        # GoodQA #14505: repeat invocations must not re-read or re-regex big sources, and nested scans (bash -c,
        # eval, env -S ...) share the parent's caches and ONE work budget, so nesting cannot multiply the cost.
        self._disk = parent._disk if parent else {}
        self._hits = parent._hits if parent else {}
        self.deadline = parent.deadline if parent else time.monotonic() + MAX_NESTED_SECONDS

    def spend(self):
        """Checked once per nested scan and per uncertain-wrapper probe (each costs at most milliseconds).

        A wall-clock budget bounds every superlinear shape without weighting units per command name: ordinary
        commands never come near it, so only pathological input is denied (fail closed)."""
        if time.monotonic() > self.deadline:
            raise WorkBudgetExceeded()

    def search(self, pattern, text):
        """pattern.search(text) is not None, memoised per source text (str hashes are cached by CPython)."""
        key = (pattern.pattern, text)
        if key not in self._hits:
            self._hits[key] = pattern.search(text) is not None
        return self._hits[key]


def resolve(path: str, cwd: str) -> str:
    path = os.path.expandvars(os.path.expanduser(path))
    return path if os.path.isabs(path) else os.path.join(cwd, path)


def read_script(path: str, cwd: str):
    try:
        full = resolve(path, cwd)
        # Regular files only: opening a FIFO or /dev/zero-style device would hang or spin the hook.
        if not stat.S_ISREG(os.stat(full).st_mode):
            return None
        import safe_input
        return safe_input.read_bounded(full, MAX_SCRIPT_BYTES).decode("utf-8", "replace")
    except (OSError, ValueError, ImportError, Exception):  # InputRejected (FIFO, device, too large) -> unknown script
        return None


def script_sources(script, ctx):
    """The script's on-disk text plus any heredoc bodies in the same command (it may be written then run)."""
    sources = list(ctx.heredocs)
    disk = None
    if script and script != "-":
        ctx.spend()  # reading a script is the other repeatable cost, so the top-level scan honours the deadline too
        key = os.path.realpath(resolve(script, ctx.cwd))  # `./x`, `.//x` and symlinks are one file, read once
        if key not in ctx._disk:
            ctx._disk[key] = read_script(script, ctx.cwd)
        disk = ctx._disk[key]
    if disk:
        sources.append(disk)
    return sources


def disk_probe_dir(script, ctx):
    """Only throwaway locations count as 'hostile probe' sources; a repo test that merely mentions /dev/zero does not."""
    return bool(script and script != "-" and re.search(r"/(?:scratchpad|tmp|private/tmp)/", resolve(script, ctx.cwd)))


def python_findings(args, ctx):
    """(rule, detail) for a python invocation, or None."""
    script, hostile_src, browser_src = None, [], []
    if "-c" in args and args.index("-c") + 1 < len(args):
        hostile_src = browser_src = [args[args.index("-c") + 1]]
    else:
        files = positional(args)
        script = files[0] if files else "-"
        browser_src = script_sources(script, ctx)
        hostile_src = list(ctx.heredocs) + (browser_src[len(ctx.heredocs):] if disk_probe_dir(script, ctx) else [])
    resolved = resolve(script, ctx.cwd) if script and script != "-" else ctx.cwd
    if any(ctx.search(HOSTILE, x) for x in hostile_src) or SCRATCH_RT.search(resolved):
        return ("adversarial", "script reads /dev/zero|urandom, makes a FIFO, or lives in a scratchpad rt/ dir")
    if any(ctx.search(PY_BROWSER_IMPORT, x) and ctx.search(BROWSER_LAUNCH, x) for x in browser_src):
        return ("browser", "python script that drives a browser (imports playwright/selenium)")
    return None


def is_focused_test(args):
    return any(FILE_TARGET.search(t) for t in positional(args, ("-t", "--testNamePattern", "-c", "--config")))


REPLAY_NAME = re.compile(r"(?:^|[:_./-])(?:replay|synthetic|stress|loadtest|load-test|soak)(?:$|[:_./-])", re.I)


def classify_pm(name, args):
    """npm/pnpm/yarn/bun: tests and builds. Returns None, (rule, detail) or ('recurse', argv)."""
    valued = ("--prefix", "-C", "--filter", "-F", "-w", "--workspace", "--cwd", "--dir")
    pos = positional(args, valued)
    if not pos:
        return None
    sub, rest = pos[0], pos[1:]
    if sub in ("exec", "dlx", "x") and rest:
        return ("recurse", rest)
    if sub in ("playwright", "puppeteer", "vitest", "jest", "cypress", "next", "vite"):
        return ("recurse", [sub] + rest)
    if sub in ("run", "run-script") and rest:
        sub, rest = rest[0], rest[1:]
    if re.match(r"^(?:test|t|tst)(?:[:_-].*)?$", sub):
        after = args[args.index(sub) + 1:] if sub in args else []
        return None if is_focused_test(after) else ("full-suite", f"{name} {sub}")
    if re.match(r"^build(?:[:_-].*)?$", sub) or sub in ("compile", "bundle"):
        return ("build", f"{name} {sub}")
    if sub in ("install", "i", "ci", "add", "update", "upgrade", "up", "dedupe", "rebuild") and not any(
            a in ("--help", "-h", "--version", "--dry-run") for a in args):
        return ("install", f"{name} {sub}")
    if REPLAY_NAME.search(sub):
        return ("replay", f"{name} {sub}")
    return None


MAKE_NAMES = {"make", "gmake"}
GRADLE_NAMES = {"gradle", "gradlew", "gradlew.bat", "gradle.bat"}
MVN_NAMES = {"mvn", "mvnw", "mvnw.cmd", "mvnw.bat", "mvnd"}
BAZEL_NAMES = {"bazel", "bazelisk"}
BUILD_TOOLS = MAKE_NAMES | GRADLE_NAMES | MVN_NAMES | BAZEL_NAMES | {"xcodebuild"}

MAKE_TEST = re.compile(r"^(?:test|tests|check|e2e|ci|coverage)(?:[_.-].*)?$")
MAKE_BUILD = re.compile(r"^(?:all|build|compile|install|package|dist|release)(?:[_.-].*)?$")
# -n/--dry-run/--just-print: bundles of value-less make flags (digits cover -j4) containing n.
MAKE_DRY = re.compile(r"^-[kBeiLpqrRsStwj0-9]*n[kBeiLpqrRsStwj0-9]*$")
GRADLE_TEST = re.compile(r"^(?:test|check|verify|integrationTest|connected\w*|test[A-Z]\w*|\w+Test|\w+Check|jacoco\w+)$")
GRADLE_BUILD = re.compile(r"^(?:build\w*|assemble\w*|bundle\w*|install\w*|classes|\w*[jJ]ar|war|dist\w+|publish\w*|compile\w*|package\w*)$")
MVN_TEST = {"test", "verify", "integration-test", "pre-integration-test", "surefire:test", "failsafe:integration-test"}
MVN_BUILD = {"package", "prepare-package", "process-classes", "install", "compile", "test-compile", "deploy", "site"}
XCODE_TEST = {"test", "test-without-building"}
XCODE_BUILD = {"build", "build-for-testing", "archive", "install", "installsrc"}
XCODE_INFO = {"-version", "-list", "-showBuildSettings", "-showsdks", "-showdestinations", "-help", "-usage",
              "-showBuildSettingsForIndex", "-showTestPlans", "-checkFirstLaunchStatus", "-runFirstLaunch",
              "-exportArchive", "-resolvePackageDependencies"}


def classify_build_tool(low, args):
    """make/gradle/mvn/bazel/xcodebuild: test and build targets are heavy; help, clean, version, query forms are not.

    Any heavy target on the line decides (`gradle -x test build` still builds); filtered forms such as
    `gradle test --tests Foo` or `mvn -Dtest=Foo test` are denied too: these tools configure the whole project
    first. `make -n` (dry run) is allowed. Returns (rule, detail) or None."""
    if low in MAKE_NAMES:
        if any(a in ("--version", "-v", "--help", "-h", "--dry-run", "--just-print", "--recon") or MAKE_DRY.match(a)
               for a in args):
            return None
        targets = [t for t in positional(args, ("-C", "--directory", "-f", "--file", "--makefile", "-I", "--include-dir",
                                                "-o", "--old-file", "-W", "--what-if", "-l", "--load-average", "-E"))
                   if "=" not in t]
        if not targets:
            return ("build", f"{low} (default target)")
        for t in targets:
            if MAKE_TEST.match(t):
                return ("full-suite", f"{low} {t}")
        for t in targets:
            if MAKE_BUILD.match(t):
                return ("build", f"{low} {t}")
        return None
    if low in GRADLE_NAMES:
        if any(a in ("--version", "-v", "--help", "-h", "-?", "--dry-run", "-m") for a in args):
            return None
        tasks = [t.split(":")[-1] for t in positional(args, (
            "-x", "--exclude-task", "-p", "--project-dir", "-c", "--settings-file", "-b", "--build-file", "-g",
            "--gradle-user-home", "-I", "--init-script", "--tests", "--test", "--task", "--dependency", "--configuration", "--max-workers", "--console", "--warning-mode"))]
        for t in tasks:
            if GRADLE_TEST.match(t):
                return ("full-suite", f"{low} {t}")
        for t in tasks:
            if GRADLE_BUILD.match(t):
                return ("build", f"{low} {t}")
        return None
    if low in MVN_NAMES:
        if any(a in ("--version", "-v", "--help", "-h") for a in args):
            return None
        goals = positional(args, ("-f", "--file", "-pl", "--projects", "-rf", "--resume-from", "-T", "--threads", "-s",
                                  "--settings", "-gs", "--global-settings", "-P", "--activate-profiles", "-l", "--log-file",
                                  "-t", "--toolchains", "-b", "--builder"))
        for g in goals:
            if g in MVN_TEST:
                return ("full-suite", f"{low} {g}")
        for g in goals:
            if g in MVN_BUILD:
                return ("build", f"{low} {g}")
        return None
    if low in BAZEL_NAMES:
        sub = (positional(args, ("--output_base", "--output_user_root", "--install_base", "--bazelrc", "--host_jvm_args",
                                 "--server_javabase", "--host_jvm_profile")) or [""])[0]
        if sub in ("test", "coverage"):
            return ("full-suite", f"{low} {sub}")
        if sub in ("build", "run"):
            return ("build", f"{low} {sub}")
        return None
    # xcodebuild
    if any(a in XCODE_INFO or a == "--help" for a in args):
        return None
    actions = positional(args, ("-project", "-scheme", "-target", "-configuration", "-sdk", "-destination", "-workspace",
                                "-derivedDataPath", "-arch", "-xcconfig", "-resultBundlePath", "-testPlan", "-toolchain",
                                "-jobs", "-archivePath", "-exportPath", "-exportOptionsPlist", "-xctestrun",
                                "-testProductsPath", "-resultStreamPath", "-clonedSourcePackagesDirPath",
                                "-destination-timeout"))
    actions = [a for a in actions if "=" not in a]
    for a in actions:
        if a in XCODE_TEST:
            return ("full-suite", f"xcodebuild {a}")
    for a in actions:
        if a in XCODE_BUILD:
            return ("build", f"xcodebuild {a}")
    return ("build", "xcodebuild (default build action)") if not actions else None


def scan_words(words, ctx, depth):
    """Uncertain wrapper parse: judge every remaining word as if it started the command; first heavy finding wins."""
    for j, word in enumerate(words):
        ctx.spend()  # each probe slices and re-classifies the remaining words
        if word.startswith("-") or ASSIGN.match(word):
            continue
        result = classify_text(word, ctx, depth + 1) if re.search(r"\s", word) else None
        result = result or classify(words[j:], ctx, depth + 1)
        if result:
            return result
    return None


COMMAND_FLAGS = {"env": ("-S", "--split-string"), "su": ("-c", "--command")}


def command_flag_value(low, args, i):
    """(value, tokens consumed) when args[i] is a flag whose value is a COMMAND, in any spelling: `-S x`, `-Sx`,
    `--split-string x`, `--split-string=x`, and bundled short flags ending in the letter (su -lc x)."""
    token = args[i]
    for flag in COMMAND_FLAGS.get(low, ()):
        if flag.startswith("--"):
            if token == flag:
                return (args[i + 1], 2) if i + 1 < len(args) else ("", 1)
            if token.startswith(flag + "="):
                return token.split("=", 1)[1], 1
        else:
            letter = flag[1]
            if token == flag:
                return (args[i + 1], 2) if i + 1 < len(args) else ("", 1)
            if token.startswith("-") and not token.startswith("--") and len(token) > 2:
                body = token[1:]
                if low == "su" and re.fullmatch(r"[A-Za-z]*" + letter, body):  # -lc pytest
                    return (args[i + 1], 2) if i + 1 < len(args) else ("", 1)
                if body.startswith(letter):  # -Spytest, -cpytest
                    return body[1:], 1
    return None


def unwrap(low, args, ctx, depth):
    """Skip a wrapper's own flags and classify the command it runs; fall back to scan_words when unsure."""
    if low == "command" and args[:1] in (["-v"], ["-V"]):
        return None  # `command -v pytest` only looks the name up
    noval, val = WRAPPER_FLAGS[low]
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            i += 1
            break
        if low in ("env", "sudo", "doas") and ASSIGN.match(token):
            i += 1
            continue
        if low == "env" and token == "-":  # legacy spelling of -i
            i += 1
            continue
        if not token.startswith("-"):
            break  # the wrapped command starts here
        flagged = command_flag_value(low, args, i)
        if flagged is not None:
            return classify_text(flagged[0], ctx, depth + 1) if flagged[0] else None
        if token in val:
            i += 2
        elif token in noval or token.split("=", 1)[0] in val:
            i += 1
        else:
            return scan_words(args[i + 1:], ctx, depth)  # unknown or bundled flag: do not guess where the command starts
    rest = args[i:]
    if len(rest) == 1 and re.search(r"\s", rest[0]):
        return classify_text(rest[0], ctx, depth + 1)  # watch 'pytest -x'
    return classify(rest, ctx, depth + 1)


def classify(argv, ctx, depth=0):
    """Classify one command's argv. Returns (rule, detail) or None."""
    _assigns, argv = split_assignments(argv)
    while argv and argv[0] in SHELL_KEYWORDS:
        k = 1
        while k < len(argv) and argv[k] in SHELL_KEYWORDS:  # skip a run of keywords without re-slicing per word
            k += 1
        argv = argv[k:]
        _assigns, argv = split_assignments(argv)
    if not argv:
        return None
    if depth > MAX_WRAPPER_DEPTH:
        return ("full-suite", "wrapper nesting too deep to analyse (denied conservatively)")
    cmd = base(argv[0])
    low = cmd.lower()
    args = argv[1:]

    if low in ("cp", "ditto", "scp", "rsync", "tar", "git", "gh"):
        try:
            found = classify_copy(low, args, ctx)
        except Exception:  # a sizing bug must never block ordinary work: fail open for this rule only
            found = None
        if found:
            return found
    if low == "claude" and any(a in ("-p", "--print") for a in args):
        ctx.claude_p = getattr(ctx, "claude_p", 0) + 1
    if low in REMOTE_CMDS:
        return None  # already off-box
    if cmd == "run_capped.py":
        ctx.capped = "--max-rss-gb" in args
        return classify(args[args.index("--") + 1:] if "--" in args else [], ctx, depth + 1)
    if low == "su":
        i = 0
        while i < len(args):
            flagged = command_flag_value("su", args, i)
            if flagged is not None:
                return classify_text(flagged[0], ctx, depth + 1) if flagged[0] else None
            i += 1
        return None
    if low in WRAPPERS:
        return unwrap(low, list(args), ctx, depth)
    if low == "xcrun":  # xcrun [--sdk X] [--toolchain Y] [-v...] <tool> args
        i = 0  # index walk, not repeated slicing (quadratic on thousands of flags; GoodQA #14505)
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("--sdk", "-sdk", "--toolchain", "-toolchain") else 1
        return classify(args[i:], ctx, depth + 1)
    if low == "script":  # macOS `script [-q] file cmd...`; Linux `script -c 'cmd' file`
        if "-c" in args and args.index("-c") + 1 < len(args):
            return classify_text(args[args.index("-c") + 1], ctx, depth + 1)
        rest = [a for a in args if not a.startswith("-")]
        return classify(rest[1:], ctx, depth + 1)
    if low == "eval":
        return classify_text(" ".join(args), ctx, depth + 1)
    if low in ("timeout", "gtimeout"):
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("-s", "-k") else 1
        return classify(args[i + 1:], ctx, depth + 1)
    if low in ("bash", "sh", "zsh", "dash", "ksh"):
        for i, a in enumerate(args):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and i + 1 < len(args):
                return classify_text(args[i + 1], ctx, depth + 1)
        script = (positional(args) or [None])[0]
        if script and base(script).lower() in BUILD_TOOLS:  # `bash ./gradlew build`, `sh gradlew build`
            return classify([script] + args[args.index(script) + 1:], ctx, depth + 1)
        if script and any(ctx.search(HOSTILE, s) for s in script_sources(script, ctx)):
            return ("adversarial", "shell script reads /dev/zero|urandom or makes a FIFO")
        return None
    if low in ("uv", "poetry", "pipenv", "pdm", "hatch", "rye") and "run" in args:
        i = args.index("run") + 1
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("--with", "--extra", "--python", "-p", "--project", "--directory") else 1
        return classify(args[i:], ctx, depth + 1)
    if low in ("uvx", "npx", "pipx", "bunx"):
        out, skip = [], False
        for a in (a for a in args if not (low == "pipx" and a == "run")):
            if skip:
                skip = False
            elif a in ("-p", "--package", "--from"):
                skip = True
            elif a.startswith("-") and not out:
                continue
            else:
                out.append(a)
        return classify(out, ctx, depth + 1)

    # ---- adversarial / unbounded reads
    if low in ("perl", "ruby") and "-e" in args:
        code = args[args.index("-e") + 1] if args.index("-e") + 1 < len(args) else ""
        if PERL_ALARM.search(code) and PERL_EXEC.search(code):
            # a plain timeout idiom: judge the command it execs, not the wrapper
            tail = args[args.index("-e") + 2:]
            return classify(tail, ctx, depth + 1)
        if HOSTILE.search(code):
            return ("adversarial", f"{low} one-liner reads /dev/zero|urandom")
    if low in ("cat", "tail", "tac", "yes") and any(re.match(r"^/dev/(?:zero|u?random)$", a) for a in args):
        return ("adversarial", f"unbounded read of a device file ({low})")

    # ---- browser automation
    if low in ("playwright", "puppeteer", "cypress"):
        sub = (positional(args) or [""])[0]
        if sub in ("install", "install-deps", "version", "verify", "show-report") or "--version" in args:
            return None
        return ("browser", f"{low} {sub}".strip())
    if low in BROWSER_BINS:
        if any(a.startswith("--headless") for a in args) or low in ("chromedriver", "geckodriver", "chrome-headless-shell"):
            return ("browser", f"headless {low}")
        return None
    if PYTHON.match(low):
        glued = [a for a in args if re.match(r"^-m[A-Za-z_]", a)]
        if glued:
            args = [a if a is not glued[0] else "-m" for a in args]
            args.insert(args.index("-m") + 1, glued[0][2:])
        if "-m" in args and args.index("-m") + 1 < len(args):
            module = args[args.index("-m") + 1]
            margs = args[args.index("-m") + 2:]
            if module == "coverage" and margs[:1] == ["run"]:
                return classify([a for a in margs[1:] if not a.startswith("--")][:0] + (["python3"] + margs[1:]), ctx, depth + 1)
            if module in ("pytest", "py.test"):
                return classify(["pytest"] + margs, ctx, depth + 1)
            if module == "unittest":
                return classify(["unittest"] + margs, ctx, depth + 1)
            if module.split(".")[0] in ("playwright", "pyppeteer"):
                return ("browser", f"python -m {module}")
            return None
        first = (positional(args) or [""])[0]
        if base(first) == "run_capped.py":
            return classify([first] + args[args.index(first) + 1:], ctx, depth + 1)
        if base(first) == "run_probe.py":
            return None  # declared-bound probe runner: the probe's own bounds apply
        return python_findings(args, ctx)
    if cmd.endswith(".py"):  # direct ./script.py execution
        return python_findings([argv[0]], ctx)
    if low == "coverage" and args[:1] == ["run"]:
        return classify(["python3"] + [a for a in args[1:] if not a.startswith("--")], ctx, depth + 1)
    if low in ("tox", "nox"):
        return ("full-suite", f"{low} runs every environment")
    if low in NODE_RUNNERS:
        for flag in ("-e", "--eval", "-p", "--print"):
            if flag in args and args.index(flag) + 1 < len(args):
                code = args[args.index(flag) + 1]
                if JS_BROWSER_IMPORT.search(code) or re.search(r"require\(\s*['\"](?:playwright|puppeteer)", code):
                    return ("browser", "node -e code that drives a browser")
        script = next(iter(positional(args)), None)
        if script and re.search(r"\.[cm]?[jt]s$", script) and REPLAY_NAME.search(base(script)):
            return ("replay", f"{low} {base(script)}")
        if script and re.search(r"\.[cm]?[jt]s$", script):
            sources = script_sources(script, ctx)
            if any(ctx.search(HOSTILE, s) for s in sources):
                return ("adversarial", "node script reads /dev/zero|urandom or makes a FIFO")
            if any(ctx.search(JS_BROWSER_IMPORT, s) and ctx.search(BROWSER_LAUNCH, s) for s in sources):
                return ("browser", "node script that drives a browser (imports playwright/puppeteer)")
        return None

    # ---- full test suites
    if low in ("pytest", "py.test"):
        if any(a in ("--collect-only", "--co", "--version", "-h", "--help", "--fixtures") for a in args):
            return None
        targets = positional(args, ("-p", "-c", "-k", "-m", "-n", "--rootdir", "--deselect", "--ignore", "-o"))
        for t in targets:
            if not FILE_TARGET.search(t) and os.path.isdir(resolve(t.split("::")[0], ctx.cwd)):
                return ("full-suite", "pytest over a directory")
        if any(FILE_TARGET.search(t) for t in targets):
            return None
        return ("full-suite", "pytest without a single-file target")
    if low == "unittest":
        pos = positional(args, ("-k", "-s", "-t", "-p"))
        if "discover" in pos or not pos:
            pattern = args[args.index("-p") + 1] if "-p" in args and args.index("-p") + 1 < len(args) else ""
            if pattern and not re.search(r"[*?\[]", pattern):
                return None  # discovery limited to one named file is a focused check
            return ("full-suite", "unittest discover")
        return None
    if low in ("vitest", "jest"):
        if any(a in ("--version", "--help", "-h", "--listTests") for a in args) or is_focused_test(args):
            return None
        return ("full-suite", f"{low} without a file target")
    if low == "go":
        if (positional(args) or [""])[0] == "test" and any("..." in a for a in args):
            return ("full-suite", "go test ./...")
        return None
    if low == "cargo":
        sub = (positional(args) or [""])[0]
        if sub in ("build", "test", "bench", "check", "clippy"):
            return ("full-suite" if sub == "test" else "build", f"cargo {sub}")
        return None
    if low == "dotnet":
        sub = (positional(args) or [""])[0]
        if sub in ("build", "publish", "pack"):
            return ("build", f"dotnet {sub}")
        return ("full-suite", "dotnet test") if sub == "test" else None

    # ---- build tools (make/gradle/mvn/bazel/xcodebuild)
    if low in BUILD_TOOLS:
        return classify_build_tool(low, args)

    # ---- builds
    if low in ("next", "vite", "webpack", "nuxt", "astro"):
        sub = (positional(args) or [""])[0]
        if sub == "build" or (low == "webpack" and sub not in ("serve", "watch")):
            return ("build", f"{low} {sub}".strip())
        return None
    if low in ("docker", "docker-compose", "podman", "nerdctl"):
        pos = positional(args, ("--context", "-H", "--host", "-f", "--file", "-p", "--project-name"))
        if "build" in pos[:2] or ("--build" in args and ("up" in pos or low == "docker-compose")):
            return ("build", f"{low} build")
        if (pos[:1] and pos[0] in ("run", "pull", "buildx", "create", "start", "up")) or (
                pos[:2] and pos[0] == "compose" and pos[1] in ("up", "run", "pull", "start")) or (
                low == "docker-compose" and pos[:1] and pos[0] in ("up", "run", "pull", "start")):
            return ("container", f"{low} {pos[0] if pos[0] != 'compose' else 'compose ' + pos[1]}")
        return None
    if low in PM:
        result = classify_pm(low, args)
        if result and result[0] == "recurse":
            return classify(result[1], ctx, depth + 1)
        return result

    # ---- media
    if low == "ffmpeg":
        if any(a in ("-version", "-h", "-help", "-formats", "-codecs", "-encoders", "-decoders", "-filters") for a in args):
            return None
        return ("media", "ffmpeg")
    if low.startswith("whisper") or low in ("mlx_whisper", "faster-whisper"):
        return None if ("--help" in args or "-h" in args) else ("media", low)

    # ---- fan-out
    if low == "xargs":
        inner = xargs_inner(args)
        if inner:
            result = classify(inner, ctx, depth + 1)
            if result:
                return result  # xargs pytest / xargs npx playwright test
        if inner and base(inner[0]) in LIGHT_XARGS:
            return None  # parallel grep/echo/stat is cheap; only fan-out of real work matters
        for i, a in enumerate(args):
            value = None
            if a in ("-P", "--max-procs") and i + 1 < len(args):
                value = args[i + 1]
            elif a.startswith("--max-procs="):
                value = a.split("=", 1)[1]
            elif re.match(r"^-P[0-9]+$", a):
                value = a[2:]
            if value is not None and re.fullmatch(r"[0-9]{1,9}", value) and (int(value) == 0 or int(value) >= 3):
                return ("fan-out", f"xargs -P {value}")
        return None
    if low == "parallel":
        return None if ("--version" in args or "--help" in args) else ("fan-out", "GNU parallel")
    return None


def scan_state(command: str, cwd: str, depth: int = 0, parent=None):
    """Walk every segment. Returns (hatch_reason_or_None, [(rule, detail, capped, segment)])."""
    text, heredocs = extract_heredocs(command[:MAX_COMMAND_CHARS])
    oversize = len(command) > MAX_COMMAND_CHARS or len(text) > MAX_SCAN_CHARS
    if oversize:
        log_event({"event": "truncated-command", "chars": len(command)})  # logged, not silent
        text = text[:MAX_SCAN_CHARS]
    ctx = Ctx(cwd, heredocs, parent)
    hatch, findings = None, []
    if oversize:
        # GoodQA #14505 NEG-1: the tail past the cap is never scanned, so fail closed instead of allowing it.
        # Heredoc bodies do not count toward the scan cap, so a long legitimate heredoc is still fine.
        findings.append(("oversize", f"command is {len(command)} characters ({len(text)} scanned after heredoc "
                         f"bodies; the guard scans at most {MAX_SCAN_CHARS})", False, ""))
    for segment in split_segments(text):
        argv = tokenize(segment)
        if len(argv) > MAX_SEGMENT_WORDS:
            # Wrapper parsing slices argv per word (quadratic); no real command has this many words. Fail closed.
            findings.append(("oversize", f"one command has {len(argv)} words; the guard scans at most "
                             f"{MAX_SEGMENT_WORDS} per command", False, segment[:80]))
            continue
        assigns, rest = split_assignments(argv)
        if argv and argv[0] == "export":
            assigns = [t for t in argv[1:] if ASSIGN.match(t)]
        for a in assigns:
            if a.startswith(HATCH + "="):
                hatch = a.split("=", 1)[1]
        if rest and rest[0] in ("cd", "pushd") and len(rest) > 1:
            target = resolve(rest[1], ctx.cwd)
            if os.path.isdir(target):
                ctx.cwd = os.path.normpath(target)
            continue
        ctx.capped = False
        result = classify(argv, ctx, depth)
        if result:
            findings.append((result[0], result[1], ctx.capped, segment))
    if getattr(ctx, "claude_p", 0) >= 3 or (getattr(ctx, "claude_p", 0) >= 1 and re.search(r"(?:^|[\s;&|(])(?:for|while|until)\s", text)):
        findings.append(("fan-out", "claude -p fan-out (several or looped headless sessions)", False, command[:400]))
    return hatch, findings


def classify_text(text, ctx, depth):
    """Classify a nested `bash -c` string with the parent's cwd."""
    ctx.spend()  # a nested scan re-tokenises and re-classifies the whole text
    _hatch, findings = scan_state(text, ctx.cwd, depth, ctx)
    if findings:
        rule, detail, capped, _segment = findings[0]
        ctx.capped = ctx.capped or capped
        return (rule, detail)
    return None


def valid_reason(reason) -> bool:
    return bool(reason) and len(reason.strip()) >= 6 and reason.strip().lower() not in (
        "true", "false", "yes", "none", "reason", "<reason>")


# ---------------------------------------------------------------- decision

def load_modes():
    modes = dict(DEFAULT_MODES)
    try:
        import json
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy_job_guard.json")
        if os.path.exists(path):
            for rule, mode in (load_json_file(path).get("modes") or {}).items():
                if mode in ("enforce", "warn", "off"):
                    modes[rule] = mode
    except Exception:
        pass
    override = os.environ.get("HARNESS_HEAVY_GUARD", "")
    if override in ("enforce", "warn", "off"):
        modes = {rule: override for rule in modes}
    for rule in NEVER_BLOCK:
        if modes.get(rule) == "enforce":
            modes[rule] = "warn"
    return modes


SEVERITY = {"allow": 0, "warn": 1, "deny": 2}


def decide(command: str, cwd: str = None, modes=None):
    """Pure decision: dict(action=allow|warn|deny, rule, detail, message, hatch_reason).

    Every finding is judged on its own (the hatch and the cap apply per finding) and the most
    severe outcome wins, so a warn-only or hatched first segment never hides a later denied one."""
    if not command:
        return {"action": "allow"}
    modes = modes or load_modes()
    try:
        hatch, findings = scan_state(command, cwd)
    except (WorkBudgetExceeded, RecursionError):
        # GoodQA #14505: too tangled (or too deeply nested) to judge in bounded time. Fail CLOSED, never open.
        hatch, findings = None, [("oversize", "analysis time or depth budget exceeded: nested wrappers/eval/scripts "
                                  "are too tangled to analyse (a very large command on a loaded host can also "
                                  "trip this; retry, or write it to a script file)", False, "")]
    best = {"action": "allow"}
    for rule, detail, capped, _segment in findings:
        mode = modes.get(rule, "enforce")
        if mode == "off" or (rule in NEVER_BLOCK and capped):
            continue
        if valid_reason(hatch) and rule != "oversize" and (capped or rule not in CAPPED_RULES):
            outcome = {"action": "allow", "rule": rule, "detail": detail, "hatch_reason": hatch.strip()}
        else:
            outcome = {"action": "deny" if mode == "enforce" else "warn", "rule": rule, "detail": detail,
                       "message": deny_message(rule, detail, hatch, capped, _segment, cwd)}
        if SEVERITY[outcome["action"]] > SEVERITY[best["action"]] or (
                outcome["action"] == "allow" and best["action"] == "allow" and outcome.get("hatch_reason")
                and not best.get("hatch_reason")):
            best = outcome
    return best


def route_host() -> str:
    """Where refused heavy work should go: HARNESS_ROUTE_HOST or heavy_job_guard.json "route_host" (default dev2;
    set to t2 when dev2 is retired). Only a plain host name is accepted."""
    value = os.environ.get("HARNESS_ROUTE_HOST", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,60}", value):
        value = ""
        try:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy_job_guard.json")
            if os.path.exists(path):
                candidate = str(load_json_file(path).get("route_host", ""))
                value = candidate if re.fullmatch(r"[A-Za-z0-9._-]{1,60}", candidate) else ""
        except Exception:
            value = ""
    return value or "t2-dev"  # dev2 retires 11-09


def routed(text: str) -> str:
    return text.replace("ssh dev2 ", f"ssh {route_host()} ")


def exact_route(segment, cwd):
    """The same command on the routed host: `ah run --host H -- CMD` (ah run lands with goodqa#14548) and the ssh form."""
    import shlex
    host = route_host()
    text = " ".join((segment or "").split())[:400]
    if not text:
        return ""
    inner = f"cd {shlex.quote(cwd)} && {text}" if cwd else text
    return (f"Exact equivalent on {host}:\n  python3 ~/.claude/hooks/ah.py run --host {host} -- {text}\n"
            f"  (until ah run is installed)  ssh {host} {shlex.quote(inner)}")


def deny_message(rule, detail, hatch, capped, segment=None, cwd=None):
    base_msg = routed(_deny_message(rule, detail, hatch, capped))
    extra = exact_route(segment, cwd) if rule not in NEVER_BLOCK else ""
    return base_msg + ("\n" + extra if extra else "")


def _deny_message(rule, detail, hatch, capped):
    cap = "python3 ~/.claude/hooks/run_capped.py --max-rss-gb <declared peak x1.5> --timeout-s <expected x2> -- <command>"
    if rule in NEVER_BLOCK:
        return (f"Heavy-job guard [{rule}] advisory (not blocked): {RULE_HELP[rule]} ({detail}). Hostile-input tests are "
                f"legitimate. Prefer dev2 (ssh dev2 '<command>'), or on the Mac run under {cap} so stopping the test also "
                "stops its children and a runaway is paused instead of resetting the machine.")
    if rule == "copy":
        return (f"Heavy-job guard [copy]: {RULE_HELP['copy']} ({detail}). Large copies, clones and review trees belong on "
                "dev2/T2, not the Mac: run it there (ssh dev2 '<command>', or the T2 host) and fetch only the result; "
                "clone with --depth 1 or --filter=blob:none, or delete finished trees first. A single unanticipated "
                f"local step may use {HATCH}=<reason> (one use per owner per hour, audited, refused above 85% disk).")
    head = (f"Heavy-job guard [{rule}]: {RULE_HELP.get(rule, 'heavy work')} ({detail}). "
            "Large jobs belong on dev2, not the Mac (2026-11-04: an uncapped local process hit ~66 GB and reset the machine).")
    lines = [head, "Run it there: ssh dev2 '<command>' (sync the checkout first if needed), or"]
    if valid_reason(hatch) and rule in CAPPED_RULES and not capped:
        lines.append(f"{HATCH} is set, but {rule} work on the Mac must ALSO run under the resource cap: {cap}")
    elif rule in CAPPED_RULES:
        lines.append(f"if it genuinely needs the Mac (GUI, Keychain, notarization, local page check) use {HATCH}=<reason> "
                     f"(logged to the WAL) AND the cap: {HATCH}=<reason> {cap}")
    else:
        lines.append(f"if it genuinely needs the Mac prefix it with {HATCH}=<reason> (logged to the WAL); "
                     f"consider the cap: {cap}")
    return "\n".join(lines)


# ---------------------------------------------------------------- side effects

def live_heavy_jobs() -> int:
    """Live run_capped wrappers on this host, read from their sidecars (stale files are ignored)."""
    state = os.path.join(os.path.expanduser("~"), ".agent-harness", "state", "run_capped")
    count = 0
    try:
        for name in os.listdir(state):
            if name.endswith(".json") and name[:-5].isdigit():
                try:
                    os.kill(int(name[:-5]), 0)
                    count += 1
                except OSError:
                    pass  # gone, or a recycled pid owned by someone else: a stale sidecar must never block work
    except OSError:
        pass
    return count


def max_heavy_jobs() -> int:
    value = 2
    env = os.environ.get("HARNESS_MAX_HEAVY_MAC", "")
    if re.fullmatch(r"[0-9]{1,6}", env) and int(env) > 0:
        return int(env)
    try:
        import json
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_limits.json")
        if os.path.exists(path):
            value = int(load_json_file(path).get("max_heavy_mac", value))
    except Exception:  # incl. safe_input.InputRejected (FIFO, device, oversize): keep defaults
        pass
    return value


def log_event(record: dict) -> None:
    try:
        import json
        from datetime import datetime, timezone
        os.makedirs(os.path.dirname(LOG_PATH), mode=0o700, exist_ok=True)
        record = dict(record, at=datetime.now(timezone.utc).isoformat())
        with open(LOG_PATH, "a") as handle:
            handle.write(json.dumps(record) + "\n")
    except Exception:
        pass


def warn(message: str) -> None:
    try:
        sys.stderr.write(f"heavy_job_guard: warning: {message}\n")
    except Exception:
        pass


def log_hatch_to_wal(payload: dict, decision: dict) -> None:
    """Record every escape-hatch use in the session WAL (the reason, never the command text)."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from datetime import datetime, timezone
        from pathlib import Path
        import wal
        import wal_note
        session = payload.get("session_id")
        if not session:
            raise ValueError("no session_id")
        reason = decision["hatch_reason"]
        if wal_note.SECRET_PATTERN.search(reason):
            reason = "[redacted]"
        note = (f"HARNESS_LOCAL_OK used: rule={decision['rule']} ({decision['detail'][:80]}); reason={reason[:300]}")
        record = {"at": datetime.now(timezone.utc).isoformat(), "event": "decision", "note": note}
        root = Path.home() / ".claude" / "wals" / wal.safe_id(session)
        targets = [root / "main.jsonl"]
        if payload.get("agent_id"):
            agent_wal = root / f"agent-{wal.safe_id(payload['agent_id'])}.jsonl"
            if agent_wal.exists():
                targets.append(agent_wal)
        for target in targets:
            wal.append(target, record)
    except Exception as error:
        warn(f"could not write the escape-hatch record to the WAL ({type(error).__name__})")
        log_event({"event": "hatch-wal-failed", "error": type(error).__name__})


# ---------------------------------------------------------------- hatch limit, disk budget, ring events (P12)

def hatch_limit() -> int:
    """Escape-hatch uses allowed per owner per hour. Default 1 (NEVER-LOSE P12/I13): the hatch is for one
    unanticipated local step, and a sequence of copies is exactly the shape that filled the disk."""
    env = os.environ.get("HARNESS_HATCH_PER_HOUR", "")
    if re.fullmatch(r"[0-9]{1,4}", env) and int(env) > 0:
        return int(env)
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "heavy_job_guard.json")
        if os.path.exists(path):
            value = int(load_json_file(path).get("hatch_per_hour", 1))
            if value > 0:
                return value
    except Exception:
        pass
    return 1


def owner_of(payload: dict) -> str:
    """Stable owner key: the sub-agent id when there is one, else the session id."""
    for key in ("agent_id", "session_id"):
        value = payload.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value):
            return value
    return "unknown"


def state_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".agent-harness", "state")


def record_hatch_use(owner: str, limit: int, now: float = None):
    """Atomically count this use. Returns (allowed, uses in the last hour, counting this one when allowed)."""
    import fcntl
    import json
    now = time.time() if now is None else now
    os.makedirs(state_dir(), mode=0o700, exist_ok=True)
    path = os.path.join(state_dir(), "heavy-hatch.json")
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            data = load_json_file(path, 1024 * 1024)
        except Exception:
            data = {}
        uses = {k: [min(t, now) for t in v if isinstance(t, (int, float)) and -300 <= now - t < 3600]
                for k, v in data.items() if isinstance(v, list)}
        mine = uses.get(owner, [])
        if len(mine) >= limit:
            return False, len(mine)
        mine.append(now)
        uses[owner] = mine
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w") as handle:
            json.dump({k: v for k, v in uses.items() if v}, handle)
        os.replace(tmp, path)
        return True, len(mine)
    finally:
        os.close(fd)


HATCH_DISK_REFUSE_PCT = 85.0


def disk_used_pct() -> float:
    import shutil
    try:
        probe = "/System/Volumes/Data" if os.path.isdir("/System/Volumes/Data") else os.path.expanduser("~")
        usage = shutil.disk_usage(probe)
        return 100.0 * usage.used / usage.total
    except Exception:
        return 0.0


def work_owner_key(path):
    """'session/sub' of the work dir owning `path`, else None."""
    root = os.path.join(os.path.expanduser("~"), ".agent-harness", "work") + os.sep
    real = os.path.realpath(path) if path else ""
    for candidate in (path, real):
        if candidate and candidate.startswith(root):
            parts = candidate[len(root):].split(os.sep)
            if len(parts) >= 2 and parts[0] and parts[1]:
                return f"{parts[0]}/{parts[1]}"
    return None


def agent_of_key(key: str) -> str:
    """Same identity ops_watch uses: the sub-agent id of work/<session>/agent-<id>, else '<session8>-<sub>'."""
    sess, _, sub = key.partition("/")
    agent = sub[len("agent-"):] if sub.startswith("agent-") and len(sub) > 6 else f"{sess[:8]}-{sub}"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", agent)[:80]


def record_epoch(rec) -> float:
    """When the record was measured: measured_at_epoch, else the ISO measured_at of the agreed contract shape."""
    try:
        return float(rec["measured_at_epoch"])
    except (KeyError, TypeError, ValueError):
        pass
    from datetime import datetime, timezone
    text = str(rec.get("measured_at", "")).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text if "T" not in text or len(text) > 16 else text + ":00")
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return 0.0


def over_budget(cwd):
    """The over-budget record covering cwd, re-measured live so freeing space unblocks at once.

    Source: state/disk-budget/<agent>.json written by ops_watch (agent, budget_bytes, used_bytes, measured_at,
    over_since; path_key optional). A live walk that cannot finish in time does NOT clear the block: only a
    complete measurement under budget does."""
    try:
        directory = os.path.join(state_dir(), "disk-budget")
        records = [load_json_file(os.path.join(directory, n), 64 * 1024) for n in os.listdir(directory) if n.endswith(".json")]
    except Exception:
        return None
    key = work_owner_key(cwd)
    if not key:
        return None
    for rec in records:
        try:
            if rec.get("over_since") is None:
                continue
            if rec.get("path_key") != key and rec.get("agent") != agent_of_key(key):
                continue
            age = time.time() - record_epoch(rec)
            if age > 3 * 3600 or age < -300:
                continue  # stale, or stamped in the future: a record must never block work for good
            base = os.path.join(os.path.expanduser("~"), ".agent-harness", "work", key)
            budget = int(rec["budget_bytes"])
            size, complete = path_size(base, cap=budget + 1, seconds=1.0)
            if size > budget or not complete:
                return dict(rec, path_key=key, used_bytes=max(size, int(rec.get("used_bytes", 0))))
        except Exception:
            continue
    return None


def ring_event(key: str, severity: str, message: str, detail: dict) -> None:
    """One ring event per refusal or hatch use (contract with ahd and the console): never command text or raw paths."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import ops_watch
        ops_watch.emit({"host": ops_watch.default_host(), "source": "heavy-guard", "event": "raise",
                        "severity": severity, "check": "heavy-guard", "key": key, "message": message[:300],
                        "detail": detail})
    except Exception as error:
        log_event({"event": "ring-failed", "error": type(error).__name__})


def path_digest(path) -> str:
    import hashlib
    return hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:12]


def event_class(decision: dict) -> str:
    detail = decision.get("detail", "")
    if detail.startswith(("git clone", "gh repo clone")):
        return "clone"
    return "tar" if detail.startswith("tar") else "copy"


def copy_event_detail(payload: dict, decision: dict, hatch_uses=None) -> dict:
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else ""
    match = re.search(r"at least ([0-9.]+) GiB", decision.get("detail", ""))
    return {"agent": owner_of(payload), "task": work_owner_key(cwd) or "", "host": "mac",
            "est_bytes": int(float(match.group(1)) * GIB) if match else None, "path_digest": path_digest(cwd),
            "route": route_host(), "hatch_uses_1h": hatch_uses}


def run(raw: bytes) -> int:
    import json
    try:
        payload = parse_payload(raw)
    except ValueError:  # too large, too deeply nested, not UTF-8/JSON: never block Bash over a payload we cannot read
        warn("payload too large, too deeply nested or malformed; failing open")
        log_event({"event": "fail-open", "reason": "payload-shape"})
        return 0
    if not isinstance(payload, dict):
        return 0
    tool = str(payload.get("tool_name") or payload.get("toolName") or "Bash").casefold()
    tool_input = payload.get("tool_input") or payload.get("toolInput")
    if not (tool == "bash" or tool.startswith(("shell", "exec", "local_shell"))):
        return 0  # Codex names its shell tools shell/exec_command/local_shell; Claude Code says Bash
    command = None
    if isinstance(tool_input, dict):
        command = tool_input.get("command") if tool_input.get("command") is not None else tool_input.get("cmd")
        if isinstance(command, list) and all(isinstance(c, str) for c in command):
            import shlex
            command = shlex.join(command)
        if isinstance(tool_input.get("workdir"), str) and not isinstance(payload.get("cwd"), str):
            payload = dict(payload, cwd=tool_input["workdir"])
    if not isinstance(command, str):
        return 0
    decision = decide(command, payload.get("cwd") if isinstance(payload.get("cwd"), str) else None)
    action = decision["action"]
    owner = owner_of(payload)
    if decision.get("rule") in ("copy", "build") and action != "warn":
        budget = over_budget(payload.get("cwd"))
        if budget:  # over its disk budget: new heavy local writes stop, hatch or not, until it frees space or routes
            gib = lambda n: f"{int(n) / GIB:.1f}"  # noqa: E731
            sys.stderr.write(routed(f"Heavy-job guard [{decision['rule']}]: owner work dir {budget['path_key']} is over its {gib(budget['budget_bytes'])} GiB "
                             f"disk budget ({gib(budget['used_bytes'])} GiB used). Free space there (nothing is deleted for you) or "
                             "run the heavy job on dev2/T2 (ssh dev2 '<command>').\n"))
            log_event({"event": "deny-over-budget", "rule": decision["rule"]})
            ring_event(f"heavy:{event_class(decision)}:{owner}", "high", f"{owner} refused a heavy {decision['rule']}: over disk budget",
                       dict(copy_event_detail(payload, decision), used_bytes=budget["used_bytes"],
                            budget_bytes=budget["budget_bytes"]))
            return 2
    if action == "allow" and decision.get("hatch_reason") and decision.get("rule") not in NEVER_BLOCK:
        if decision.get("rule") == "copy" and disk_used_pct() >= HATCH_DISK_REFUSE_PCT:
            sys.stderr.write(routed(f"Heavy-job guard [copy]: the disk is above {HATCH_DISK_REFUSE_PCT:.0f}% used, so {HATCH} does not "
                             "apply to large copies. Run it on dev2/T2 (ssh dev2 '<command>') or free space first.\n"))
            log_event({"event": "deny-hatch-disk", "rule": "copy"})
            ring_event(f"heavy:{event_class(decision)}:{owner}", "high", f"{owner} refused a hatch copy: disk above 85%",
                       copy_event_detail(payload, decision))
            return 2
        if live_heavy_jobs() >= max_heavy_jobs():  # refuse BEFORE spending this owner's hourly use
            sys.stderr.write(routed(f"Heavy-job guard: {live_heavy_jobs()} heavy jobs are already running on the Mac (limit "
                             f"{max_heavy_jobs()}). Queue this one until a run finishes, or run it on dev2 (ssh dev2 '<command>').\n"))
            log_event({"event": "deny-concurrency", "rule": decision["rule"]})
            return 2
        allowed, uses = record_hatch_use(owner, hatch_limit())
        if not allowed:
            sys.stderr.write(routed(f"Heavy-job guard: {HATCH} was already used {uses} time(s) in the last hour by this owner "
                             f"(limit {hatch_limit()}). More than that is heavy work on the Mac: run it on dev2/T2 "
                             "(ssh dev2 '<command>') or raise the budget in the run kit.\n"))
            log_event({"event": "deny-hatch-limit", "rule": decision["rule"]})
            ring_event(f"heavy:hatch:{owner}", "warning", f"{owner} exceeded the {HATCH} limit ({uses}/h)",
                       dict(copy_event_detail(payload, decision), hatch_uses_1h=uses))
            return 2
        decision["hatch_uses_1h"] = uses
    if (action == "allow" and decision.get("hatch_reason") and decision.get("rule") not in NEVER_BLOCK
            and live_heavy_jobs() >= max_heavy_jobs()):
        sys.stderr.write(routed(f"Heavy-job guard: {live_heavy_jobs()} heavy jobs are already running on the Mac (limit "
                         f"{max_heavy_jobs()}). Queue this one until a run finishes, or run it on dev2 (ssh dev2 '<command>').\n"))
        log_event({"event": "deny-concurrency", "rule": decision["rule"]})
        return 2
    if action == "allow":
        if decision.get("hatch_reason"):
            log_hatch_to_wal(payload, decision)
            log_event({"event": "hatch", "rule": decision["rule"]})
            ring_event(f"heavy:hatch:{owner}", "warning", f"{owner} used {HATCH} for rule {decision['rule']}",
                       dict(copy_event_detail(payload, decision, decision.get("hatch_uses_1h")), rule=decision["rule"]))
        return 0
    log_event({"event": action, "rule": decision["rule"]})  # never the command text: it may carry secrets
    if action == "deny" and decision["rule"] == "copy":
        ring_event(f"heavy:{event_class(decision)}:{owner}", "warning",
                   f"{owner} refused a heavy {event_class(decision)} on the Mac", copy_event_detail(payload, decision))
    if action == "warn":
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "additionalContext": "WARNING (warn mode) " + decision["message"]}}))
        return 0
    sys.stderr.write(decision["message"] + "\n")
    return 2


def main() -> int:
    if sys.platform != "darwin" and os.environ.get("HARNESS_HEAVY_GUARD_FORCE") != "1":
        return 0  # dev2 and other hosts are where the heavy work is supposed to run
    if os.environ.get("HARNESS_HEAVY_GUARD") == "off":
        return 0
    try:
        import safe_input
        try:
            raw = safe_input.read_stdin_bounded(8 * 1024 * 1024)
        except safe_input.InputRejected as rejected:
            warn(f"stdin rejected ({rejected.code}); failing open")
            log_event({"event": "fail-open", "reason": rejected.code})
            return 0
        return run(raw)
    except Exception as error:  # fail open: a guard bug must never block every Bash call
        warn(f"internal error {type(error).__name__}; failing open")
        log_event({"event": "fail-open", "reason": type(error).__name__})
        return 0


if __name__ == "__main__":
    sys.exit(main())
