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

Classification looks at the command word of each shell segment, never at quoted
text, so `git commit -m "run pytest"` or `grep pytest` are never flagged.
Stdlib only, Python 3.9 compatible, lazy imports to keep startup small.
"""
from __future__ import annotations

import os
import re
import stat
import sys

MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_COMMAND_CHARS = 100_000
MAX_SCRIPT_BYTES = 256 * 1024
DEFAULT_MODES = {"browser": "enforce", "adversarial": "warn", "full-suite": "enforce",
                 "build": "enforce", "media": "warn", "fan-out": "warn"}
CAPPED_RULES = {"browser", "media", "fan-out"}  # memory hogs: hatch alone is not enough
NEVER_BLOCK = {"adversarial"}  # red-team/fuzz work is legitimate: advise (dev2, group cleanup), never deny
HATCH = "HARNESS_LOCAL_OK"
LOG_PATH = os.path.join(os.path.expanduser("~"), ".agent-harness", "logs", "heavy-job-guard.jsonl")

PREFILTER = re.compile(
    r"playwright|puppeteer|chrom|selenium|cypress|pytest|py\.test|unittest|\bnpm\b|\bpnpm\b|\byarn\b|\bbun|"
    r"vitest|jest|\bnext\b|\bvite\b|webpack|docker|cargo|dotnet|\bgo\b|ffmpeg|whisper|xargs|parallel|"
    r"python|\bnode\b|\btsx\b|ts-node|deno|perl|ruby|\bsh\b|bash|zsh|run_capped|HARNESS_LOCAL_OK|npx|uvx?\b|"
    r"poetry|pipenv|pdm|/dev/zero|/dev/u?random|mkfifo|\bcat\b",
    re.I)

RULE_HELP = {
    "browser": "browser automation (Playwright/Puppeteer/headless Chrome) can spawn dozens of renderers",
    "adversarial": "hostile-input, fuzz or unbounded-read test code can grow without limit",
    "full-suite": "a full test suite is long and CPU/memory heavy",
    "build": "a production build is CPU/memory heavy",
    "media": "large media work (ffmpeg/whisper) is CPU/memory heavy",
    "fan-out": "parallel fan-out multiplies memory use",
}


# ---------------------------------------------------------------- input safety

def json_depth_ok(raw: str) -> bool:
    """Reject deeply nested JSON before json.loads: Python 3.9's C scanner can SIGABRT."""
    if len(raw) > MAX_PAYLOAD_BYTES:
        return False
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', raw)
    brackets = re.findall(r"[\[\]{}]", stripped)
    if len(brackets) > 20000:
        return False
    depth = 0
    for ch in brackets:
        if ch in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        else:
            depth -= 1
    return True


# ---------------------------------------------------------------- shell scanning

HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][\w.-]*)\2")


def extract_heredocs(text: str):
    """Return (text without heredoc bodies, [bodies]). Unterminated heredocs are left alone."""
    lines = text.split("\n")
    out, bodies, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        for match in HEREDOC.finditer(line):
            if line[max(0, match.start() - 1):match.start()] == "<":  # here-string <<<
                continue
            strip_tabs, term = match.group(1) == "-", match.group(3)
            j = i
            while j < len(lines) and (lines[j].strip() if strip_tabs else lines[j]) != term:
                j += 1
            if j < len(lines):
                bodies.append("\n".join(lines[i:j]))
                i = j + 1
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


def tokenize(segment: str):
    import shlex
    try:
        return shlex.split(segment)
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


# ---------------------------------------------------------------- classification

REMOTE_CMDS = {"ssh", "scp", "sftp", "rsync", "mosh", "sshpass"}
PYTHON = re.compile(r"^(?:python|pypy)[\d.]*$")
NODE_RUNNERS = {"node", "nodejs", "tsx", "ts-node", "deno", "esno"}
PM = {"npm", "pnpm", "yarn", "bun", "bunx"}
WRAPPERS = {"env", "sudo", "nohup", "time", "command", "exec", "nice", "caffeinate", "stdbuf", "arch",
            "setsid", "builtin"}
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


class Ctx:
    def __init__(self, cwd, heredocs):
        self.cwd = cwd or os.getcwd()
        self.heredocs = heredocs
        self.capped = False


def resolve(path: str, cwd: str) -> str:
    path = os.path.expandvars(os.path.expanduser(path))
    return path if os.path.isabs(path) else os.path.join(cwd, path)


def read_script(path: str, cwd: str):
    try:
        full = resolve(path, cwd)
        # Regular files only: opening a FIFO or /dev/zero-style device would hang or spin the hook.
        if not stat.S_ISREG(os.stat(full).st_mode):
            return None
        with open(full, "r", errors="replace") as handle:
            return handle.read(MAX_SCRIPT_BYTES)
    except (OSError, ValueError):
        return None


def script_sources(script, ctx):
    """The script's on-disk text plus any heredoc bodies in the same command (it may be written then run)."""
    sources = list(ctx.heredocs)
    disk = read_script(script, ctx.cwd) if script and script != "-" else None
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
    if any(HOSTILE.search(x) for x in hostile_src) or SCRATCH_RT.search(resolved):
        return ("adversarial", "script reads /dev/zero|urandom, makes a FIFO, or lives in a scratchpad rt/ dir")
    if any(PY_BROWSER_IMPORT.search(x) and BROWSER_LAUNCH.search(x) for x in browser_src):
        return ("browser", "python script that drives a browser (imports playwright/selenium)")
    return None


def is_focused_test(args):
    return any(FILE_TARGET.search(t) for t in positional(args, ("-t", "--testNamePattern", "-c", "--config")))


def classify_pm(name, args):
    """npm/pnpm/yarn/bun: tests and builds. Returns None, (rule, detail) or ('recurse', argv)."""
    valued = ("--prefix", "-C", "--filter", "-F", "-w", "--workspace", "--cwd", "--dir")
    pos = positional(args, valued)
    if not pos:
        return None
    sub, rest = pos[0], pos[1:]
    if sub in ("exec", "dlx", "x") and rest:
        return ("recurse", rest)
    if sub in ("run", "run-script") and rest:
        sub, rest = rest[0], rest[1:]
    if re.match(r"^(?:test|t|tst)(?:[:_-].*)?$", sub):
        after = args[args.index(sub) + 1:] if sub in args else []
        return None if is_focused_test(after) else ("full-suite", f"{name} {sub}")
    if re.match(r"^build(?:[:_-].*)?$", sub) or sub in ("compile", "bundle"):
        return ("build", f"{name} {sub}")
    return None


def classify(argv, ctx, depth=0):
    """Classify one command's argv. Returns (rule, detail) or None."""
    _assigns, argv = split_assignments(argv)
    if not argv or depth > 4:
        return None
    cmd = base(argv[0])
    low = cmd.lower()
    args = argv[1:]

    if low in REMOTE_CMDS:
        return None  # already off-box
    if cmd == "run_capped.py":
        ctx.capped = True
        return classify(args[args.index("--") + 1:] if "--" in args else [], ctx, depth + 1)
    if low in WRAPPERS:
        rest = list(args)
        while rest and (rest[0].startswith("-") or ASSIGN.match(rest[0]) or rest[0].isdigit()):
            rest = rest[1:]
        return classify(rest, ctx, depth + 1)
    if low in ("timeout", "gtimeout"):
        rest = list(args)
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("-s", "-k") else rest[1:]
        return classify(rest[1:], ctx, depth + 1)
    if low in ("bash", "sh", "zsh", "dash", "ksh"):
        for i, a in enumerate(args):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and i + 1 < len(args):
                return classify_text(args[i + 1], ctx, depth + 1)
        script = (positional(args) or [None])[0]
        if script and any(HOSTILE.search(s) for s in script_sources(script, ctx)):
            return ("adversarial", "shell script reads /dev/zero|urandom or makes a FIFO")
        return None
    if low in ("uv", "poetry", "pipenv", "pdm", "hatch", "rye") and "run" in args:
        rest = args[args.index("run") + 1:]
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        return classify(rest, ctx, depth + 1)
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
        if "-m" in args and args.index("-m") + 1 < len(args):
            module = args[args.index("-m") + 1]
            margs = args[args.index("-m") + 2:]
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
        return python_findings(args, ctx)
    if cmd.endswith(".py"):  # direct ./script.py execution
        return python_findings([argv[0]], ctx)
    if low in NODE_RUNNERS:
        script = next(iter(positional(args)), None)
        if script and re.search(r"\.[cm]?[jt]s$", script):
            sources = script_sources(script, ctx)
            if any(HOSTILE.search(s) for s in sources):
                return ("adversarial", "node script reads /dev/zero|urandom or makes a FIFO")
            if any(JS_BROWSER_IMPORT.search(s) and BROWSER_LAUNCH.search(s) for s in sources):
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
        inner = [a for a in args if not a.startswith("-") and not a.isdigit()]
        if inner and base(inner[0]) in LIGHT_XARGS:
            return None  # parallel grep/echo/stat is cheap; only fan-out of real work matters
        for i, a in enumerate(args):
            value = None
            if a in ("-P", "--max-procs") and i + 1 < len(args):
                value = args[i + 1]
            elif a.startswith("--max-procs="):
                value = a.split("=", 1)[1]
            elif re.match(r"^-P\d+$", a):
                value = a[2:]
            if value is not None and value.isdigit() and (int(value) == 0 or int(value) >= 3):
                return ("fan-out", f"xargs -P {value}")
        return None
    if low == "parallel":
        return None if ("--version" in args or "--help" in args) else ("fan-out", "GNU parallel")
    return None


def scan_state(command: str, cwd: str):
    """Walk every segment. Returns (hatch_reason_or_None, [(rule, detail, capped, segment)])."""
    text, heredocs = extract_heredocs(command[:MAX_COMMAND_CHARS])
    ctx = Ctx(cwd, heredocs)
    hatch, findings = None, []
    for segment in split_segments(text):
        argv = tokenize(segment)
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
        result = classify(argv, ctx)
        if result:
            findings.append((result[0], result[1], ctx.capped, segment))
    return hatch, findings


def classify_text(text, ctx, depth):
    """Classify a nested `bash -c` string with the parent's cwd."""
    _hatch, findings = scan_state(text, ctx.cwd)
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
            with open(path) as handle:
                for rule, mode in (json.load(handle).get("modes") or {}).items():
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


def decide(command: str, cwd: str = None, modes=None):
    """Pure decision: dict(action=allow|warn|deny, rule, detail, message, hatch_reason)."""
    if not command or not PREFILTER.search(command):
        return {"action": "allow"}
    modes = modes or load_modes()
    hatch, findings = scan_state(command, cwd)
    for rule, detail, capped, _segment in findings:
        mode = modes.get(rule, "enforce")
        if mode == "off":
            continue
        if rule in NEVER_BLOCK and capped:
            continue  # group cleanup is the requested safety; nothing to say
        if valid_reason(hatch) and (capped or rule not in CAPPED_RULES):
            return {"action": "allow", "rule": rule, "detail": detail, "hatch_reason": hatch.strip()}
        return {"action": "deny" if mode == "enforce" else "warn", "rule": rule, "detail": detail,
                "message": deny_message(rule, detail, hatch, capped)}
    return {"action": "allow"}


def deny_message(rule, detail, hatch, capped):
    cap = "python3 ~/.claude/hooks/run_capped.py --max-rss-gb <declared peak x1.5> --timeout-s <expected x2> -- <command>"
    if rule in NEVER_BLOCK:
        return (f"Heavy-job guard [{rule}] advisory (not blocked): {RULE_HELP[rule]} ({detail}). Hostile-input tests are "
                f"legitimate. Prefer dev2 (ssh dev2 '<command>'), or on the Mac run under {cap} so stopping the test also "
                "stops its children and a runaway is paused instead of resetting the machine.")
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


def run(raw: str) -> int:
    import json
    if not json_depth_ok(raw):
        warn("payload too large or too deeply nested; failing open")
        log_event({"event": "fail-open", "reason": "payload-shape"})
        return 0
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("tool_name", "Bash") != "Bash":
        return 0
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0
    decision = decide(command, payload.get("cwd") if isinstance(payload.get("cwd"), str) else None)
    action = decision["action"]
    if action == "allow":
        if decision.get("hatch_reason"):
            log_hatch_to_wal(payload, decision)
            log_event({"event": "hatch", "rule": decision["rule"]})
        return 0
    log_event({"event": action, "rule": decision["rule"], "argv0": command.strip().split(" ", 1)[0][:60]})
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
        return run(sys.stdin.read(MAX_PAYLOAD_BYTES + 1))
    except Exception as error:  # fail open: a guard bug must never block every Bash call
        warn(f"internal error {type(error).__name__}; failing open")
        log_event({"event": "fail-open", "reason": type(error).__name__})
        return 0


if __name__ == "__main__":
    sys.exit(main())
