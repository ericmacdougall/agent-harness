#!/usr/bin/env python3
"""AC-13 launch guard for the ahc daemon process (goodqa#16049 slice 1 (b), spec r9).

Scope, as the spec states it: a regression detector and a launch-time policy for the daemon's own code, not a sandbox.
It checks what the daemon process launches and connects to at the moment of the call. It does not cover what an
allowed child does once it runs, the R3 review unit, code that bypasses Python's audit hooks (ctypes, C extensions),
same-uid writes (L10), or processes other than the daemon.

How it works:
- `install(policy)` adds one process-wide `sys.addaudithook` and one `sys.meta_path` finder, once per process. Both
  consult the active Policy and do nothing while none is active, so a test process can activate a policy for one
  test and clear it in tearDown (`deactivate`). The daemon's `run` command activates its policy once at start.
- Launches: every `subprocess.Popen` event is checked before the fork; `os.exec*`, `os.posix_spawn*`, `os.system`,
  `os.fork*` and `os.popen` events are refused outright (the daemon launches only through subprocess). A refused
  launch raises LaunchRefused, so the child never exists.
- Each allowed executable is resolved once, at policy creation, from a fixed trusted directory list, never from
  PATH; it is refused at resolution and again at every launch if it is group- or other-writable or owned by anyone
  but root or the daemon uid. argv[0] and the executable must be that absolute path. env is passed explicitly and
  equals the form's minimal environment; cwd is passed explicitly and lies under the daemon's root.
- Per executable, a table in code lists subcommands, options and positional types (git, gh, systemd-run,
  systemctl, lsof, fuser, sysctl and the legacy Python helpers). Anything else is refused.
- systemd-run and W21's update-branch PUT need a one-shot expectation armed by core from a committed record; it is
  consumed by the launch that matches it byte for byte.
- Connections: socket.connect, sendto and sendmsg to anything but an AF_UNIX path under the root are refused, and
  socket.getaddrinfo and gethostbyname are refused outright. Provider SDK imports are refused by the finder and the
  `import` audit event, including importlib at runtime.

The READ_TEMPLATES table (builder ticket T11) is the one list of GitHub read endpoints: AC-1's producer reads
through it and the gh form allows only endpoints that fill one of its templates.
"""
from __future__ import annotations

import hashlib
import importlib.abc
import json
import os
import re
import socket
import stat
import sys
from pathlib import Path

TRUSTED_DIRS = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin")
# The user unit's PATH (ahc_install) puts these per-user directories first, so the daemon resolves the same gh
# and git it ran before AC-13 (ASSUMPTION: a file there must still be owned by the daemon uid and not group- or
# other-writable).
HOME_DIRS = (".local/bin", "bin", ".npm-global/bin")
EXECUTABLES = ("git", "gh", "systemd-run", "systemctl", "lsof", "fuser", "sysctl")
PROVIDER_MODULES = ("anthropic", "openai", "google.genai", "google.generativeai", "mistralai", "cohere")
HTTP_MODULES = ("urllib.request", "http.client", "requests", "httpx", "aiohttp", "urllib3")
REFUSED_EVENTS = ("os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "os.popen")
SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
UNIT = re.compile(r"ahc-review-[A-Za-z0-9-]{1,128}\.service")
REVIEW_SLICE = "ahc-review.slice"
ROLE_UNITS = ("ahc-core.service", "ahc-review.service")
SHOW_PROPS = ("InvocationID", "ActiveState", "SubState", "MainPID", "ExecMainStatus", "Result")
RECOVERY_PROPS = ("Slice", "ActiveState", "SubState")

# T11: the GitHub read templates, with their pagination and byte caps (AC-1 reads only through these)
READ_TEMPLATES = {
    "pull": {"path": re.compile(r"repos/(?P<repo>[^/]+/[^/]+)/pulls/(?P<pr>[1-9][0-9]{0,9})"), "paginate": False,
             "max_bytes": 2_000_000},
    "ref": {"path": re.compile(r"repos/(?P<repo>[^/]+/[^/]+)/git/ref/heads/(?P<branch>[A-Za-z0-9._/-]{1,200})"),
            "paginate": False, "max_bytes": 64_000},
    "check_runs": {"path": re.compile(r"repos/(?P<repo>[^/]+/[^/]+)/commits/(?P<sha>[0-9a-f]{40})/check-runs"
                                      r"(\?per_page=100(&filter=all)?)?"), "paginate": True, "max_bytes": 8_000_000},
    "statuses": {"path": re.compile(r"repos/(?P<repo>[^/]+/[^/]+)/commits/(?P<sha>[0-9a-f]{40})/statuses"
                                    r"(\?per_page=100)?"), "paginate": True, "max_bytes": 8_000_000},
    "commit": {"path": re.compile(r"repos/(?P<repo>[^/]+/[^/]+)/commits/(?P<sha>[0-9a-f]{40})"), "paginate": False,
               "max_bytes": 4_000_000},
    "repo": {"path": re.compile(r"repos/(?P<repo>[^/]+/[^/]+)"), "paginate": False, "max_bytes": 512_000},
}
GH_HEADERS = ("Accept: application/vnd.github+json", "X-GitHub-Api-Version: 2022-11-28")
# gh pr view --json fields: the legacy fields at 4d45fe40 plus AC-1's
PR_FIELDS = frozenset(("number", "state", "headRefOid", "mergeCommit", "baseRefName", "baseRefOid", "isDraft",
                       "mergeable", "mergeStateStatus", "body", "updatedAt", "changedFiles", "headRepository",
                       "headRepositoryOwner", "title", "url", "isCrossRepository"))
# Legacy helpers: the installed scripts only (never a path from config), and the keys of their environment, whose
# values are fixed when the policy is made (ASSUMPTION: the helpers run model CLIs and ah, which need the daemon's
# own PATH and HOME; every other inherited key, such as GIT_* or a provider key, is dropped).
HELPER_SCRIPTS = {"ah": "ah.py", "ops_watch": "ops_watch.py", "peer_review": "peer_review.py"}
HELPER_ENV_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "XDG_RUNTIME_DIR")
W21_PUT = re.compile(r"repos/(?P<repo>[^/]+/[^/]+)/pulls/(?P<pr>[1-9][0-9]{0,9})/update-branch")


RELEASE_LIST = Path(__file__).resolve().parent / "ahc_release.json"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def release_helpers(path=None):
    """{helper name: sha256} from the installed release list's "helpers" section. A missing or unreadable list, or
    a malformed entry, binds nothing, so every helper launch is refused (fail closed)."""
    try:
        data = json.loads(Path(path or RELEASE_LIST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    helpers = data.get("helpers") if isinstance(data, dict) else None
    if not isinstance(helpers, dict):
        return {}
    return {n: h for n, h in helpers.items() if n in HELPER_SCRIPTS and isinstance(h, str) and SHA256_HEX.fullmatch(h)}


class LaunchRefused(RuntimeError):
    """A launch, connection or import the daemon's policy does not allow (AC-13)."""


def template_of(endpoint):
    """(name, match) of the READ_TEMPLATES entry the endpoint fills in full, or (None, None)."""
    for name, t in READ_TEMPLATES.items():
        m = t["path"].fullmatch(endpoint)
        if m:
            return name, m
    return None, None


def _canon_argv(argv):
    return json.dumps([str(a) for a in argv], separators=(",", ":"))


def argv_digest(argv):
    """The sha256 of a command line's canonical encoding (AC-8's committed launch-intent digest)."""
    return hashlib.sha256(_canon_argv(argv).encode("utf-8")).hexdigest()


def _under(path, root):
    try:
        real = os.path.realpath(str(path))
    except (TypeError, ValueError):
        return False
    root = os.path.realpath(str(root))
    return real == root or real.startswith(root + os.sep)


def trusted_dirs(home):
    """The fixed trusted directory list for a daemon whose HOME is `home`."""
    return tuple(os.path.join(str(home), d) for d in HOME_DIRS) + TRUSTED_DIRS


def resolve(name, dirs):
    """The first trusted, executable `name` in `dirs`, as an absolute path, or None. Never PATH."""
    for d in dirs:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK) and trusted_file_problem(p) is None:
            return p
    return None


USER_BUS_FORMS = ("systemctl", "systemd-run")


def user_bus_env(uid=None):
    """The daemon's own user manager bus (goodqa#16386): XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS derived from
    the running uid, never read from the caller's environment. Without them a guarded `systemctl --user` or
    `systemd-run --user` fails with "Failed to connect to bus: No medium found"."""
    runtime = "/run/user/%d" % (os.getuid() if uid is None else uid)
    return {"XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": "unix:path=%s/bus" % runtime}


def form_env(name, dirs, home, gh_auth=None, unit_scope=""):
    """The minimal environment of one executable's form: fixed keys and values only. systemctl and systemd-run in
    the --user scope also get the uid-derived user bus (user_bus_env); nothing else does."""
    base = {"PATH": ":".join(dirs), "HOME": str(home), "LC_ALL": "C"}
    if name in USER_BUS_FORMS and unit_scope == "--user":
        base.update(user_bus_env())
    if name == "git":
        base.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"})
    elif name == "gh":
        base.update({"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1"})
        if gh_auth:
            base["GH_TOKEN"] = gh_auth
    return base


def trusted_file_problem(path):
    """Why an executable or helper file is not trusted, or None: it must be a regular file, not group- or
    other-writable, and owned by root or the daemon uid."""
    try:
        st = os.stat(path)
    except OSError as error:
        return "%s: %s" % (path, type(error).__name__)
    if not stat.S_ISREG(st.st_mode):
        return "%s is not a regular file" % path
    if st.st_mode & 0o022:
        return "%s is group- or other-writable" % path
    if st.st_uid not in (0, os.geteuid()):
        return "%s is owned by uid %d" % (path, st.st_uid)
    return None


class Policy:
    """One daemon process's launch and connection policy. Production builds it with `Policy(root, repos=...)`;
    the test constructor `Policy.for_test` maps executables to stub files and may enable the file transport. Fakes
    are never injectable through config or env."""

    def __init__(self, root, *, repos=(), home=None, trusted_dirs=None, helpers=None, unit_scope="--user",
                 gh_auth=None, release=None, _stubs=None, _allow_file=False, _python=None):
        self.root = os.path.realpath(str(root))
        self.clones = os.path.join(self.root, "clones")
        self.repos = {str(r).lower() for r in repos}
        self.home = str(home or Path.home())
        self.trusted = tuple(trusted_dirs) if trusted_dirs is not None else globals()["trusted_dirs"](self.home)
        self.path_env = ":".join(self.trusted)
        self.allow_file = bool(_allow_file)
        self.unit_scope = unit_scope if unit_scope in ("--user", "") else "--user"
        self.gh_auth = gh_auth
        self.exe = {}
        for name in EXECUTABLES:
            path = (_stubs or {}).get(name) if _stubs is not None else self._resolve(name)
            if path and not trusted_file_problem(path):
                self.exe[name] = str(path)
        self.python = str(_python or sys.executable)
        self.helper_env = {k: os.environ[k] for k in HELPER_ENV_KEYS if k in os.environ}
        self.helper_env["LC_ALL"] = "C"
        if helpers is None:
            helpers = {n: os.path.join(self.home, ".claude", "hooks", f) for n, f in HELPER_SCRIPTS.items()}
        # name -> (installed script path, sha256 from the release list): r9 AC-13 binds each helper to its hash in
        # ahc_release.json (owner ruling e); a helper with no release entry is not bound, so it is refused
        self.release = dict(release) if release is not None else release_helpers()
        self.helpers = {}
        for name, script in helpers.items():
            want = self.release.get(name)
            if trusted_file_problem(script) is None and isinstance(want, str) and SHA256_HEX.fullmatch(want):
                self.helpers[name] = (str(script), want)
        self.armed = {}                 # "systemd-run" -> (argv, digest); "w21" -> argv
        self.intent_units = set()       # units of committed R3 launch intents
        self.reconciling = False        # startup reconciliation (AC-8, NEG-49)
        self.slice_ok = set()           # units whose recovery show reported ahc-review.slice
        self.migrating = False          # AC-11 steps 2 and 4: lsof and fuser
        self.incidents = []             # every refusal, for the caller to raise

    @classmethod
    def for_test(cls, root, stubs, **kw):
        """Test constructor only: each executable resolves to the given stub path. Unless the test passes its own
        release list, the given helper files are their own release entries."""
        if "release" not in kw and kw.get("helpers"):
            kw["release"] = {n: hashlib.sha256(Path(p).read_bytes()).hexdigest() for n, p in kw["helpers"].items()
                             if os.path.isfile(str(p))}
        return cls(root, _stubs=dict(stubs), **kw)

    def _resolve(self, name):
        return resolve(name, self.trusted)

    # ------------------------------------------------------------ the forms' environments and argv

    def env(self, name):
        return form_env(name, self.trusted, self.home, self.gh_auth, self.unit_scope)

    def argv(self, name, args):
        if name not in self.exe:
            raise LaunchRefused("%s is not resolved from the trusted directories" % name)
        return [self.exe[name]] + [str(a) for a in args]

    def helper_argv(self, name, args):
        if name not in self.helpers:
            raise LaunchRefused("helper %s is not an installed, trusted script" % name)
        return [self.python, self.helpers[name][0]] + [str(a) for a in args]

    def git_prefix(self):
        import ahc_clone  # noqa: PLC0415
        return list(ahc_clone.SAFE) + (list(ahc_clone.FILE_TRANSPORT) if self.allow_file else [])

    # ------------------------------------------------------------ arming (core, from committed records)

    def arm_unit(self, argv, digest):
        if argv_digest(argv) != digest:
            raise LaunchRefused("the armed command line does not match its committed digest")
        self.armed["systemd-run"] = (list(map(str, argv)), digest)

    def arm_w21(self, argv):
        self.armed["w21"] = list(map(str, argv))

    # ------------------------------------------------------------ the check

    def refuse(self, why):
        self.incidents.append(why)
        raise LaunchRefused(why)

    def check_launch(self, executable, args, cwd, env):
        args = [os.fsdecode(a) if isinstance(a, bytes) else str(a) for a in (args or [])]
        if not args:
            self.refuse("an empty command line")
        exe = os.fsdecode(executable) if isinstance(executable, bytes) else executable
        if exe is not None and str(exe) != args[0]:
            self.refuse("the executable differs from argv[0]")
        name = next((n for n, p in self.exe.items() if p == args[0]), None)
        helper = args[0] == self.python
        if name is None and not helper:
            self.refuse("%s is not an allowed executable (absolute path resolved at start)" % args[0])
        problem = trusted_file_problem(args[0])
        if problem:
            self.refuse("untrusted executable: %s" % problem)
        if env is None:
            self.refuse("a launch must pass its minimal environment explicitly, never inherit it")
        if cwd is None or not _under(cwd, self.root):
            self.refuse("a launch needs an explicit cwd under the daemon root")
        if helper:
            return self._check_helper(args, dict(env))
        if dict(env) != self.env(name):
            self.refuse("%s: the environment differs from its minimal form" % name)
        getattr(self, "_check_" + name.replace("-", "_"))(args[1:], cwd)
        return name

    # git -------------------------------------------------------------------------------------------------------

    GIT_SUB = {
        "clone": ({"--quiet", "--no-checkout", "--template=", "--"}, ("url", "path")),
        "fetch": ({"--quiet", "--no-tags"}, ("origin", "refspec", "sha")),
        "cat-file": ({"-e"}, ("rev",)),
        "checkout": ({"--quiet", "--force", "--detach"}, ("sha",)),
        "clean": ({"-ffdxq"}, ()),
        "rev-parse": ({"--is-shallow-repository", "--verify", "--quiet"}, ("HEAD", "rev")),
        "log": ({"--format=%H%x09%s", "--format=%H%x00%B%x00", "--no-color", "-z"}, ("range",)),
        "diff": ({"--name-only", "--no-renames", "-z", "--name-status", "--find-renames", "--no-color"},
                 ("sha", "range")),
        "merge-base": ({"--is-ancestor"}, ("sha",)),
        "merge-tree": ({"--write-tree"}, ("sha",)),
    }
    REV = re.compile(r"[0-9a-f]{40}(\^\{commit\}|\^\{tree\}|\^1|\^2)?")

    def _git_positional(self, tok, kinds):
        if "sha" in kinds and SHA.fullmatch(tok):
            return True
        if "rev" in kinds and self.REV.fullmatch(tok):
            return True
        if "range" in kinds and re.fullmatch(r"[0-9a-f]{40}\.\.[0-9a-f]{40}", tok):
            return True
        if "origin" in kinds and tok == "origin":
            return True
        if "HEAD" in kinds and tok == "HEAD":
            return True
        if "refspec" in kinds and tok == "+refs/heads/*:refs/remotes/origin/*":
            return True
        if "path" in kinds and _under(tok, self.clones):
            return True
        if "url" in kinds:
            m = re.fullmatch(r"https://github\.com/(%s)\.git" % REPO.pattern, tok)
            if m and m.group(1).lower() in self.repos:
                return True
            if self.allow_file and os.path.isabs(tok) and not tok.startswith("-"):
                return True             # a local fixture remote: test constructor only (_allow_file)
        return False

    def _check_git(self, args, cwd):
        prefix = self.git_prefix()
        if args[:len(prefix)] != prefix:
            self.refuse("git: the command line must start with exactly the SAFE -c pairs")
        rest = args[len(prefix):]
        if rest[:1] == ["-C"]:
            if len(rest) < 2 or not _under(rest[1], self.clones):
                self.refuse("git: -C names a path outside the clones root")
            rest = rest[2:]
        if not rest or rest[0] not in self.GIT_SUB:
            self.refuse("git: subcommand %r is not allowed" % (rest[0] if rest else None))
        options, kinds = self.GIT_SUB[rest[0]]
        for tok in rest[1:]:
            if tok in options:
                continue
            if tok.startswith("-") or not self._git_positional(tok, kinds):
                self.refuse("git %s: %r is not an allowed option or positional" % (rest[0], tok[:60]))

    # gh --------------------------------------------------------------------------------------------------------

    def _check_gh(self, args, cwd):
        if args[:2] == ["pr", "view"]:
            if not (len(args) == 7 and re.fullmatch(r"[1-9][0-9]{0,9}", args[2]) and args[3] == "-R"
                    and args[4].lower() in self.repos and args[5] == "--json"
                    and set(args[6].split(",")) <= PR_FIELDS and args[6]):
                self.refuse("gh pr view: not the allowed form")
            return
        if args[:1] != ["api"]:
            self.refuse("gh: only `pr view` and `api` reads are allowed, not %r" % (args[:1] or [None])[0])
        rest = args[1:]
        if rest[:2] == ["--method", "PUT"]:
            return self._check_w21(args)
        endpoint = None
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok == "--method" and rest[i + 1:i + 2] == ["GET"]:
                i += 2
                continue
            if tok in ("--include", "--paginate"):
                i += 1
                continue
            if tok == "-H" and rest[i + 1:i + 2] and rest[i + 1] in GH_HEADERS:
                i += 2
                continue
            if tok.startswith("-") or endpoint is not None:
                self.refuse("gh api: %r is not allowed" % tok[:60])
            endpoint = tok
            i += 1
        name, m = template_of(endpoint or "")
        if name is None or m.group("repo").lower() not in self.repos:
            self.refuse("gh api: %r fills no read template for a listed repo" % (endpoint or "")[:80])
        if "--paginate" in rest and not READ_TEMPLATES[name]["paginate"]:
            self.refuse("gh api: %s is not a paginated template" % name)

    def _check_w21(self, args):
        armed = self.armed.pop("w21", None)
        if os.environ.get("AHC_W21_SEND") != "1":
            self.refuse("gh api PUT: W21 sending is off (AHC_W21_SEND is not exactly 1)")
        m = W21_PUT.fullmatch(args[3]) if len(args) == 6 else None
        if not (m and m.group("repo").lower() in self.repos and args[4] == "-f"
                and re.fullmatch(r"expected_head_sha=[0-9a-f]{40}", args[5])):
            self.refuse("gh api PUT: only W21's update-branch form")
        if armed is None or [self.exe.get("gh")] + list(args) != armed:
            self.refuse("gh api PUT: no armed W21 expectation, or a different one")

    # systemd-run and systemctl ---------------------------------------------------------------------------------

    def _check_systemd_run(self, args, cwd):
        armed = self.armed.pop("systemd-run", None)
        full = [self.exe["systemd-run"]] + list(args)
        if armed is None:
            self.refuse("systemd-run: no committed launch intent is armed")
        if full != armed[0] or argv_digest(full) != armed[1]:
            self.refuse("systemd-run: the command line differs from the committed intent")

    def _check_systemctl(self, args, cwd):
        scope = [self.unit_scope] if self.unit_scope else []
        if args[:len(scope)] != scope:
            self.refuse("systemctl: the scope flag differs from the R3 runner's mode")
        rest = args[len(scope):]
        if any(t in ("-H", "--host", "-M", "--machine", "--root") or t.startswith(("--host=", "--machine=", "--root="))
               for t in rest):
            self.refuse("systemctl: remote or root flags are refused")
        verb = rest[0] if rest else None
        if verb == "list-units":
            if rest[1:] != ["--plain", "--no-legend", "--all", "ahc-review-*"]:
                self.refuse("systemctl list-units: not the allowed form")
            return
        if verb == "show" and len(rest) == 4 and rest[1] == "-p":
            props, unit = rest[2].split(","), rest[3]
            if set(props) <= set(SHOW_PROPS) and (unit in self.intent_units or unit in ROLE_UNITS):
                return
            if self.reconciling and set(props) <= set(RECOVERY_PROPS) and UNIT.fullmatch(unit):
                return
            self.refuse("systemctl show: not an allowed property set or unit")
        if verb == "is-active" and len(rest) == 2 and (rest[1] in self.intent_units or rest[1] in ROLE_UNITS):
            return
        if verb == "stop" and len(rest) == 2:
            unit = rest[1]
            if unit in self.intent_units:
                return
            if self.reconciling and UNIT.fullmatch(unit) and unit in self.slice_ok:
                return
            self.refuse("systemctl stop %s: not a committed intent's unit, or not a recovery stop in the review "
                        "slice during startup reconciliation" % unit[:80])
        self.refuse("systemctl: verb %r is not allowed" % verb)

    # lsof, fuser, sysctl ---------------------------------------------------------------------------------------

    def _ledger_files(self, files):
        allowed = {os.path.join(self.root, "ledger.sqlite3" + s) for s in ("", "-wal", "-shm")}
        return bool(files) and all(os.path.realpath(f) in {os.path.realpath(a) for a in allowed} for f in files)

    def _check_lsof(self, args, cwd):
        if not (self.migrating and args[:4] == ["-w", "-F", "p", "--"] and self._ledger_files(args[4:])):
            self.refuse("lsof: only during migration, with fixed options, on the ledger files")

    def _check_fuser(self, args, cwd):
        if not (self.migrating and self._ledger_files(args)):
            self.refuse("fuser: only during migration, on the ledger files")

    def _check_sysctl(self, args, cwd):
        if sys.platform != "darwin" or args != ["-n", "kern.bootsessionuuid"]:
            self.refuse("sysctl: only `sysctl -n kern.bootsessionuuid` on macOS")

    # legacy Python helpers -------------------------------------------------------------------------------------

    HELPER_ARGS = {
        "ah": lambda a: (a[:2] in (["ticket", "comment"], ["alert", "raise"], ["alert", "clear"],
                                   ["heartbeat", "beat"])),
        "ops_watch": lambda a: a[:1] in (["capabilities"], ["config"], ["delivered"]),
        "peer_review": lambda a: a[:1] == ["pr"] and "--no-main-stamp" in a and "-c" not in a,
    }

    def _check_helper(self, args, env):
        if env != self.helper_env:
            self.refuse("python helper: the environment differs from the helper form's fixed environment")
        if len(args) < 2 or args[1].startswith("-"):
            self.refuse("python: only a bound helper script, never -c, -m or flags")
        for name, (script, sha) in self.helpers.items():
            if args[1] != script:
                continue
            problem = trusted_file_problem(script)
            if problem or hashlib.sha256(Path(script).read_bytes()).hexdigest() != sha:
                self.refuse("helper %s does not match its sha256 in the release list" % name)
            if not self.HELPER_ARGS[name](args[2:]):
                self.refuse("helper %s: arguments outside its pattern" % name)
            return name
        self.refuse("python: %s is not an installed helper script" % args[1][:120])

    # sockets ---------------------------------------------------------------------------------------------------

    def check_connect(self, sock, address):
        family = getattr(sock, "family", None)
        if family == socket.AF_UNIX and isinstance(address, (str, bytes)):
            path = os.fsdecode(address)
            if path and not path.startswith("\0") and _under(os.path.dirname(path) or ".", self.root):
                return
        self.refuse("connection to %r refused: only AF_UNIX paths under the daemon root" % (str(address)[:80],))


# ---------------------------------------------------------------- process-wide hooks

_ACTIVE = None
_INSTALLED = False


def _is_provider(name):
    return any(name == m or name.startswith(m + ".") for m in PROVIDER_MODULES)


class _ProviderFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if _ACTIVE is not None and _is_provider(fullname):
            _ACTIVE.refuse("import of provider SDK %s refused in the daemon" % fullname)
        return None


def _hook(event, args):
    policy = _ACTIVE
    if policy is None:
        return
    if event == "subprocess.Popen":
        executable, argv, cwd, env = args
        policy.check_launch(executable, argv if isinstance(argv, (list, tuple)) else [argv], cwd, env)
    elif event.startswith(REFUSED_EVENTS):
        policy.refuse("%s refused: the daemon launches children only through subprocess" % event)
    elif event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
        policy.check_connect(args[0], args[1] if len(args) > 1 else None)
    elif event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
                   "socket.gethostbyaddr"):
        policy.refuse("%s refused in the daemon process" % event)
    elif event == "import" and args and isinstance(args[0], str) and _is_provider(args[0]):
        policy.refuse("import of provider SDK %s refused in the daemon" % args[0])


def install(policy):
    """Activate `policy` for this process (installing the hooks on first use). Returns the policy."""
    global _ACTIVE, _INSTALLED
    if not _INSTALLED:
        sys.addaudithook(_hook)
        sys.meta_path.insert(0, _ProviderFinder())
        _INSTALLED = True
    _ACTIVE = policy
    return policy


def deactivate():
    """Clear the active policy (tests only; the daemon never calls it)."""
    global _ACTIVE
    _ACTIVE = None


def active():
    return _ACTIVE


def run(policy, name, args, timeout, cwd=None):
    """The production launcher for one form: the resolved executable, its minimal env and an explicit cwd under the
    root (default: the root). The policy builds the form whether or not it is the active (enforcing) one, so a CLI
    process launches the same way the daemon does. Returns (rc, stdout, stderr) as ahc_core.run_argv does."""
    import ahc_core  # noqa: PLC0415
    return ahc_core.run_argv(policy.argv(name, args), timeout, cwd=str(cwd or policy.root), env=policy.env(name))


def sysctl_run(argv, timeout):
    """`read_boot_id`'s launcher on macOS: AC-13's sysctl form (resolved path, minimal env), through the active
    policy when one is installed (cwd its root) and unenforced otherwise (cwd /). Returns an object with returncode
    and stdout."""
    import ahc_core  # noqa: PLC0415
    from types import SimpleNamespace  # noqa: PLC0415
    policy = _ACTIVE
    if policy is not None:
        rc, out, _err = ahc_core.run_argv(policy.argv("sysctl", argv[1:]), timeout, cwd=policy.root,
                                          env=policy.env("sysctl"))
    else:
        home = str(Path.home())
        dirs = trusted_dirs(home)
        exe = resolve("sysctl", dirs)
        if exe is None:
            return SimpleNamespace(returncode=127, stdout="")
        rc, out, _err = ahc_core.run_argv([exe] + list(argv[1:]), timeout, cwd="/", env=form_env("sysctl", dirs, home))
    return SimpleNamespace(returncode=rc, stdout=out)


def probe_run(argv, timeout):
    """AC-11's open-file probe (lsof, or fuser) under AC-13: through the active policy's form (its resolved
    executable, minimal env and the root as cwd), checked against the lsof/fuser rules (only while migrating, fixed
    options, the ledger files) before it launches. Without a policy it is ahc_migrate's default (cwd /)."""
    import ahc_core  # noqa: PLC0415
    import ahc_migrate  # noqa: PLC0415
    from types import SimpleNamespace  # noqa: PLC0415
    policy = _ACTIVE
    if policy is None:
        return ahc_migrate.default_run(argv, timeout)
    name = os.path.basename(str(argv[0]))
    full = policy.argv(name, list(argv[1:]))
    policy.check_launch(full[0], full, policy.root, policy.env(name))
    rc, out, err = ahc_core.run_argv(full, timeout, cwd=policy.root, env=policy.env(name))
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def run_helper(policy, name, args, timeout, script=None):
    """The production launcher for a legacy Python helper: the interpreter, the script, the helper form's fixed
    env and the root as cwd. `script` (a configured path) is launched as given; under an active policy the hook
    refuses it unless it is the installed, unchanged script (NEG-47)."""
    import ahc_core  # noqa: PLC0415
    argv = [policy.python, str(script)] + [str(a) for a in args] if script else policy.helper_argv(name, args)
    return ahc_core.run_argv(argv, timeout, cwd=policy.root, env=dict(policy.helper_env))
