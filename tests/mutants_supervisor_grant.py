"""Failing-first set for supervisor power (goodqa#16944). Each variant removes one control in a temporary copy of the
tree; tests.test_supervisor_grant must fail against every variant and pass against the real files.

    python3 -B tests/mutants_supervisor_grant.py      exit 0 when every variant is killed and the real tree passes
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Not variants, because each is equivalent: a stranger's key with a pinned key id still fails the signature, and an
# enabler that skips its own expiry check still meets grant_body's identical check (both are kept as layers).
ROOT = Path(__file__).resolve().parent.parent
SG = "harness/hooks/supervisor_grant.py"
EN = "scripts/enable-agent-ops.py"
TG = "harness/hooks/transcript_guard.py"
SUITES = ("tests.test_supervisor_grant", "tests.test_supervisor_grant_repair")

VARIANTS = [
    ("forged duplicate record accepted", SG,
     "    if len(found) > 1 or len(found[0][2]) > 1:\n", "    if False:\n"),
    ("any record shape counts", SG,
     '    if record.get("type") != "assistant" or message.get("role") != "assistant" or record.get("isApiErrorMessage") \\\n'
     '            or not isinstance(record.get("uuid"), str) or not isinstance(message.get("model"), str):\n',
     '    if not isinstance(message.get("model"), str):\n'),
    ("every model qualifies", SG,
     '    if isinstance(allowed, list) and family in allowed:\n', '    if True:\n'),
    ("unknown model qualifies", SG,
     '    if found is None:\n        return False, "model_unknown"\n', '    if found is None:\n        return True, "unknown"\n'),
    ("model not re-read at use", SG,
     "    model, family = observed_model(payload)\n", "    model, family = 'claude-opus-5-5', 'opus'\n"),
    ("grant not bound to the session", SG,
     'mine = [g for g, problem, _p in grants if g is not None and g["session"] == session]',
     'mine = [g for g, problem, _p in grants if g is not None]'),
    ("signature not verified", SG,
     "        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(ss.b64url_decode(grant[\"signature\"]), signed_message(body))\n",
     "        pass\n"),
    ("expiry ignored", SG,
     '        if grant["expires_at"] is not None and now >= ss.parse_time(grant["expires_at"]):\n',
     '        if False:\n'),
    ("a revoked grant id ignored", SG,
     '    if revoked["all"] or grant["gid"] in revoked["gids"]:\n', '    if revoked["all"]:\n'),
    ("unsafe revocation log fails open (F2)", SG,
     '    except Refusal as refusal:\n        state.update({"all": True, "problem": refusal.message})\n',
     '    except Refusal as refusal:\n        state.update({"problem": refusal.message})\n'),
    ("revoke-all ignores its time (F4)", SG,
     '    return any(issued <= at for at in revoked["all_at"])\n', '    return True\n'),
    ("kill switch ignored", SG,
     "    if ss.kill_switch_active(home):\n        raise Refusal(\"disabled\"", "    if False:\n        raise Refusal(\"disabled\""),
    ("sub-agents always included", SG,
     '    if agent and not any(g["include_subagents"] for g in live):\n', '    if False:\n'),
    ("host not checked", SG,
     'and host in (p.get("hosts") or [])', ''),
    ("never-covered targets allowed", SG,
     '    if not isinstance(target, dict):\n        return "a delete needs a target"\n',
     '    return None\n    if not isinstance(target, dict):\n        return "a delete needs a target"\n'),
    ("protected roots not checked", SG,
     '            if _covers(form, template.replace("{home}", home_dir)):\n', "            if False:\n"),
    ("harness logs root missing (F3)", SG,
     'SUPERVISOR_EXTRA_ROOTS = ("{home}/.agent-harness/logs", ', "SUPERVISOR_EXTRA_ROOTS = ("),
    ("delete guard's own list not read (F3)", SG,
     '    for template in list(guard_policy["protected_log_roots"]) + list(guard_policy["guard_files"]) + list(SUPERVISOR_EXTRA_ROOTS):\n',
     "    for template in list(SUPERVISOR_EXTRA_ROOTS):\n"),
    ("path as written not checked (other hosts)", SG,
     "    for form in dict.fromkeys((written, real)):\n", "    for form in (real,):\n"),
    ("folder contents not read", SG, "    return _contents_reason(real, home, policy)\n", "    return None\n"),
    ("harness tree allow-list off", SG,
     "            if not _harness_deletable(low, home_dir.lower(), policy):\n", "            if False:\n"),
    ("tail window brought back (F5)", SG,
     "            lines, pos = [], view.find(needle)\n",
     "            lines, pos = [], view.find(needle, max(0, info.st_size - (16 << 20)))\n"),
    ("transcript guard off (F5)", TG, "        if tool not in TOOLS:\n            return None\n", "        return None\n"),
    ("transcript guard fails open (F5)", TG,
     '        return "the transcript guard could not check this call (%s); refused" % type(error).__name__\n',
     "        return None\n"),
    ("memory exception reaches transcripts (F5)", TG,
     'if name == "projects" and len(below) >= 3 and below[1] == "memory" and not real.lower().endswith(".jsonl"):',
     'if name == "projects" and "memory" in below:'),
    ("symlinks not resolved", SG, "    real = os.path.realpath(written)\n", "    real = written\n"),
    ("no stamp needed to request", SG,
     '    if not isinstance(stamp, dict) or not isinstance(stamp.get("session"), str) or not stamp.get("tool_use_id"):\n',
     '    if False:\n'),
    ("unsupervised slug accepted", SG, "    if missing:\n        raise Refusal(\"not_supervised\"",
     "    if False:\n        raise Refusal(\"not_supervised\""),
    ("edited request fields accepted (F1)", SG,
     "    changed = [field for field in REQUEST_DERIVED if stored.get(field) != derived[field]]\n", "    changed = []\n"),
    ("request record uuid not compared", SG,
     '    if record["uuid"] != stored.get("record_uuid"):\n', "    if False:\n"),
    ("any command shape counts as the request (F1)", SG,
     '    if len(simple) != 1 or len(argvs) != 1 or argvs[0][:2] != [STAMP_SUB, "request"]:\n',
     '    if not argvs or argvs[0][:2] != [STAMP_SUB, "request"]:\n'),
    ("request id not bound to the call (F1)", SG,
     '            or request_id(stored["session"], stored["tool_use_id"]) != rid:\n', "            or False:\n"),
    ("request age read from the file (F1)", SG,
     '        asked = ss.parse_time(record.get("timestamp"))\n', '        asked = ss.parse_time(stored.get("at"))\n'),
    ("one call grants many times", SG,
     '    return any(g is not None and g.get("rid") == rid for g, _problem, _path in load_grants(_home(home)))\n',
     "    return False\n"),
    ("until revoked is the default", SG, 'DEFAULT_EXPIRY = "8h"', 'DEFAULT_EXPIRY = "until revoked"'),
    ("worktree warning missing", SG, '        lines.append("  Uncommitted and unpushed work in those worktrees can be lost.")\n', ''),
    ("enabler skips the code", EN, '        confirm(self.env, "supervisor")\n', ''),
    ("enabler skips the human checks", EN,
     '        if options.grant_supervisor:\n            require_human(enabler.env)  # before any read or write\n',
     '        if options.grant_supervisor:\n'),
]


def run(tree: Path) -> int:
    return subprocess.run([sys.executable, "-B", "-m", "unittest", "-f", *SUITES], cwd=str(tree),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800).returncode


def copy_tree(dest: Path):
    for part in ("harness/hooks", "scripts", "tests", "templates"):
        shutil.copytree(ROOT / part, dest / part, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(ROOT / "install.py", dest / "install.py")


def main() -> int:
    survivors, bad = [], []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "real"
        copy_tree(base)
        if run(base) != 0:
            print("the real tree fails its own tests; nothing measured")
            return 1
        for number, (name, rel, old, new) in enumerate(VARIANTS):
            tree = Path(tmp) / ("v%02d" % number)
            shutil.copytree(base, tree)
            path = tree / rel
            text = path.read_text()
            if text.count(old) != 1:
                bad.append(name)
                print("NOT APPLIED  %s" % name)
                shutil.rmtree(tree)
                continue
            path.write_text(text.replace(old, new))
            rc = run(tree)
            print("%-9s %s" % ("killed" if rc else "SURVIVED", name))
            if rc == 0:
                survivors.append(name)
            shutil.rmtree(tree)
    print("%d variants, survivors: %s, not applied: %s" % (len(VARIANTS), ", ".join(survivors) or "none",
                                                          ", ".join(bad) or "none"))
    return 1 if survivors or bad else 0


if __name__ == "__main__":
    sys.exit(main())
