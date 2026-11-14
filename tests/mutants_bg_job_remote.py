"""goodqa#15565 failing-first evidence: tests.test_bg_job_remote must fail against origin/main (no wait-remote) and against
each controlled broken variant of bg_job.py / bg_lint.py.

Run: python3 -B tests/mutants_bg_job_remote.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_bg_job_remote"

MUTANTS = {
    "the offset follows the reported size": ("bg_job.py", "                offset += len(data)", "                offset = size"),
    "the first look is not a baseline": ("bg_job.py", "                    offset, data = size, b\"\"  # only", "                    data = data  # only"),
    "a banner before the size is accepted": ("bg_job.py", "    if not re.fullmatch(rb\"\\s*[0-9]{1,18}\\s*\", head):", "    if False:"),
    "an unreadable file is not told from absent": ("bg_job.py", "    if status == EXIT_UNREADABLE:", "    if False:"),
    "the guard check is removed": ("bg_job.py", "        allowed, why = file_judged_by_guard(args.file)", "        allowed, why = True, \"\""),
    "a tilde path is accepted": ("bg_job.py", "    if args.file.startswith(\"~\"):", "    if False:"),
    "the retry is removed": ("bg_job.py", "            if attempt == 0:\n                continue", "            if False:\n                continue"),
    "ssh refusals are retried as infra": ("bg_job.py", "            if SSH_REFUSED.search(err):", "            if False:"),
    "the fail line is ignored": ("bg_job.py", "                if fail is not None and fail in buf:", "                if False:"),
    "no carry across polls": ("bg_job.py", "                carry = buf[-keep:] if keep > 0 else b\"\"", "                carry = b\"\""),
    "ssh-job is ignored": ("bg_job.py", "    if code == 255 and getattr(args, \"ssh_job\", False):", "    if False:"),
    "the host is not validated": ("bg_job.py", "    if not HOST_RE.match(args.host or \"\"):", "    if False:"),
    "from-offset is ignored": ("bg_job.py", "        offset, first = args.from_offset, False", "        pass"),
    "a truncation is not noticed": ("bg_job.py", "                elif size < offset:", "                elif False:"),
    "a file that appears later is baselined": ("bg_job.py", "                first = False\n        if time.time() >= end:", "                pass\n        if time.time() >= end:"),
    "the infra count is never reset": ("bg_job.py", "            infra_polls = 0\n            if kind == \"ok\":", "            if kind == \"ok\":"),
    "the stderr line is not bounded": ("bg_job.py", "[^\\x20-\\x7e]\", \"?\", line.strip())[:160]", "[^\\x20-\\x7e]\", \"?\", line.strip())[:100000]"),
    "the ssh call has no bound": ("bg_job.py", "                              timeout=SSH_CALL_BOUND)", "                              timeout=None)"),
    "the read-on shortcut skips the deadline": ("bg_job.py", "                if len(data) >= READ_CAP and time.time() < end:", "                if len(data) >= READ_CAP:"),
    "the guard check uses the broad probe": ("bg_job.py", "            if command_guard.raw_credential(text):", "            if command_guard.raw_sensitive(text):"),
    "the lint advice is removed": ("bg_lint.py", "% (hit, SAFE, REMOTE_HINT if re.search(r\"\\bssh\\b\", command) else \"\")", "% (hit, SAFE, \"\")"),
}


def run(tmp, label):
    try:
        done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True, timeout=90)
        killed = done.returncode != 0
    except subprocess.TimeoutExpired:  # a variant that hangs (an unbounded wait) is caught by the test run not finishing
        killed = True
    print("%-52s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_bg_job_remote.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:  # origin/main has neither wait-remote nor the lint advice: take the new code out of a copy
        path = tmp / "harness" / "hooks" / "bg_job.py"
        text = path.read_text()
        cut = text.index("# ---- wait-remote")
        path.write_text(text[:cut] + text[text.index("def cmd_status"):])
        bad += 0 if run(tmp, "origin/main (no wait-remote)") else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (target, old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / target
            text = path.read_text()
            if old not in text:
                print("MUTANT NOT APPLIED:", name)
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
