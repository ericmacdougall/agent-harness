"""goodqa#15785 failing-first evidence: the tests must fail against the guard WITHOUT the change (origin/main) and against each
controlled broken variant of it.

Run: python3 -B tests/mutants_gq_credentials.py   (copies the hooks and the test into a temporary tree; changes nothing here)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "tests.test_command_guard_gq_credentials"
GUARD = "command_guard.py"

MUTANTS = {
    "token regex removed": ("r'(^|/)\\.config/goodqa/user-token$', ", ""),
    "key regex removed": (", r'(^|/)\\.agent-harness/gq-browser/[0-9a-f]{16}/key$'", ""),
    "samples removed": ("'{home}/.config/goodqa/user-token', '{home}/.agent-harness/gq-browser/0000000000000000/key'],", "],"),
    "parent directories removed": ("'credential_parent_dirs': ['{home}/.config/goodqa', '{home}/.agent-harness/gq-browser'],",
                                   "'credential_parent_dirs': [],"),
    "recursive readers ignore the parents": ("if not dir_hit and (recursive or name in ARCHIVE_CMDS or name in EXFIL_CMDS) and not any(",
                                             "if False and not any("),
    "archives not treated as walking": ("ARCHIVE_CMDS = {'tar', 'bsdtar', 'gtar', 'zip', '7z', 'cpio', 'pax', 'gzip', 'bzip2', 'xz', 'zstd'}", "ARCHIVE_CMDS = set()"),
    "walkers ignore a key directory inside": ("dir_hit = self.under_cred_parent(norm_path(t, ctx), below=True)", "dir_hit = self.under_cred_parent(norm_path(t, ctx))"),
    "destinations are judged like sources": ("and not any(w is d for d in destinations):", ":"),
    "no destinations are recognised": ("        destinations = self._local_destinations(name, args) if name in ARCHIVE_CMDS or name in EXFIL_CMDS else []",
                                       "        destinations = []"),
    "tar extract mode is not recognised": ("            if reading and not create:", "            if False:"),
    "the last scp operand is not a destination": ("            if len(operands) >= 2:\n                skip.append(operands[-1])", "            if False:\n                skip.append(operands[-1])"),
    "grep -d recurse is not recursive": ("or self._grep_directories_recurse(texts))", ")"),
    # the per-tool skip_next lists are defence in depth: the fail-closed working-directory check (no existing path operand) now
    # catches the same searches, so removing a list entry is no longer observable and has no mutant of its own
    "zip - is not the archive operand": ("operands = [w for w in words if not w.text.startswith('-') or w.text == '-']", "operands = [w for w in words if not w.text.startswith('-')]"),
    "7z sources after the archive are skipped": ("                        skip.append(rest[0])", "                        skip.extend(rest)"),
    "an unlisted option value does not fail closed": ("no_real_path = not words or not any(os.path.exists(norm_path(w.text, ctx)) for w in words)", "no_real_path = not words"),
    "search with no path operand not judged": ("if recursive and no_real_path and not reads_stdin and self.under_cred_parent(ctx.cwd, below=True):", "if False:"),
    "no-path search ignores a key directory as cwd": ("not reads_stdin and self.under_cred_parent(ctx.cwd, below=True):", "not reads_stdin and self.under_cred_parent(ctx.cwd):"),
    "grep exempt when piped": ("reads_stdin = idx > 0 and name in ('rg', 'ag', 'ack')", "reads_stdin = idx > 0"),
    "rg --files treated as a print": ("'--files-with-matches', '--files-without-match', '--files'})\n", "'--files-with-matches', '--files-without-match'})\n"),
    "pax and compressors not treated as archives": ("ARCHIVE_CMDS = {'tar', 'bsdtar', 'gtar', 'zip', '7z', 'cpio', 'pax', 'gzip', 'bzip2', 'xz', 'zstd'}",
                                                    "ARCHIVE_CMDS = {'tar', 'gtar', 'zip', '7z', 'cpio'}"),
    "archive tools not dispatched to the credential check": ("or name in EXFIL_CMDS or name in ARCHIVE_CMDS or name in ('openssl', 'source'):",
                                                            "or name in EXFIL_CMDS or name in ('openssl', 'source'):"),
    "copy tools ignore the parents": ("(recursive or name in ARCHIVE_CMDS or name in EXFIL_CMDS) and not any(",
                                      "(recursive or name in ARCHIVE_CMDS) and not any("),
    "find -exec ignores the parents": ("self.under_cred_dir(p) or self.under_cred_parent(p, below=True) or", "self.under_cred_dir(p) or"),
    "key directory contents not covered": ("if below and len(segs) > len(d) and segs[:len(d)] == d and not segs[len(d):][-1:] == ['config.json']:",
                                           "if False:"),
}


def run(tmp, label):
    done = subprocess.run([sys.executable, "-B", "-m", "unittest", TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print("%-42s %s" % (label, "FAILS (good)" if killed else "PASSES (test is vacuous)"))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix="mutant-"))
    shutil.copytree(ROOT / "harness" / "hooks", tmp / "harness" / "hooks", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "tests").mkdir()
    shutil.copy(ROOT / "tests" / "test_command_guard_gq_credentials.py", tmp / "tests")
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(["git", "-C", str(ROOT), "show", "origin/main:harness/hooks/" + GUARD], capture_output=True, check=True).stdout
        (tmp / "harness" / "hooks" / GUARD).write_bytes(base)
        bad += 0 if run(tmp, "origin/main (no change)") else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / GUARD
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
