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
    "no destinations are recognised": ("        destinations = self._local_destinations(name, args, ctx) if name in ARCHIVE_CMDS or name in EXFIL_CMDS else []",
                                       "        destinations = []"),
    "tar extract mode is not recognised": ("            if _tar_mode(name, args) == 'read':", "            if False:"),
    "the last scp operand is not a destination": ("            if len(operands) >= 2 and any(is_source(w) for w in operands[:-1] if id(w) not in scan.after_unknown):\n                skip.append(operands[-1])",
                                                  "            if False:\n                skip.append(operands[-1])"),
    "grep -d recurse is not recursive": ("or self._grep_directories_recurse(texts))", ")"),
    # the option tables replace the skip_next lists (receipt r4): a missing table entry makes the search uncertain and fail
    # closed, so removing a single entry can only over-block; the mutants above remove the parsing rules themselves
    "zip - is not the archive operand": ("operands = [w for w in words if not w.text.startswith('-') or w.text == '-']", "operands = [w for w in words if not w.text.startswith('-')]"),
    "7z sources after the archive are skipped": ("                        skip.append(rest[0])", "                        skip.extend(rest)"),
    # receipt r4 F1: an unrecognised option judges the working directory whatever the operands
    "an uncertain search is not judged on the cwd": ("no_real_path = uncertain or not words", "no_real_path = not words"),
    "an uncertain search judges only operands": ("                words = scan.free\n", "                words = scan.operands[1:]\n"),
    "an unknown long option is certain": ("            else:\n                scan.uncertain = True\n                if not eq and i + 1 < len(words):",
                                          "            elif not eq:\n                scan.uncertain = True\n                if i + 1 < len(words):"),
    "an unknown short letter is certain": ("            scan.uncertain = True  # an unknown letter", "            pass  # an unknown letter"),
    "long option values are not free words": ("                    if not words[i].text.startswith('-'):\n                        scan.free.append(words[i])",
                                              "                    pass"),
    "short option values are not free words": ("            if not words[i].text.startswith('-'):\n                scan.free.append(words[i])\n        i += 1",
                                               "            pass\n        i += 1"),
    "a separate long value is not consumed": ("                if not eq and i + 1 < len(words):\n                    i += 1  # the separate value",
                                              "                if False:\n                    i += 1  # the separate value"),
    "an attached value letter takes the next word": ("take_next = j + 1 == len(t)", "take_next = True"),
    "a value letter never takes the next word": ("take_next = j + 1 == len(t)", "take_next = False"),
    "an attached pattern option is not seen": ("scan.pattern_given = scan.pattern_given or ch in ps", "pass"),
    "a long pattern option is not seen": ("scan.pattern_given = scan.pattern_given or name in pls", "pass"),
    "count-only reads letters of values": ("            count_only = self._count_only(args, scan)", "            count_only = self._count_only(args)"),
    "count-only trusts an uncertain scan": ("            if scan.uncertain:\n                return False  # an unknown option", "            if False:\n                return False  # an unknown option"),
    "grep --dereference-recursive is not recursive": (" or self._grep_recursive_long(texts)", ""),
    "grep -d abbreviations are not recursive": ("return len(value) >= 3 and 'recurse'.startswith(value)", "return value == 'recurse'"),
    "pt is not recursive": ("RECURSIVE_SEARCHERS = {'rg', 'ag', 'ack', 'pt'}", "RECURSIVE_SEARCHERS = {'rg', 'ag', 'ack'}"),
    # receipt r4 F2: tar create mode is never read as extract mode
    "tar value letters do not end a cluster": ("                if ch in value_letters:\n                    break", "                if False:\n                    break"),
    "tar create abbreviations not seen": ("if long_name and any(m.startswith(long_name) for m in _TAR_CREATE_LONGS):", "if long_name in _TAR_CREATE_LONGS:"),
    "tar read abbreviations not seen": ("elif len(long_name) >= 2 and any(m.startswith(long_name) for m in _TAR_READ_LONGS):", "elif long_name in _TAR_READ_LONGS:"),
    "tar two modes read as one": ("return modes.pop() if len(modes) == 1 else None", "return 'read' if 'read' in modes else None"),
    "tar old-style first word ignored": ("letters = t  # old style", "letters = ''  # old style"),
    # receipt r4 F3: copy option values and the only real source
    "copy option values are operands": ("scan = _scan_options(args, _COPY_TABLES[name])", "scan = _scan_options(args, {})"),
    "copy destination skipped without a real source": ("if len(operands) >= 2 and any(is_source(w) for w", "if len(operands) >= 2 and any(True for w"),
    "a word after an unknown copy option is a source": (" if id(w) not in scan.after_unknown):", "):"),
    "a remote operand is not a source": ("return True  # host:path, the remote side", "return False  # host:path, the remote side"),
    "search with no path operand not judged": ("if recursive and no_real_path and not reads_stdin and self.under_cred_parent(ctx.cwd, below=True):", "if False:"),
    "no-path search ignores a key directory as cwd": ("not reads_stdin and self.under_cred_parent(ctx.cwd, below=True):", "not reads_stdin and self.under_cred_parent(ctx.cwd):"),
    "grep exempt when piped": ("reads_stdin = idx > 0 and name in RECURSIVE_SEARCHERS", "reads_stdin = idx > 0"),
    "rg --files treated as a print": ("'files-without-match', 'files'})", "'files-without-match'})"),
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
