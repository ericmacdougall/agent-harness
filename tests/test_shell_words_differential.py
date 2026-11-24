"""goodqa#16811 round 1: shell_words agrees with the real shells or says it cannot verify.

The differential test writes each corpus line into a script for bash and for zsh in which every command, builtins
included, goes to a recorder: PATH is empty, the builtins are disabled, and the shell's command-not-found handler
writes the argv it was given to fd 3. So the shells parse the line themselves and run nothing. For every line
shell_words verifies, each argv a shell ran must be one of the commands shell_words listed (it never misses a local
command), and on lines with no expansion, glob, brace, tilde or `||`, the two lists are equal. A line it cannot verify
is not run. The corpus holds every reviewer example (PR 334 round 1), the genericized refused commands from the
transcripts (the copy and stamp test lists) and adversarial shapes for each corner of either shell.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "harness" / "hooks"))
sys.path.insert(0, str(HERE))
import shell_words  # noqa: E402
import test_copy_hygiene_ssh as copy_cases  # noqa: E402

BACKTICK = "`"
REVIEW = ("python3 ~/.claude/hooks/peer_review.py pr --repo /w --packet /p --expected-head " + "a" * 40
          + " --github-repo o/r --pr 5")
REVIEWER_EXAMPLES = [
    # F1: an apostrophe in a comment on the ssh line, and a pair of ANSI-C words across lines.
    "ssh devbox 'cd ~/w && git clone u d'   # remote; doesn't touch this disk\n"
    "git clone u ~/local-copy               # here's the local one",
    "echo $'a\\'b' && ssh devbox 'x'\ngit clone u d\necho $'c\\'d'",
    # F2: a bound review inside bash -c, and python options the old scan did not skip.
    'bash -c "python3 ~/.claude/hooks/peer_review.py --repeat-reason \'a;b\' --github-repo o/r --pr 5 pr"',
    "python3 -X utf8 ~/.claude/hooks/peer_review.py --repeat-reason 'a;b' --github-repo o/r --pr 5 pr",
    "python3 -W ignore -O ~/.claude/hooks/peer_review.py --repeat-reason 'a;b' --github-repo o/r --pr 5 pr",
    # F3: PowerShell curly quotes around real separators.
    REVIEW + " --repeat-reason ’x' ; touch pwned ; 'y’",
    # F4: an ssh inside bash -c.
    "bash -c 'ssh h \"git clone a b\"'",
]
STAMP_LINES = [REVIEW + " --repeat-reason " + reason for reason in (
    "'first attempt died on a provider limit; rerun'", "'lint & tests fixed'", "'a | b'", "'x < y'", "'x > y'",
    '"fixed && retested"', '"a || b"', "'2>&1 was the old form'", "'see --pr 999 --github-repo other/repo; old run'",
    '"was --pr=999"', "--pr=999", "$REASON", '"home $HOME"', '"${a[@]}"', "$(cat r)", BACKTICK + "cat r" + BACKTICK,
    "$'a\\nb'", "a\\;b", "'a")] + [REVIEW + "; true", REVIEW + " && echo done", REVIEW + " || true",
                                  REVIEW + " | tee out.txt", REVIEW + " > out.txt", REVIEW + " >> out.txt",
                                  REVIEW + " < /dev/null", REVIEW + " &", REVIEW + " # trailing comment",
                                  REVIEW + " --pr 6", "cd /w && " + REVIEW]
ADVERSARIAL = [
    "a;b", "a&&b", "a||b", "a|b", "a|&b", "a & b", "(a)", "(a; b) && c", "( (a) )", "a\n\nb", "a;", "x=1 y=2",
    "x=1 cmd arg", "'x'=1 cmd", "cmd 'a b' \"c d\" e'f'\"g\"", "cmd '' \"\"", "cmd\ta", "cmd a#b", "cmd a # c",
    "cmd 'it''s'", 'cmd "$T"', "cmd $T", 'cmd "$T/x"', "cmd ${T}", 'cmd "$T[1]"', "cmd $T:h", "cmd $10", "cmd $#a",
    "cmd $+a", "cmd $=a", "cmd ${a:-b}", "cmd $((1+1))", "cmd <(a)", "cmd >(a)", "cmd <<<x", "cmd <<EOF\nx\nEOF",
    "cmd 2>&1", "cmd 2> err.txt", "cmd >&2", "cmd &> all.txt", "cmd >| f.txt", "cmd <> rw.txt", "echo hi>out",
    "cmd <1-5>", "> f.txt", "cmd &|", "=ls", "- ls", "{ a; }", "[[ x ]]", "if true; then a; fi",
    "for i in 1; do a; done", "f() { a; }", "a ) b", "cmd (b)", "a ;; b", ";a", "a &&", "a |", "&& a",
    "cmd *", "cmd a{b,c}", "cmd ~/x", "cmd ~root", "cmd !x", 'cmd "!x"', "cmd a\\ b", "cmd \\\nb",
    "cmd '‘x’'", "cmd  x", "cmd café", "cmd 'multi\nline'", 'cmd "two\nlines"', "cmd 'a\rb'",
    "env A=1 cmd", "timeout 5 cmd", "sudo -u ops cmd", "nice -n 5 cmd", "exec cmd", "command cmd",
    "cd /w && cmd x", "T=/srv; cmd $T && other", "cmd $'a' b", "cmd $'x;y' z", 'cmd $"a" b', "cmd a$'b'",
]
CORPUS = REVIEWER_EXAMPLES + STAMP_LINES + ADVERSARIAL + copy_cases.REMOTE + copy_cases.LOCAL + \
    copy_cases.BASE_REFUSED + copy_cases.WRAPPED + copy_cases.ROUND2_LOCAL + copy_cases.ROUND2_STILL_LOCAL + \
    copy_cases.ROUND2_REMOTE

# Each record is one append-mode write, so the two sides of a pipeline cannot interleave their records.
BASH_PRELUDE = r"""exec 3>>"$SW_RECORD"
command_not_found_handle() { builtin printf -v sw_record '%s\037' "$@"; builtin printf '%s\036' "$sw_record" >&3; return 0; }
for sw_builtin in $(compgen -b); do
  case $sw_builtin in builtin|printf|enable|return|wait) ;; *) enable -n "$sw_builtin" ;; esac
done
enable -n enable
"""
ZSH_PRELUDE = r"""exec 3>>"$SW_RECORD"
command_not_found_handler() { builtin printf -v sw_record '%s\037' "$@"; builtin printf '%s\036' "$sw_record" >&3; return 0 }
for sw_builtin in ${(k)builtins}; do
  case $sw_builtin in builtin|printf|disable|return|wait) ;; *) disable $sw_builtin ;; esac
done
disable disable
"""


def shells():
    found = {}
    bash = shutil.which("bash")
    if bash:
        version = subprocess.run([bash, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True).stdout
        if version.strip().isdigit() and int(version) >= 4:  # command_not_found_handle needs bash 4
            found["bash"] = ([bash, "--norc", "--noprofile"], BASH_PRELUDE)
    zsh = shutil.which("zsh")
    if zsh:
        found["zsh"] = ([zsh, "-f"], ZSH_PRELUDE)
    return found


def record(shell, prelude, line):
    """The argv lists `shell` ran for `line`, and its stderr."""
    with tempfile.TemporaryDirectory(prefix="sw-diff-") as temporary:
        script = Path(temporary) / "line.sh"
        script.write_text(prelude + line + "\nwait\n", encoding="utf-8")
        out = Path(temporary) / "record.bin"
        env = {"PATH": "/nonexistent-shell-words", "HOME": temporary, "LC_ALL": "C.UTF-8", "SW_RECORD": str(out)}
        result = subprocess.run(shell + [str(script)], cwd=temporary, env=env, capture_output=True, timeout=20,
                                stdin=subprocess.DEVNULL)
        raw = out.read_bytes().decode("utf-8", "replace") if out.exists() else ""
    records = [entry.split("\x1f")[:-1] for entry in raw.split("\x1e")[:-1]]
    return records, result.stderr.decode("utf-8", "replace")


def rewritable(word):
    """A word whose final value a shell may change: an expansion, or an unquoted glob, brace or tilde character."""
    return bool(word.expansions) or any(char in "*?[]{}~" for _, char in word.unquoted)


class ScannerVerdicts(unittest.TestCase):
    """Unit checks, so a broken scanner fails here even where no zsh is installed."""

    def test_every_reviewer_example_and_corner_is_unverified(self):
        unverified = {
            REVIEWER_EXAMPLES[0]: "comment", REVIEWER_EXAMPLES[1]: "ansi_c", REVIEWER_EXAMPLES[5]: "quote_like",
            "cmd a # c": "comment", "cmd 'it''s' # x": "comment", "cmd $'x'": "ansi_c", 'cmd $"x"': "locale_quote",
            "cmd $(a)": "command_substitution", "cmd " + BACKTICK + "a" + BACKTICK: "command_substitution",
            'cmd "$(a)"': "command_substitution", "cmd $((1))": "arithmetic", "cmd <(a)": "process_substitution",
            "cmd <<EOF\nx\nEOF": "heredoc", "cmd <<<x": "heredoc", "cmd a\\ b": "backslash",
            'cmd "a\\"b"': "backslash", "cmd !x": "history", 'cmd "!x"': "history", "cmd 'a\rb'": "control",
            "cmd  x": "quote_like", "cmd '“x”'": "quote_like", 'cmd "$T[1]"': "expansion_suffix",
            "cmd $T:h": "expansion_suffix", "cmd $10": "expansion_suffix", "cmd $#a": "expansion_suffix",
            "cmd ${a:-b}": "expansion_form", "cmd $+a": "expansion_form", "echo hi>out": "glued_redirect",
            "> f": "null_command", "cmd <1-5>": "numeric_glob", "=ls": "equals_word", "- ls": "reserved_word",
            "{ a; }": "reserved_word", "if true; then a; fi": "reserved_word", "f() { a; }": "paren_in_word",
            "cmd (b)": "paren_in_word", "a ;; b": "syntax", ";a": "syntax", "a &&": "syntax", "&& a": "syntax",
            "cmd 'a": "unbalanced", "(a": "unbalanced", "a)": "unbalanced", "(a) > f": "subshell_redirect",
            "cmd &|": "syntax",
        }
        for line, kind in unverified.items():
            with self.subTest(line=line):
                scan = shell_words.scan(line)
                self.assertFalse(scan.verified)
                self.assertEqual(scan.kind, kind, scan.message)

    def test_verified_shapes_and_their_words(self):
        cases = {
            "ssh devbox 'cd x && cp -a a b'": [["ssh", "devbox", "cd x && cp -a a b"]],
            "a; b && (c | d) || e &": [["a"], ["b"], ["c"], ["d"], ["e"]],
            "x=1 cmd 'a b' \"c\"d e''": [["cmd", "a b", "cd", "e"]],
            "cmd '' \"\"": [["cmd", "", ""]],
            "cmd 2>&1 >/dev/null": [["cmd"]],
            REVIEWER_EXAMPLES[2]: [["bash", "-c", "python3 ~/.claude/hooks/peer_review.py --repeat-reason 'a;b' "
                                    "--github-repo o/r --pr 5 pr"]],
            "a\n\nb\n": [["a"], ["b"]],
        }
        for line, argv in cases.items():
            with self.subTest(line=line):
                scan = shell_words.scan(line)
                self.assertTrue(scan.verified, scan.message)
                self.assertEqual([segment.argv for segment in scan.segments], argv)

    def test_a_word_says_where_its_first_character_comes_from(self):
        # Round 2: copy_hygiene's ssh rule judges a word by its value's first character. Empty quotes in front of
        # an expansion do not make the expansion literal text, and a quoted `-` is still a `-`.
        cases = {"''\"$X\"": "expansion", '""$X': "expansion", "$X": "expansion", "${X}.x": "expansion",
                 "\"x$X\"": "quoted", "\"''$X\"": "quoted", "'-o'$X": "quoted", "\"-$X\"": "quoted",
                 "x$X": "unquoted", "-o\"$X\"": "unquoted", '""*': "unquoted", "~/k": "unquoted",
                 "''": "", '""': ""}
        for text, lead in cases.items():
            with self.subTest(word=text):
                scan = shell_words.scan("cmd " + text)
                self.assertTrue(scan.verified, scan.message)
                self.assertEqual(scan.segments[0].words[1].lead, lead)

    def test_scan_never_raises(self):
        for line in CORPUS + ["", " ", "\x00", "(" * 50, "$", "${", "'" * 3, '"', "a" * (shell_words.MAX_TEXT + 1)]:
            shell_words.scan(line)


class Differential(unittest.TestCase):
    def test_the_real_shells_run_only_what_the_scanner_lists(self):
        found = shells()
        if not found:
            self.skipTest("no bash 4+ or zsh on this host")
        compared = exact = 0
        for line in CORPUS:
            scan = shell_words.scan(line)
            if not scan.verified:
                continue
            segments = [segment for segment in scan.segments if segment.argv]
            listed = [segment.argv for segment in segments]
            loose = any("||" == segment.op for segment in scan.segments) or any(
                rewritable(word) for segment in segments for word in segment.words)
            # A program written as a path is not looked up in PATH, so no handler records it.
            listed_recordable = [argv for argv in listed if "/" not in argv[0]]
            for name, (command, prelude) in found.items():
                with self.subTest(shell=name, line=line):
                    records, stderr = record(command, prelude, line)
                    self.assertNotRegex(stderr, r"syntax error|parse error", "verified, yet the shell refused it")
                    compared += 1
                    if loose:
                        programs = Counter(argv[0] for argv in listed)
                        for argv in records:
                            self.assertTrue(argv and (argv[0] in programs or any(
                                rewritable(segment.words[len(segment.words) - len(segment.argv)])
                                for segment in segments)), (argv, listed))
                        self.assertLessEqual(len(records), len(listed))
                    else:
                        exact += 1
                        self.assertEqual(Counter(map(tuple, records)), Counter(map(tuple, listed_recordable)))
        self.assertGreater(compared, 100, "too few verified lines reached a real shell")
        self.assertGreater(exact, 60)


if __name__ == "__main__":
    unittest.main()
