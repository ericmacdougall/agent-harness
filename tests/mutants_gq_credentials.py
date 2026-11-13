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
    # the tree rule of read_creds (receipt r6 restructure: every word is judged unless a rule proves it is not read)
    "recursive readers ignore the parents": ("or self.under_cred_parent(p, below=True, globs=globs)\n                               for p in paths)",
                                             "or False\n                               for p in paths)"),
    "walkers ignore a key directory inside": ("self.under_cred_parent(p, below=True, globs=globs)", "self.under_cred_parent(p, globs=globs)"),
    "archives not treated as walking": ("walking = bool(recursive) or name in ARCHIVE_CMDS or name in EXFIL_CMDS", "walking = bool(recursive) or name in EXFIL_CMDS"),
    "copy tools ignore the parents": ("walking = bool(recursive) or name in ARCHIVE_CMDS or name in EXFIL_CMDS", "walking = bool(recursive) or name in ARCHIVE_CMDS"),
    "destinations are judged like sources": ("exempt_dir.update(id(d) for d in self._local_destinations(name, args, ctx))", "pass"),
    "no destinations are recognised": ("            skip.extend(w for w in words if not w.text.startswith('-'))\n        return skip",
                                       "            skip.extend(w for w in words if not w.text.startswith('-'))\n        return []"),
    "tar extract mode is not recognised": ("            if _tar_mode(name, args) == 'read' and not (ctx", "            if False and not (ctx"),
    "the last scp operand is not a destination": ("if not scan.uncertain and len(operands) >= 2 and any(is_source(w) for w in operands[:-1]):",
                                                  "if False:"),
    "grep -d recurse is not recursive": ("self._grep_recursive_long(texts)\n                                          or self._grep_directories_recurse(texts))",
                                         "self._grep_recursive_long(texts))"),
    # the option tables replace the skip_next lists (receipt r4): a missing table entry makes the search uncertain and fail
    # closed, so removing a single entry can only over-block; the mutants above remove the parsing rules themselves
    "zip - is not the archive operand": ("operands = [w for w in words if not w.text.startswith('-') or w.text == '-']", "operands = [w for w in words if not w.text.startswith('-')]"),
    "7z sources after the archive are skipped": ("                        skip.append(rest[0])", "                        skip.extend(rest)"),
    # receipt r4 F1: an unrecognised option judges the working directory whatever the operands
    "an uncertain search is not judged on the cwd": ("no_real_path = uncertain or not sources", "no_real_path = not sources"),
    "an uncertain search exempts its pattern and options": ("            if not uncertain:  # an uncertain walk exempts nothing", "            if True:  # an uncertain walk exempts nothing"),
    "an unknown long option is certain": ("                scan.uncertain = True  # an unknown name", "                pass  # an unknown name"),
    "an unknown short letter is certain": ("            scan.uncertain = True  # an unknown letter", "            pass  # an unknown letter"),
    "a separate long value is not consumed": ("                elif i + 1 < len(words):\n                    i += 1  # the separate value",
                                              "                elif False:\n                    i += 1  # the separate value"),
    "an attached value letter takes the next word": ("take_next = j + 1 == len(t)", "take_next = True"),
    "a value letter never takes the next word": ("take_next = j + 1 == len(t)", "take_next = False"),
    "an attached pattern option is not seen": ("scan.pattern_given = scan.pattern_given or ch in ps", "pass"),
    "a long pattern option is not seen": ("scan.pattern_given = scan.pattern_given or name in pls", "pass"),
    "count-only reads letters of values": ("            count_only = self._count_only(name, scan)", "            count_only = bool(_flag_letters(args) & set('cqlL'))"),
    "count-only trusts an uncertain scan": ("        if table is None or scan.uncertain:", "        if table is None:"),
    # receipt r5 F1: count-only letters and long names are each tool's own
    "count-only letters shared by every tool": ("scan.letters & set(table.get('count_short', ''))", "scan.letters & set('cqlL')"),
    "count-only long names shared by every tool": ("scan.longs & table.get('count_long', frozenset())",
                                                   "scan.longs & {'count', 'quiet', 'silent', 'files-with-matches', 'files-without-match', 'files'}"),
    "find -exec count-only read naively": ("self.out_visible(pl, idx, True) and not (real in GREP_CMDS and self._count_only(real, self._search_scan(real, real_args))):",
                                           "self.out_visible(pl, idx, True) and not (real in GREP_CMDS and bool(_flag_letters(real_args) & set('cqlL'))):"),
    "stdin count-only read naively": ("self._count_only(name, self._search_scan(name, words[1:]))",
                                      "bool(_flag_letters(words[1:]) & set('cqlL'))"),
    "grep --dereference-recursive is not recursive": ("name in RECURSIVE_SEARCHERS or self._grep_recursive_long(texts)\n                                          or",
                                                      "name in RECURSIVE_SEARCHERS\n                                          or"),
    "grep -d abbreviations are not recursive": ("return len(value) >= 3 and 'recurse'.startswith(value)", "return value == 'recurse'"),
    "pt is not recursive": ("RECURSIVE_SEARCHERS = {'rg', 'ag', 'ack', 'pt'}", "RECURSIVE_SEARCHERS = {'rg', 'ag', 'ack'}"),
    # receipt r4 F2: tar create mode is never read as extract mode
    "tar value letters do not end a cluster": ("                if ch in v_all:\n                    break", "                if False:\n                    break"),
    # tar create detection has two independent layers: the maximal reading sees a create letter or abbreviation, and the
    # minimal reading never counts a word that may be an option value as read mode. Either layer alone refuses the r4 and
    # r5 tar attacks, so a mutant that breaks one layer is masked by the other; each mutant below breaks both
    "tar create abbreviations not seen": [("is_create = bool(long_name) and any(m.startswith(long_name) for m in _TAR_CREATE_LONGS)", "is_create = long_name in _TAR_CREATE_LONGS"),
                                          ("            if not maybe_value:\n", "            if True:\n")],
    "tar read abbreviations not seen": ("is_read = len(long_name) >= 2 and any(m.startswith(long_name) for m in _TAR_READ_LONGS)", "is_read = long_name in _TAR_READ_LONGS"),
    "tar two modes read as one": ("    if create:\n        return 'create'", "    if False:\n        return 'create'"),
    "tar old-style first word ignored": ("            read = read or any(ch in read_letters for ch in t)", "            read = read"),
    # receipt r5 F2: the most dangerous reading of letters the tar implementations disagree on
    "tar create stops at any value letter": [("                if ch in v_all:\n                    break\n                create = create", "                if ch in v_any:\n                    break\n                create = create"),
                                             ("            if not maybe_value:\n", "            if True:\n")],
    "GNU tar -s read as a value letter": [("_TAR_VALUE_ALL = 'CfTX'", "_TAR_VALUE_ALL = 'CfTXs'"), ("            if not maybe_value:\n", "            if True:\n")],
    "bsdtar -H read as a value letter": [("_TAR_VALUE_ALL = 'CfTX'", "_TAR_VALUE_ALL = 'CfTXH'"), ("            if not maybe_value:\n", "            if True:\n")],
    "bsdtar -L read as a value letter": [("_TAR_VALUE_ALL = 'CfTX'", "_TAR_VALUE_ALL = 'CfTXL'"), ("            if not maybe_value:\n", "            if True:\n")],
    "TAR_OPTIONS ignored": (" and not (ctx is not None and _options_from_environment(name, getattr(ctx, 'raw_top', ''))):", ":"),
    "search options from the environment ignored": ("if name not in SEARCH_TABLES or _options_from_environment(name, getattr(self.ctx, 'raw_top', ''), self.ctx.cwd):",
                                                    "if name not in SEARCH_TABLES:"),
    # receipt r5 F3 and r6 F2: a file opened as an option value is judged by name; only pattern, glob and number values
    # are free
    "every option value is free": ("if key in (free_short if kind == 's' else free_long):", "if True:"),
    "short option values are free": ("if key in (free_short if kind == 's' else free_long):", "if kind == 's' or key in free_long:"),
    "long option values are free": ("if key in (free_short if kind == 's' else free_long):", "if kind == 'l' or key in free_short:"),
    "values inside a word are not derived": ("    out = []\n    if not text or len(text) > 4096:\n        return out", "    out = []\n    if True:\n        return out"),
    "cluster suffixes are not derived": ("            out.append(text[k:])\n            k += 1", "            k += 1"),
    "a file URL is not percent-decoded": ("decoded = urllib.parse.unquote(path)", "decoded = path"),
    "curl globs are not expanded": [("out.extend([path, decoded] + _curl_glob(decoded))", "out.extend([path, decoded])"),
                                    ("        out.extend(_curl_glob(text))\n", "        pass\n")],
    "curl words are not curl-globbed": ("curl=name == 'curl') if k < 8 else []", "curl=False) if k < 8 else []"),
    "socat FILE: values are not derived": ("colon=name == 'socat', curl=name == 'curl') if k < 8", "colon=False, curl=name == 'curl') if k < 8"),
    "GREP_PATH ignored": ("grep_path = self._grep_path_dirs() if name in GREP_CMDS else []", "grep_path = []"),
    "7z -i wildcards read as literal": (" or (name in ('7z', '7za', '7zr', '7zz') and alt.startswith('-i'))", ""),
    "derived globs never literal": ("literal=not self_glob)", "literal=False)"),
    "parent globs not matched": ("if not all(_seg_eq(a, b) if globs else a == b for a, b in zip(segs, d)):", "if not all(a == b for a, b in zip(segs, d)):"),
    "brace alternatives not judged as trees": ("            alts = w.cred_alts() or [w.text]\n            hit, shown", "            alts = [w.text]\n            hit, shown"),
    # receipt r6 F4: count-only exempts the searched operands only
    "count-only exempts option values": ("counted = {id(w) for w in sources}", "counted = {id(w) for w in words}"),
    # receipt r6 F3: ack reads an .ackrc in any parent and the global and user files
    "ack parent rc files ignored": ("            d = parent if parent != d else None", "            d = None"),
    "ack global and user rc files ignored": ("candidates = [os.path.expanduser(p) for p in ACK_RC_FILES]", "candidates = []"),
    # the r5 sweep
    "pt trusted to read a pipe": ("STDIN_SEARCHERS = {'rg', 'ag', 'ack'}", "STDIN_SEARCHERS = {'rg', 'ag', 'ack', 'pt'}"),
    # receipt r6 F1: curl and wget destinations only from a certain walk with the tool's own table
    "curl -O read as a destination": [("'destinations': frozenset({('s', 'o'), ", "'destinations': frozenset({('s', 'O'), ('s', 'o'), "),
                                      ("'short_values': 'AbcCdDeEFHKmoPQrtTuUwxXyYz', 'short_flags': ':#012346aBfgGIijJklLMnNOpqRsSvVZ'",
                                       "'short_values': 'AbcCdDeEFHKmoOPQrtTuUwxXyYz', 'short_flags': ':#012346aBfgGIijJklLMnNpqRsSvVZ'")],
    "fetch destinations from a naive scan": ("            scan = _scan_options(args, table)\n            if not scan.uncertain:\n                skip.extend(w for key, w, _attached in scan.values if key in table['destinations'])",
                                             "            skip.extend(args[i + 1] for i, a in enumerate(args[:-1]) if a.text in ('-o', '--output', '-O', '-P'))"),
    "fetch destinations skipped on an uncertain walk": ("            if not scan.uncertain:\n                skip.extend(w for key, w, _attached in scan.values if key in table['destinations'])",
                                                        "            if True:\n                skip.extend(w for key, w, _attached in scan.values if key in table['destinations'])"),
    # removing one letter from a fetch or search table only makes the walk uncertain (fail closed), so it has no mutant
    # receipt r4 F3: copy option values and the only real source
    "copy option values are operands": ("scan = _scan_options(args, _COPY_TABLES[name])", "scan = _scan_options(args, {})"),
    "copy destination skipped without a real source": ("any(is_source(w) for w in operands[:-1])", "any(True for w in operands[:-1])"),
    "copy destination skipped on an uncertain walk": ("if not scan.uncertain and len(operands) >= 2", "if len(operands) >= 2"),
    "a remote operand is not a source": ("return True  # host:path, the remote side", "return False  # host:path, the remote side"),
    "search with no path operand not judged": ("if recursive and no_real_path and not reads_stdin and self.under_cred_parent(ctx.cwd, below=True):", "if False:"),
    "no-path search ignores a key directory as cwd": ("not reads_stdin and self.under_cred_parent(ctx.cwd, below=True):", "not reads_stdin and self.under_cred_parent(ctx.cwd):"),
    "grep exempt when piped": ("reads_stdin = idx > 0 and name in STDIN_SEARCHERS", "reads_stdin = idx > 0"),
    "rg --files treated as a print": ("'files-without-match',\n                                                    'files'})", "'files-without-match'})"),
    "pax, compressors, 7z family and ditto not treated as archives": (
        "ARCHIVE_CMDS = {'tar', 'bsdtar', 'gtar', 'zip', '7z', 'cpio', 'pax', 'gzip', 'bzip2', 'xz', 'zstd',\n                '7za', '7zr', '7zz', 'ditto', 'pigz', 'lz4', 'lzip', 'lzop', 'bsdcpio'}",
        "ARCHIVE_CMDS = {'tar', 'gtar', 'zip', '7z', 'cpio'}"),
    "archive tools not dispatched to the credential check": ("or name in EXFIL_CMDS or name in ARCHIVE_CMDS or name in ('openssl', 'source'):",
                                                            "or name in EXFIL_CMDS or name in ('openssl', 'source'):"),
    "key directory contents not covered": ("            if below and segs[-1] != 'config.json':\n                return True", "            if False:\n                return True"),
    # the r6 sweep: tar -C, unknown tar letters, ugrep arity, option commands
    "tar -C bases ignored": ("bases = _tar_bases(args, ctx) if name in ('tar', 'bsdtar', 'gtar')", "bases = [] if name in ('tar', 'bsdtar', 'gtar')"),
    # cumulative -C bases have no separate mutant: every -C value is itself judged against the earlier bases, and a base
    # leading to a credential directory is its ancestor, so the per-word judgement masks a non-cumulative variant
    "an unknown tar letter is ignored": ("                        return None  # an option letter no known tar accepts", "                        pass  # an option letter no known tar accepts"),
    "ugrep -X read as a value letter": ("'short_values': 'ABCDdefm', 'short_flags'", "'short_values': 'ABCDdefmX', 'short_flags'"),
    "--group-separator takes a separate value": ("    'long_optional': frozenset({'context', 'group-separator'}),\n    'long_values': frozenset({'regexp',",
                                                 "    'long_optional': frozenset({'context'}),\n    'long_values': frozenset({'group-separator', 'regexp',"),
    "option commands not analysed": ("        for inner in _option_commands(name, args):", "        for inner in []:"),
    # the r6 sweep: find (bfs) start directories anywhere, exec bodies that read, words of each body
    "bfs start directories ignored": ("cred_roots = _find_cred_roots(args, roots)", "cred_roots = roots"),
    "find -exec readers are only printers": ("            if real in FIND_EXEC_READERS:\n                for r in cred_roots:", "            if real in PRINT_FILE_CMDS:\n                for r in cred_roots:"),
    "find -exec bodies not unwrapped": ("            real, real_args = _unwrap_command(body)\n            if real in FIND_EXEC_READERS:",
                                        "            real, real_args = norm_name(body[0].text), body[1:]\n            if real in FIND_EXEC_READERS:"),
    "find -exec body words not judged": ("        for body in _find_exec_bodies(args):\n            real, real_args = _unwrap_command(body)\n            if real in PRINT_FILE_CMDS",
                                         "        for body in []:\n            real, real_args = _unwrap_command(body)\n            if real in PRINT_FILE_CMDS"),
    # the r6 sweep: a reader of a NAME LIST another command prints
    "names consumers never recognised": ("reader = self._names_consumer(name, args) if name else None", "reader = None"),
    "earlier pipeline stages are not producers": ("            hit = None\n            for prev in pl.cmds[:idx]:", "            hit = None\n            for prev in []:"),
    "a consumer's stdin redirect is not a producer": ("        for r in cmd.redirs if cmd is not None else []:\n            if r.op in ('<', '<>')",
                                                      "        for r in []:\n            if r.op in ('<', '<>')"),
    "process substitution arguments are not producers": ("if a.subs and (a.raw or '').lstrip('\"\\'').startswith('<('):", "if False:"),
    "command substitutions in reader arguments not judged": ("        self._substituted_names(rest, pl, idx)\n", ""),
    "read variables are not bound": ("            self._bind_read_vars(rest, pl, idx, cmd)  # after dispatch", "            pass  # after dispatch"),
    "loop input on done is not pre-bound": ("        self._prebind_loop_input(pipelines)\n", ""),
    "for items from a substitution are not bound": ("                hit = next((h for h in (self._script_lists_creds(inner) for inner in item.subs[:4]) if h), None)",
                                                    "                hit = None"),
    "producers ignore directories and ancestors": ("                        if self.under_cred_dir(path) or self.under_cred_parent(path, below=True):\n                            return t",
                                                   "                        if self.under_cred_dir(path):\n                            return t"),
    "producers ignore the working directory": ("                return ctx.cwd\n        return None", "                return None\n        return None"),
    "producer values inside words not derived": ("for t in [alt] + (_derived_texts(alt, curl=True) if len(alts) <= 8 else []):", "for t in [alt]:"),
    "xargs value options not skipped": [("'xargs': ('-n', '-I', '-J',", "'xargs-unused': ('-n', '-I', '-J',"),
                                        ("if real is None or not re.match(r'[A-Za-z_]', real):", "if False:")],
    "a misparsed xargs or parallel command is not searched for a reader": ("if real is None or not re.match(r'[A-Za-z_]', real):", "if False:"),
    "tar names file is not a name list": ("            return name if _tar_names_file(name, args) else None", "            return None"),
    # receipt r7 F1: the tar names-file table
    "bsdtar -I is not a names file": ("_TAR_NAME_LETTERS = {'tar': 'TI', 'bsdtar': 'TI', 'gtar': 'T'}",
                                      "_TAR_NAME_LETTERS = {'tar': 'T', 'bsdtar': 'T', 'gtar': 'T'}"),
    "plain tar -I is not a names file": ("_TAR_NAME_LETTERS = {'tar': 'TI', 'bsdtar': 'TI', 'gtar': 'T'}",
                                         "_TAR_NAME_LETTERS = {'tar': 'T', 'bsdtar': 'TI', 'gtar': 'T'}"),
    "--files-from abbreviations not recognised": ("if len(long_name) >= 5 and any(full.startswith(long_name) for full in _TAR_NAME_LONGS):",
                                                  "if long_name in _TAR_NAME_LONGS:"),
    "old-style names letters ignored": ("        if k == 0 and not t.startswith('-'):\n            if any(ch in letters for ch in t):\n                return True",
                                        "        if k == 0 and not t.startswith('-'):\n            if False:\n                return True"),
    "names letter read inside an option value": ("                if ch in _TAR_VALUE_ALL:\n                    break\n    return False",
                                                 "                if False:\n                    break\n    return False"),
    "bsdtar -I still read as a command": ("    'bsdtar': ('', ('use-compress-program',)),", "    'bsdtar': ('I', ('use-compress-program',)),"),
    # receipt r7 F2: find -files0-from
    "files0-from list not judged": ("            listed = self._files0_hit(args, pl, idx)", "            listed = None"),
    "files0-from stdin not judged": ("            if value.text in ('-', '/dev/stdin', '/dev/fd/0'):", "            if False:"),
    "files0-from value is not a producer": ("_find_cred_roots(rargs, []) + _find_files0_values(rargs) if real", "_find_cred_roots(rargs, []) if real"),
    # receipt r7 fail closed
    "raw fallback ignores credential locations": ("if PROTECTED_TEXT.search(t) or SECRET_TEXT.search(t) or raw_credential(t):",
                                                  "if PROTECTED_TEXT.search(t) or SECRET_TEXT.search(t):"),
    "raw fallback ignores quoted forms": ("    return bool(CRED_TEXT.search(text) or CRED_TEXT.search(re.sub(r'[\\'\"\\\\]', '', text)))",
                                          "    return bool(CRED_TEXT.search(text))"),
    "launcher fallback ignores credential locations": ("command_guard_hook.py",
                                                       "    if CRED_TEXT.search(t) or CRED_TEXT.search(re.sub(r'[\\'\"\\\\]', '', t)):\n        return True",
                                                       "    if False:\n        return True"),
    "brace sequences not expanded": ("        seq = _BRACE_SEQ.fullmatch(text[i + 1:j - 1]) if depth == 0 else None", "        seq = None"),
    "lexer skips sequence-only braces": ("        if '{' in raw and (',' in raw or '..' in raw):", "        if '{' in raw and ',' in raw:"),
    "overflow not judged as a glob": ("            return self.alts[:32] + [_overflow_glob(self.overflow)]", "            return self.alts[:32]"),
    "credential alternatives not capped": ("        if alts is None or len(alts) > cap:", "        if alts is None:"),
    "read_creds keeps the old alternatives": ("            alts = w.cred_alts() or [w.text]\n            hit, shown",
                                              "            alts = w.all_alts() or w.alts[:32] or [w.text]\n            hit, shown"),
    "name check keeps the old alternatives": ("        alts = word.cred_alts() if word is not None else [text]",
                                              "        alts = (word.all_alts() or word.alts[:32]) if word is not None else [text]"),
    "zip -@ is not a name list": ("return name if any('@' in t for t in short) or '--names-stdin' in texts else None", "return None"),
    "cpio and pax are not name lists": ("        if name in ('cpio', 'bsdcpio', 'pax', 'afio'):\n            return name", "        if False:\n            return name"),
    "ack -x is not a name list": ("return name if any(t.startswith('--files') for t in texts) or any('x' in t for t in short) else None", "return None"),
    "curl -K is not a name list": ("return name if any('K' in t for t in short) or any(t.startswith('--conf') for t in texts) else None", "return None"),
    "sftp batch input is not a name list": ("        if name == 'sftp':\n            return name", "        if False:\n            return name"),
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
    for name, spec in MUTANTS.items():
        pairs = spec if isinstance(spec, list) else [spec]  # a list breaks two independent layers at once
        # a three-item spec names the hook file it breaks (the launcher keeps its own copy of the raw-text probe)
        target = pairs[0][0] if len(pairs[0]) == 3 else GUARD
        pairs = [p[-2:] for p in pairs]
        tmp = tree()
        try:
            path = tmp / "harness" / "hooks" / target
            text = path.read_text()
            if any(old not in text for old, _ in pairs):
                print("MUTANT NOT APPLIED:", name)
                bad += 1
                continue
            for old, new in pairs:
                text = text.replace(old, new, 1)
            path.write_text(text)
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
