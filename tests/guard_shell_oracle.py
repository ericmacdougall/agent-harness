"""Differential shell oracle for the guards' shared lexer (goodqa#17059, goodqa#17060, goodqa#17044, goodqa#17073).

The guards decide what a command text runs; the shells decide what it really runs. Every parser repair so far was
blocked by a reviewer who found, by reading, one more place where the two disagree about a word, a blank, a line end
or a keyword. This finds those places by running the shells.

Each generated text holds a marker command, `mk -x ID`, where a guard's twin would stand. Two phases:

* `shells` runs every text under bash, dash and zsh (as `-c TEXT`, and as `eval` of the text inside `-c`, the way
  agent tools hand a command to a shell; seeds also as a script file) inside a bubblewrap sandbox: no network, a
  cleared environment, read-only system directories, one throwaway working directory, and the marker's record
  directory bound where no text names it. It records, per text, which shells and modes ran the marker.
  Shells only ever run markers. A text is refused before any exec if it holds either twin or a word outside the
  closed vocabulary's programs.
* `judge` reads those results, puts each guard's twin where the marker was (command_guard: a protected-path
  deletion; kill_guard: a broad kill, which it refuses only as a real command) and asks the guards of a hooks
  directory, with the analysis clock removed so that load cannot change a verdict.

Property, per guard: whenever any shell ran the marker, the guard refuses the twin text. A text a shell ran and the
guard allowed or only warned on is a finding. The reverse (no shell ran it, the guard refused) is counted as cost.

The texts come from a small grammar, deterministic by seed:
  E   every text of the form W1 J1 W2 J2 MARKER [closers], over WORDS and JOINTS (bounded and exhaustive);
  R   sampled longer texts (3 to 6 words) with an optional preamble line (aliases, disabled keywords, options);
  C   the marker inside contexts (substitutions, expansion bodies, case patterns, here-documents, functions);
  S   the shapes from the PR 342, 346 and 348 reviews and goodqa#17073;
  M   each seed with each space replaced in turn by each other blank kind.
S and M are held out when checking that the grammar alone (E, R, C) finds each known class.

What it leaves out: interactive-only behaviour (history expansion, rc-file aliases); other shell versions than
those on the host; options and environment set outside the text; runtime values (variable contents, IFS, functions
defined elsewhere, globs that match files); PowerShell; computed payloads beyond a literal eval; markers that would
run after the per-run timeout. It samples a grammar: it finds disagreements inside its productions and proves
nothing outside them.

This is a dev-host job (Linux, bubblewrap, many cores), not part of the Mac's focused suite:
  python3 -B tests/guard_shell_oracle.py shells --out RESULTS.jsonl [--seed 1] [--sampled 20000] [--jobs 40]
  python3 -B tests/guard_shell_oracle.py judge --results RESULTS.jsonl --hooks harness/hooks [--private FILE]
  python3 -B tests/guard_shell_oracle.py local --results RESULTS.jsonl --findings FILE   # Mac: findings only
The judge prints counts, rule ids and skeletons (atom names), never text; --private writes the finding texts to a
file the caller keeps private.
"""
import argparse
import collections
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# command_guard refuses this deletion of a protected path; kill_guard refuses this kill only as a real command
TWINS = {'command_guard': 'rm -rf ' + '~/.claude/projects', 'kill_guard': 'kill -9 ' + '-1'}
MARK = 'mk -x '  # three words, like each twin

WORDS = {
    'case': 'case y in', 'case_pat': 'case y in y)', 'esac': 'esac', 'pat': 'y)', 'dsemi': ';;',
    'if': 'if true; then', 'then': 'then', 'fi': 'fi', 'do': 'do', 'done': 'done', 'while': 'while false; do',
    'time': 'time', 'bang': '!', 'lbrace': '{', 'rbrace': '}', 'lparen': '(', 'rparen': ')', 'dbr': '[[ a',
    'rdbr': ']]', 'echo': 'echo', 'true': 'true', 'fdef': 'f()', 'function': 'function f', 'arr': 'x=()',
    'assign': 'x=1', 'echo_if': 'echo if', 'echo_case': 'echo case', 'in': 'in',
}
JOINTS = {
    'sp': ' ', 'tab': '\t', 'cr': '\r', 'sp_cr_sp': ' \r ', 'ff': '\f', 'sp_ff_sp': ' \f ', 'vt': '\v',
    'sp_vt_sp': ' \v ', 'nbsp': '\u00a0', 'semi': ';', 'nl': '\n', 'crlf': '\r\n', 'bs_crlf': ' \\\r\n',
    'bs_lf': ' \\\n', 'and': ' && ', 'or': ' || ', 'pipe': ' | ', 'bg': ' & ',
}
CLOSERS = {'case': ' esac', 'case_pat': ';; esac', 'if': '; fi', 'while': '; done', 'lbrace': '; }',
           'lparen': ' )', 'dbr': ' ]]'}
PREAMBLES = {
    'none': '',
    'bash_alias_case': 'shopt -s expand_aliases\nalias case=true\n',
    'bash_aliases_array': 'shopt -s expand_aliases\nBASH_ALIASES[case]=true\n',
    'alias_if': 'shopt -s expand_aliases 2>/dev/null\nalias if=true\n',
    'zsh_galias': 'galiases[case]=true 2>/dev/null\n',
    'zsh_disable': 'disable -r case 2>/dev/null\n',
    'eval_alias': "shopt -s expand_aliases 2>/dev/null\neval 'alias case=true'\n",
    'alias_dbr': "shopt -s expand_aliases 2>/dev/null\nalias '[['=false\n",
}
CONTEXTS = {
    'cmdsub': 'echo $({X})', 'dq_cmdsub': 'echo "$({X})"', 'backtick': 'echo `{X}`',
    'default': 'echo ${x:-$({X})}', 'dq_default': 'echo "${x:-$({X})}"', 'assign_default': 'x=${x:=$({X})}',
    'arith': 'echo $(( $({X}) ))', 'arith_subshell': 'echo $(({X}) )', 'case_in_sub': 'echo $(case a in a) {X};; esac)',
    'brace_in_sub': 'echo "${x:-$(true }; {X})}"', 'case_subject': 'case $({X}) in *) ;; esac',
    'case_pattern': 'case a in $({X})) ;; esac', 'dbr_operand': '[[ -n $({X}) ]]',
    'dbr_or': '[[ a == b || $({X}) ]]', 'heredoc': 'cat <<E\n$({X})\nE\n', 'procsub': 'cat <({X})',
    'func_body': 'f() {{B}{X};{B}}; f', 'func_case': 'f() { case a in a) {X};; esac; }; f',
    'background': '{X} &', 'time_kw': 'time {X}', 'pipe_time': 'true | time {X}', 'negate': '! {X}',
    'subshell': '({B}{X}{B})', 'group': '{{B}{X};{B}}', 'arith_sub_index': '[[ a -eq "a[$({X})]" ]]',
    'trap': "trap -- '{X}' EXIT", 'env_split': "env --sp '{X}'", 'eval': "eval '{X}'",
    # controls: no shell runs the marker here; the shells phase must record none of them as run
    'ctl_single_quoted': "echo '{X}'", 'ctl_comment': 'true #{B}{X}', 'ctl_line_join': 'echo x \\\n{X}',
    'ctl_false_and': 'false && {X}', 'ctl_case_unmatched': 'case a in b) {X};; esac',
}
CONTEXT_BLANKS = {'sp': ' ', 'tab': '\t', 'cr': '\r', 'nl': '\n'}

# Shapes from the PR 342, 346 and 348 reviews and goodqa#17073, as templates. `base` is whether the base guards
# (main at d56a8cb0) are expected to allow the twin while a shell runs it; None where the review did not say.
SEEDS = [
    ('r348_f1_cr', '\r case y in; {X}', True), ('r348_f1_vt', '\v case y in; {X}', True),
    ('r348_f1_ff', '\f case y in; {X}', True), ('r348_f1_cr_tab', '\r\tcase y in; {X}', True),
    ('r348_f1_after_true', 'true; \r case y in; {X}', True),
    ('r348_f1_in_if', 'if true; then \r case y in; {X}; fi', True),
    ('r348_f1_regression', 'echo if case y in; \r case esac in; {X}', False),
    ('r348_f2_bash_aliases', 'shopt -s expand_aliases\nBASH_ALIASES[case]=echo\ncase y in; {X}', True),
    ('r348_f2_galiases', 'galiases[case]=echo\ncase y in; {X}', None),
    ('r348_f2_disable', 'disable -r case\ncase y in; {X}', None),
    ('r348_f2_eval_alias', "shopt -s expand_aliases\neval 'alias case=echo'\ncase y in; {X}", True),
    ('r348_p1_case_pattern', 'case x in $({X})) true ;; esac', True),
    ('r348_p2_bs_crlf', 'echo x \\\r\n{X}\n', True),
    ('t17073_after_true', 'true; echo x \\\r\n{X}\n', True),
    ('r346_f1_empty_array', 'x=() [[ a || {X} ]]', False), ('r346_f1_declare', 'declare -a x=() [[ a || {X} ]]', False),
    ('r346_f2_brace_if', '{if,} [[ a || {X} ]]', False), ('r346_f3_pipe_time', 'true | time [[ a || {X} ]]', False),
    ('r346_f4_cr_dbr', '[[\r a || {X} ]]', False), ('r346_f5_dash', "dash -c '[[ a || {X} ]]'", False),
    ('r346_f5_sh', "sh -c '[[ -d b ]] || {X}'", False),
    ('r346_f6_default', '[[ -z a || ${x:-$({X})} ]]', False),
    ('r346_f7_alias_zsh', "alias '[['=false; eval '[[ a || {X} ]]'", False),
    ('r346_f7_alias_bash', "shopt -s expand_aliases; alias '[['=false; eval '[[ a || {X} ]]'", False),
    ('r346_p1_done_case', 'echo done case x in; {X}', True),
    ('r346_p2_arith_index', '[[ a -eq "a[$({X})]" ]]', False),
    ('r349_early_brace', 'echo "${x:-$(true }; {X})}"', True), ('r349_early_case', 'echo $(case a in a) {X};; esac)', True),
    ('r342_f1_script_c', "script -q --c '{X}' /dev/null", None),
    ('r342_f1_script_comm', "script -q --comm='{X}' /dev/null", None),
    ('r342_f1_env_sp', "env --sp '{X}'", None), ('r342_f3_trap', "trap -- '{X}' EXIT", None),
]
# The kill guard's documented known limits that this lexer claims to close (docs/operations.md, kill guard Known
# limits rows 3, 4 and 5): a row's text leaves the docs only when the oracle shows its shapes refused.
SEEDS += [
    ('ops_row3_comment', 'true # note \\\n{X}', None),
    ('ops_row3_heredoc_quoted', "cat <<'E'\nx \\\nE\n{X}", None),
    ('ops_row3_heredoc', 'cat <<E\nx \\\nE\n{X}\nE\n', None),
    ('ops_row3_escaped_backslash', 'echo x \\\\\n{X}', None),
    ('ops_row4_default', 'echo ${x:-$({X})}', None),
    ('ops_row4_arith', 'echo $(( $({X}) ))', None),
    ('ops_row4_case_pattern', 'case x in $({X})) ;; esac', None),
    ('ops_row5_then_case', 'echo then case x in; {X}', None),
    ('ops_row5_if_case', 'echo if case x in; {X}', None),
]
# PR 349 review shapes
SEEDS += [
    ('r349_f1_case_args', 'echo "$(echo case in a)" ; {X} ; echo ")"', False),  # a regression at the 349 head
    ('r349_f1_case_args_nested', 'echo $(echo "$(echo case in a)" ; {X} ; echo ")")', False),
    ('r349_f3_default_paren', 'echo $(echo ${x:-(}; {X})', None),
    ('r349_f3_nested_quote', 'echo $(echo "$(echo "\'")"; {X} ) \' )', None),
    ('r349_f4_backtick_in_dq', 'echo $(echo "`{X}`")', None),
    ('r349_f4_comment', 'echo $(true # )\n{X})', None),
    ('r349_f4_heredoc', 'echo $(cat <<E\n)\nE\n{X})', None),
    ('r349_f4_ansi_c', "echo $(echo $'a\\'b'; {X})", None),
    ('r349_f5_dq_default_squote', 'echo "${x:-\'}"; {X}; echo "\'}"', None),
]
# Seeds that are open outside the lexer, and where they are tracked. The lexer PR's property is zero findings outside
# this set (main's ruling, 2026-11-24); each becomes a must-refuse seed when its fix lands.
SEED_OPEN = {
    'r342_f1_script_c': 'PR B, launcher model (#342, GoodQA goodqa#16943)',
    'r342_f1_script_comm': 'PR B, launcher model (#342, GoodQA goodqa#16943)',
    'r342_f1_env_sp': 'PR B, launcher model (#342, GoodQA goodqa#16943)',
    'r342_f3_trap': 'PR B, launcher model (#342, GoodQA goodqa#16943)',
}
# Which shells and modes ran each seed's marker at seed 1 on the dev host (bash 5.2.21, dash, zsh 5.9), where that
# is narrower than every shell in every mode. Agent tools run commands as `-c` text or through `eval`; a seed that
# runs only from a script file needs `bash FILE` or `zsh FILE` to matter.
SEED_MODES = {
    'r348_f2_bash_aliases': 'bash only (c, eval, file)',
    'r348_f2_galiases': 'zsh file only',
    'r348_f2_disable': 'zsh file only',
    'r348_f2_eval_alias': 'bash (c, eval, file), zsh file',
    'r346_f1_empty_array': 'bash only', 'r346_f1_declare': 'bash only',
    'r346_f2_brace_if': 'bash, dash', 'r346_f3_pipe_time': 'bash, dash', 'r346_f4_cr_dbr': 'bash, dash',
    'r346_f7_alias_zsh': 'dash, zsh',
    'r349_early_brace': 'bash, dash', 'r349_f3_default_paren': 'bash, dash',
    'r349_f3_nested_quote': 'no shell (a control)', 'r349_f4_ansi_c': 'bash, zsh',
    'r349_f5_dq_default_squote': 'dash, zsh',
}
# Nesting (family N): substitution and expansion forms inside each other, with closers and keywords that a scanner
# can misread inside, and the marker either inside or after the outer form.
OUTERS = {'cmdsub': '$(%s)', 'dq_cmdsub': '"$(%s)"', 'backtick': '`%s`', 'default': '${x:-%s}',
          'dq_default': '"${x:-%s}"', 'arith': '$((%s))', 'case_subject': 'case %s in *) ;; esac',
          'case_pattern': 'case a in %s) ;; esac'}
INNERS = {'marker': '{X}', 'sub': '$({X})', 'brace_close': 'true }; {X}', 'case_body': 'case a in a) {X};; esac',
          'case_args': 'echo case in a); {X}', 'sq_paren': "echo ')'; {X}", 'dq_paren': 'echo "("; {X}',
          'sq_brace': "echo '}'; {X}", 'subshell': '(true) ; {X}', 'arith_paren': '(1) ; {X}',
          'comment': 'true # )\n{X}', 'backtick_dq': 'echo "`{X}`"'}
NEUTRAL = {'case_args': 'echo case in a)', 'sq_paren': "echo ')'", 'dq_paren': 'echo "("', 'sq_brace': "echo '}'",
           'brace': 'echo }', 'paren_word': 'echo a)', 'subshell': '(true)', 'esac_word': 'echo esac'}
AFTER_TAILS = {'none': '', 'dq_paren': ' ; echo ")"', 'dq_brace': ' ; echo "}"', 'sq_paren': " ; echo ')'"}
MUTATION_BLANKS = {'tab': '\t', 'cr': '\r', 'sp_cr_sp': ' \r ', 'ff': '\f', 'vt': '\v', 'nbsp': '\u00a0'}
# programs a text may name; anything else at a command start in the closed vocabulary is a generator bug
VOCAB_PROGRAMS = {'mk', 'echo', 'true', 'false', 'cat', 'env', 'script', 'dash', 'sh', 'declare', 'shopt', 'alias',
                  'eval', 'trap', 'disable', 'x', 'f', 'time', 'galiases'}
SHELLS = ('bash', 'dash', 'zsh')


def closers(names):
    return ''.join(CLOSERS[n] for n in reversed(names) if n in CLOSERS)


def generate(seed=1, sampled=20000):
    """Return [(family, skeleton, template)]. Deterministic for a seed; a template repeated within a family is dropped
    (a template may appear in two families, so that held-out checks see the grammar's own copy)."""
    seen = set()

    def emit(family, skel, template):
        if (family, template) not in seen:
            seen.add((family, template))
            return [(family, skel, template)]
        return []

    out = []
    words = [('', '')] + list(WORDS.items())
    joints = list(JOINTS.items())
    for n1, w1 in words:
        for j1, s1 in joints:
            for n2, w2 in words:
                for j2, s2 in joints:
                    if not w1 and j1 != 'sp':
                        if not w2:
                            continue
                    parts = [w1 + s1 if w1 else s1 if w2 else '', w2 + s2 if w2 else '']
                    body = ''.join(parts)
                    used = [n for n in (n1, n2) if n]
                    skel = '%s %s %s %s X' % (n1 or '-', j1, n2 or '-', j2)
                    out += emit('E', skel, body + '{X}')
                    tail = closers(used)
                    if tail:
                        out += emit('E', skel + ' +close', body + '{X}' + tail)
    rng = random.Random(seed)
    names, jnames, pnames = list(WORDS), list(JOINTS), list(PREAMBLES)
    for _ in range(sampled):
        k = rng.randint(3, 6)
        pre = rng.choice(pnames) if rng.random() < 0.3 else 'none'
        seq = [(rng.choice(names), rng.choice(jnames)) for _ in range(k)]
        body = ''.join(WORDS[w] + JOINTS[j] for w, j in seq)
        tail = closers([w for w, _ in seq]) if rng.random() < 0.5 else ''
        skel = 'pre=%s %s X%s' % (pre, ' '.join('%s %s' % p for p in seq), ' +close' if tail else '')
        out += emit('R', skel, PREAMBLES[pre] + body + '{X}' + tail)
    for name, ctx in CONTEXTS.items():
        for bname, b in CONTEXT_BLANKS.items():
            t = ctx.replace('{B}', b)
            out += emit('C', 'ctx=%s blank=%s' % (name, bname), t)
            for pname in ('bash_alias_case', 'alias_dbr'):
                out += emit('C', 'ctx=%s blank=%s pre=%s' % (name, bname, pname), PREAMBLES[pname] + t)
    for oname, outer in OUTERS.items():
        for iname, inner in INNERS.items():
            out += emit('N', 'in %s(%s)' % (oname, iname), 'echo ' + outer % inner)
            for o2name, outer2 in OUTERS.items():
                out += emit('N', 'in %s(%s(%s))' % (oname, o2name, iname), 'echo ' + outer % (outer2 % inner))
        for nname, neutral in NEUTRAL.items():
            for tname, tail in AFTER_TAILS.items():
                for jname, j in (('semi', ' ; '), ('nl', '\n'), ('and', ' && ')):
                    out += emit('N', 'after %s(%s) %s X tail=%s' % (oname, nname, jname, tname),
                                'echo ' + outer % neutral + j + '{X}' + tail)
                    for o2name, outer2 in OUTERS.items():
                        out += emit('N', 'after %s(%s(%s)) %s X tail=%s' % (oname, o2name, nname, jname, tname),
                                    'echo ' + outer % (outer2 % neutral) + j + '{X}' + tail)
    for name, t, _ in SEEDS:
        out += emit('S', 'seed=%s' % name, t)
    for name, t, _ in SEEDS:
        spaces = [i for i, ch in enumerate(t) if ch == ' ']
        for i in spaces:
            for bname, b in MUTATION_BLANKS.items():
                out += emit('M', 'seed=%s at=%d blank=%s' % (name, i, bname), t[:i] + b + t[i + 1:])
    return out


def check_template(t):
    """Refuse a template that could run anything but a marker under a shell."""
    for twin in TWINS.values():
        if twin in t or twin.split()[0] + ' ' in t.replace('{X}', ''):
            raise ValueError('template holds a twin word')
    if t.count('{X}') != 1:
        raise ValueError('template must hold one marker')


# ---------------------------------------------------------------------------------------------------- shells phase
INNER = r'''
import json, os, re, resource, signal, subprocess, sys
# a shell that rejected the text as a whole (it ran nothing from it): bash and dash `syntax error`, zsh `parse error`
SYNTAX = re.compile(rb'syntax error|parse error')
resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
LOG = '/rec/log'
def ran_since(pos):
    try:
        with open(LOG) as f:
            f.seek(pos)
            new = f.read()
    except FileNotFoundError:
        return 0, set()
    return pos + len(new), set(new.split())
pos = 0
out = []
for line in sys.stdin:
    row = json.loads(line)
    marker = row['id']
    with open('/w/t.sh', 'w', newline='') as f:
        f.write(row['text'])
    ran, late, syntax = {}, set(), []
    for sh in row['shells']:
        for mode in row['modes']:
            argv = {'c': ['/usr/bin/' + sh, '-c', row['text']],
                    'eval': ['/usr/bin/' + sh, '-c', 'eval "$(cat /w/t.sh)"'],
                    'file': ['/usr/bin/' + sh, '/w/t.sh']}[mode]
            p = subprocess.Popen(argv, cwd='/w', stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE, start_new_session=True)
            try:
                err = p.communicate(timeout=2)[1] or b''
            except subprocess.TimeoutExpired:
                err = b''
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
            pos, got = ran_since(pos)
            key = '%s.%s' % (sh, mode)
            ran[key] = marker in got
            if SYNTAX.search(err[:8192]):
                syntax.append(key)
            late |= got - {marker}
    out.append({'id': marker, 'ran': ran, 'late': sorted(late), 'syntax': syntax})
import time
time.sleep(1)
pos, got = ran_since(pos)
print(json.dumps({'rows': out, 'tail': sorted(got)}))
'''

MK = '#!/bin/sh\nprintf "%s\\n" "$2" >> /rec/log\n'


def run_chunk(rows, tmp):
    """Run one chunk of texts in a fresh sandbox. Returns the inner script's rows, with late markers merged."""
    work, rec, mbin, inner = (tmp / d for d in ('w', 'rec', 'm', 'o'))
    for d in (work, rec, mbin, inner):
        d.mkdir(parents=True, exist_ok=True)
    (mbin / 'mk').write_text(MK)
    (mbin / 'mk').chmod(0o755)
    (inner / 'inner.py').write_text(INNER)
    argv = ['bwrap', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/sbin', '/sbin', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--bind', str(work), '/w', '--bind', str(rec), '/rec', '--ro-bind', str(mbin), '/m',
            '--ro-bind', str(inner), '/o', '--chdir', '/w', '--unshare-all', '--die-with-parent', '--new-session',
            '--clearenv', '--setenv', 'PATH', '/m:/usr/bin', '--setenv', 'HOME', '/w', '--setenv', 'LANG', 'C.UTF-8',
            '/usr/bin/python3', '-I', '/o/inner.py']
    payload = ''.join(json.dumps(r) + '\n' for r in rows)
    done = subprocess.run(argv, input=payload, capture_output=True, text=True, timeout=60 + 30 * len(rows))
    if done.returncode != 0:
        raise RuntimeError('sandbox failed: %s' % done.stderr.strip()[-300:])
    res = json.loads(done.stdout)
    late = set(res['tail'])
    for r in res['rows']:
        late |= set(r['late'])
    for r in res['rows']:
        r['late_ran'] = r['id'] in late
        del r['late']
    return res['rows']


def shells_phase(args):
    if not shutil.which('bwrap'):
        sys.exit('bwrap is required (a dev-host job)')
    texts = [t for t in generate(args.seed, args.sampled) if t[0] in args.families]
    if args.limit:
        texts = texts[:args.limit]
    rows = []
    for i, (family, skel, t) in enumerate(texts):
        check_template(t)
        ident = 'I%07d' % i
        modes = ['c', 'eval', 'file'] if family == 'S' else ['c', 'eval']
        rows.append({'id': ident, 'text': t.replace('{X}', MARK + ident), 'shells': list(SHELLS), 'modes': modes,
                     'family': family, 'skel': skel, 'template': t})
    from concurrent.futures import ThreadPoolExecutor
    size = args.chunk
    chunks = [rows[i:i + size] for i in range(0, len(rows), size)]
    base = Path(tempfile.mkdtemp(prefix='oracle-'))
    results = {}
    try:
        def one(k):
            return run_chunk([{x: r[x] for x in ('id', 'text', 'shells', 'modes')} for r in chunks[k]],
                             base / ('c%05d' % k))
        with ThreadPoolExecutor(args.jobs) as pool:
            for k, got in enumerate(pool.map(one, range(len(chunks)))):
                for g in got:
                    results[g['id']] = g
                shutil.rmtree(base / ('c%05d' % k), ignore_errors=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    with open(args.out, 'w') as f:
        for r in rows:
            g = results[r['id']]
            f.write(json.dumps({'id': r['id'], 'family': r['family'], 'skel': r['skel'], 'template': r['template'],
                                'ran': g['ran'], 'late_ran': g['late_ran'], 'syntax': g['syntax']}) + '\n')
    fam = collections.Counter(r['family'] for r in rows)
    ran = collections.Counter(r['family'] for r in rows
                              if any(results[r['id']]['ran'].values()) or results[r['id']]['late_ran'])
    print('texts', len(rows), 'by family', dict(fam), 'marker ran in some shell', dict(ran))


# ----------------------------------------------------------------------------------------------------- judge phase
JUDGE = r'''
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
import command_guard as cg, kill_guard as kg
_init = cg.Budget.__init__
def _no_clock(self, limits):  # offline measurement only: the wall-clock deadline makes verdicts depend on load
    _init(self, limits)
    self.deadline = float('inf')
cg.Budget.__init__ = _no_clock
twins = json.loads(sys.argv[2])
home = tempfile.mkdtemp(prefix='oj-')
cwd = tempfile.mkdtemp(prefix='oj-w-')
c = cg.Compiled(cg.load_policy(), cwd=cwd)
out = []
for line in sys.stdin:
    t = json.loads(line)
    row = []
    try:
        v, m = cg.decide(t.replace('{X}', twins['command_guard']), c, cwd=cwd)
        row += [v, m[m.find('['):m.find(']') + 1] if v != 'allow' else '']
    except Exception as e:
        row += ['error', type(e).__name__]
    try:
        k = kg.decide(t.replace('{X}', twins['kill_guard']), cwd=cwd, home=home)
        row += [k[0], k[1] or '']
    except Exception as e:
        row += ['error', type(e).__name__]
    out.append(row)
print(json.dumps(out))
'''


def judge_rows(templates, hooks, jobs):
    from concurrent.futures import ThreadPoolExecutor
    size = max(1, -(-len(templates) // (jobs * 4)))
    chunks = [templates[i:i + size] for i in range(0, len(templates), size)]

    def one(chunk):
        done = subprocess.run([sys.executable, '-c', JUDGE, str(hooks), json.dumps(TWINS)],
                              input=''.join(json.dumps(t) + '\n' for t in chunk), capture_output=True, text=True,
                              timeout=3600)
        if done.returncode != 0:
            raise RuntimeError('judge child failed: %s' % done.stderr.strip()[-300:])
        return json.loads(done.stdout)
    out = []
    with ThreadPoolExecutor(jobs) as pool:
        for got in pool.map(one, chunks):
            out += got
    return out


def judge_phase(args):
    rows = [json.loads(line) for line in open(args.results)]
    verdicts = judge_rows([r['template'] for r in rows], Path(args.hooks).resolve(), args.jobs)
    report = summarise(rows, verdicts)
    print(json.dumps(report['counts'], indent=1, sort_keys=True))
    for g in ('command_guard', 'kill_guard'):
        print('%s findings by skeleton (first 60):' % g)
        for skel, n in report['by_skel'][g][:60]:
            print('  %4d  %s' % (n, skel))
    print('seeds:')
    for line in report['seeds']:
        print('  ' + line)
    if args.verdicts:
        with open(args.verdicts, 'w') as f:
            json.dump(verdicts, f)
    if args.private:
        with open(args.private, 'w') as f:
            for r, v in zip(rows, verdicts):
                if ran_any(r) and (v[0] != 'block' or v[2] != 'block'):
                    f.write(json.dumps({'id': r['id'], 'family': r['family'], 'skel': r['skel'],
                                        'template': r['template'], 'ran': r['ran'], 'verdicts': v}) + '\n')
    return report


def ran_any(r):
    return any(r['ran'].values()) or r.get('late_ran')


JOINT_CLASS = {'sp': '_', 'tab': '_', 'cr': 'ODD', 'sp_cr_sp': 'ODD', 'ff': 'ODD', 'sp_ff_sp': 'ODD', 'vt': 'ODD',
               'sp_vt_sp': 'ODD', 'nbsp': 'NBSP', 'semi': ';', 'nl': ';', 'crlf': 'CRLF', 'and': ';', 'or': ';',
               'pipe': ';', 'bg': ';', 'bs_crlf': 'BSCRLF', 'bs_lf': 'BSLF'}


def skel_class(skel):
    """A coarser skeleton for counting: blank kinds and separators folded into classes, mutation offsets dropped."""
    words = skel.replace(' +close', '').split()
    if words and words[0].startswith('seed='):
        return ' '.join(w for w in words if not w.startswith('at='))
    return ' '.join(JOINT_CLASS.get(w, w) for w in words)


CONTEXT_OPEN = {'trap': 'r342_f3_trap', 'env_split': 'r342_f1_env_sp'}  # contexts that are open seeds' shapes


def open_seed(r):
    """The seed a row comes from when that seed is open outside this lexer (SEED_OPEN), else None."""
    if r['family'] in ('S', 'M'):
        name = r['skel'].split('=', 1)[1].split(' ')[0]
        return name if name in SEED_OPEN else None
    if r['family'] == 'C':
        return CONTEXT_OPEN.get(r['skel'].split(' ')[0].split('=', 1)[1])
    return None


def compare_phase(args):
    """Base against head over the same shell results: findings at each (open seeds apart), what changed where a
    shell ran the marker, and the reverse direction (no shell ran it, and a guard now refuses what it allowed)."""
    rows = [json.loads(line) for line in open(args.results)]
    base, head = json.load(open(args.base)), json.load(open(args.head))
    out = {'findings': collections.defaultdict(collections.Counter),
           'ran_refused_to_allowed': collections.defaultdict(collections.Counter),
           'not_run_allowed_to_refused': collections.defaultdict(collections.Counter)}
    skels = {k: {g: collections.Counter() for g in TWINS}
             for k in ('head_findings', 'reverse_accepted', 'reverse_rejected_everywhere', 'regressed')}
    for r, b, h in zip(rows, base, head):
        ran, fam, opened = ran_any(r), r['family'], open_seed(r)
        for g, at in (('command_guard', 0), ('kill_guard', 2)):
            bv, hv = b[at], h[at]
            if ran:
                for label, v in (('base', bv), ('head', hv)):
                    if v != 'block':
                        out['findings'][fam]['%s %s%s' % (label, g, ' open' if opened else '')] += 1
                if hv != 'block' and not opened:
                    skels['head_findings'][g][skel_class(r['skel'])] += 1
                if bv == 'block' and hv != 'block':
                    out['ran_refused_to_allowed'][fam][g] += 1
                    skels['regressed'][g][skel_class(r['skel'])] += 1
            elif bv != 'block' and hv == 'block':
                # rejected whole by every shell and mode (a syntax error: refusing it costs nothing), or accepted
                # by some shell that simply never reached the marker (refusing it can cost a real command)
                kind = 'rejected_everywhere' if set(r.get('syntax') or ()) >= set(r['ran']) else 'accepted'
                out['not_run_allowed_to_refused'][fam]['%s %s' % (g, kind)] += 1
                skels['reverse_' + kind][g][skel_class(r['skel'])] += 1
    print(json.dumps({k: {f: dict(c) for f, c in v.items()} for k, v in out.items()}, indent=1, sort_keys=True))
    for k, by in skels.items():
        for g, c in by.items():
            print('%s %s: %d texts, top skeletons:' % (k, g, sum(c.values())))
            for skel, n in c.most_common(args.top):
                print('  %5d  %s' % (n, skel))


def summarise(rows, verdicts):
    counts = collections.defaultdict(collections.Counter)
    by_skel = {g: collections.Counter() for g in TWINS}
    seeds = []
    expect = {name: exp for name, _, exp in SEEDS}
    for r, v in zip(rows, verdicts):
        fam = r['family']
        ran = ran_any(r)
        counts[fam]['texts'] += 1
        counts[fam]['ran'] += ran
        for g, (verdict, rule) in (('command_guard', v[0:2]), ('kill_guard', v[2:4])):
            if ran and verdict != 'block':
                counts[fam]['%s_finding_%s' % (g, verdict)] += 1
                by_skel[g][r['skel']] += 1
            elif not ran and verdict == 'block':
                counts[fam]['%s_refused_not_run' % g] += 1
            if ran and verdict == 'block':
                counts[fam]['%s_refused %s' % (g, rule)] += 1
        if fam == 'S':
            name = r['skel'].split('=', 1)[1]
            shells = sorted(k for k, x in r['ran'].items() if x)
            seeds.append('%-24s expected_base_finding=%-5s ran=%s command_guard=%s kill_guard=%s' % (
                name, expect.get(name), ','.join(shells) or 'none', v[0], v[2]))
    return {'counts': {k: dict(c) for k, c in counts.items()},
            'by_skel': {g: c.most_common() for g, c in by_skel.items()}, 'seeds': seeds}


# ----------------------------------------------------------------------------------------------------- local phase
def local_phase(args):
    """Findings only, under this machine's own shells (the Mac's zsh and /bin/bash 3.2), without a sandbox: the
    texts hold only markers, the closed vocabulary and no twin, so a run touches only its throwaway directory."""
    rows = [json.loads(line) for line in open(args.findings)]
    shells = [s for s in args.shells.split(',') if os.path.exists(s)]
    tmp = Path(tempfile.mkdtemp(prefix='oracle-local-'))
    try:
        mbin, rec = tmp / 'm', tmp / 'rec'
        mbin.mkdir()
        rec.mkdir()
        (mbin / 'mk').write_text(MK.replace('/rec/log', str(rec / 'log')))
        (mbin / 'mk').chmod(0o755)
        tally = collections.Counter()
        for r in rows:
            check_template(r['template'])
            ident = r['id']
            text = r['template'].replace('{X}', MARK + ident)
            for sh in shells:
                for mode in ('c', 'eval'):
                    work = tmp / 'w'
                    work.mkdir(exist_ok=True)
                    (work / 't.sh').write_text(text)
                    argv = [sh, '-c', text] if mode == 'c' else [sh, '-c', 'eval "$(cat %s)"' % (work / 't.sh')]
                    env = {'PATH': '%s:/usr/bin:/bin' % mbin, 'HOME': str(work), 'LANG': 'C.UTF-8'}
                    try:
                        subprocess.run(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                       timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                    log = rec / 'log'
                    got = log.read_text().split() if log.exists() else []
                    if log.exists():
                        log.unlink()
                    tally['%s %s %s' % (r['skel'], sh, mode)] += ident in got
                    tally['ran %s %s' % (sh, mode)] += ident in got
                    tally['texts %s %s' % (sh, mode)] += 1
        for k in sorted(k for k in tally if k.startswith(('ran ', 'texts '))):
            print(k, tally[k])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('shells')
    s.add_argument('--out', required=True)
    s.add_argument('--seed', type=int, default=1)
    s.add_argument('--sampled', type=int, default=20000)
    s.add_argument('--limit', type=int, default=0)
    s.add_argument('--families', default='ERCSM')
    s.add_argument('--jobs', type=int, default=40)
    s.add_argument('--chunk', type=int, default=200)
    j = sub.add_parser('judge')
    j.add_argument('--results', required=True)
    j.add_argument('--hooks', default=str(ROOT / 'harness' / 'hooks'))
    j.add_argument('--jobs', type=int, default=40)
    j.add_argument('--private')
    j.add_argument('--verdicts', help='write every verdict (no text) for `compare`')
    cmp_ = sub.add_parser('compare')
    cmp_.add_argument('--results', required=True)
    cmp_.add_argument('--base', required=True)
    cmp_.add_argument('--head', required=True)
    cmp_.add_argument('--top', type=int, default=25)
    loc = sub.add_parser('local')
    loc.add_argument('--findings', required=True)
    loc.add_argument('--shells', default='/bin/zsh,/bin/bash')
    g = sub.add_parser('count')
    g.add_argument('--seed', type=int, default=1)
    g.add_argument('--sampled', type=int, default=20000)
    a = p.parse_args(argv)
    if a.cmd == 'shells':
        shells_phase(a)
    elif a.cmd == 'judge':
        judge_phase(a)
    elif a.cmd == 'local':
        local_phase(a)
    elif a.cmd == 'compare':
        compare_phase(a)
    else:
        texts = generate(a.seed, a.sampled)
        for t in texts:
            check_template(t[2])
        print(len(texts), dict(collections.Counter(t[0] for t in texts)))


if __name__ == '__main__':
    main()
