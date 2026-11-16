#!/usr/bin/env python3
"""1377 v3 code fixes for receipt bugtracker-pr1377-gate-v2 F1-F5. Run from the bugtracker repo root.
Usage: patch_v3_code.py [F1 F2 F3 F4 F5]   (default: all)"""
import sys

RH = 'infra/release-harness/'
ONLY = set(sys.argv[1:]) or {'F1', 'F2', 'F3', 'F4', 'F5'}


def edit(path, old, new, count=1):
    t = open(path).read()
    n = t.count(old)
    if n != count:
        sys.exit('anchor %r in %s found %d times, want %d' % (old[:70], path, n, count))
    open(path, 'w').write(t.replace(old, new))


CTL = RH + 'selfhost-ctl.py'
SHIP = RH + 'rw-ship.sh'

# ---------------------------------------------------------------- F1
if 'F1' in ONLY:
    edit(CTL, '''import argparse, hashlib, json, os, re, shutil, subprocess, sys, time
''', '''import argparse, hashlib, json, os, re, shutil, subprocess, sys, time
try: import tomllib                     # python >= 3.11: the containerd config is read as TOML, exactly
except ImportError: tomllib = None      # older python: the strict reader below accepts only forms it cannot misread
''')
    edit(CTL, '''        top = []
        for line in text.split('\\n'):
            if re.match(r'^\\s*\\[', line): break
            top.append(line)
        body = '\\n'.join(top)
        im = re.search(r'^\\s*imports\\s*=\\s*\\[([^\\]]*)\\]', body, re.M)
        if (im and re.sub(r'(#[^\\n]*)|[\\s,]', '', im.group(1))) or (not im and re.search(r'^\\s*imports\\s*=', body, re.M)):
            raise Refused('the containerd config %s uses imports, which can override its root' % cfg)
        hits = [l for l in top if re.match(r'^\\s*root\\s*=', l)]
        if len(hits) > 1: raise Refused('the containerd config %s sets root %d times' % (cfg, len(hits)))
        if not hits: root = CTD_DEFAULT_ROOT
        else:
            m = re.match(r'^\\s*root\\s*=\\s*(["\\x27])([^"\\x27\\\\\\n]*)\\1\\s*(#.*)?$', hits[0])
            if not m or not m.group(2).startswith('/'): raise Refused('the containerd config %s has an unreadable root' % cfg)
            root = m.group(2)
''', '''        root = ctd_config_root(text, cfg)
''')
    edit(CTL, '''def docker(*a, check=False, timeout=None, cwd=None):
''', '''# The strict reader (no tomllib). Above the first table header every line is a comment, a blank, or ONE bare key set to a
# basic string without escapes, a literal string, a decimal integer, true/false, or a one-line array of such strings.
# Anything else (quoted or dotted keys, inline tables, escapes, multi-line strings or arrays, other numbers) refuses.
_TS = r"""(?:"[^"\\\\\\n]*"|'[^'\\n]*')"""
CTD_TOP_LINE = re.compile(r'^[ \\t]*(?P<k>[A-Za-z0-9_-]+)[ \\t]*=[ \\t]*(?P<v>%s|[+-]?[0-9]+|true|false|\\[[ \\t]*(?:%s[ \\t]*,[ \\t]*)*(?:%s[ \\t]*,?[ \\t]*)?\\])[ \\t]*(?:#[^\\n]*)?$' % (_TS, _TS, _TS))


def ctd_top_strict(text, cfg):
    """{top-level key: [raw value, ...]} read by the strict grammar above, or Refused."""
    top = []
    for n, line in enumerate(text.split('\\n'), 1):
        line = line.rstrip('\\r')
        if re.match(r'^[ \\t]*\\[', line): break
        top.append((n, line))
    region = '\\n'.join(l for _, l in top)
    if '"""' in region or "\\x27\\x27\\x27" in region:
        raise Refused('the containerd config %s has a multi-line string above its first table, which %s' % (cfg, CTD_NOSAFE))
    keys = {}
    for n, line in top:
        s = line.strip()
        if not s or s.startswith('#'): continue
        m = CTD_TOP_LINE.match(line)
        if not m: raise Refused('the containerd config %s line %d %s' % (cfg, n, CTD_NOSAFE))
        keys.setdefault(m.group('k'), []).append(m.group('v'))
    return keys


CTD_NOSAFE = 'cannot be read safely without tomllib (python < 3.11)'


def ctd_config_root(text, cfg):
    """containerd's top-level root from the text of its config file (CTD_DEFAULT_ROOT when it sets none), or Refused.
    tomllib when it imports, else the strict reader; both refuse a non-empty imports, a root or imports key spelled in
    another case (containerd's decoder may match it), and a root that is not an absolute path string."""
    if tomllib is not None:
        try: doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e: raise Refused('the containerd config %s is not valid TOML (%s)' % (cfg, str(e)[:120]))
        keys = list(doc)
        root, imports = doc.get('root'), doc.get('imports', [])
    else:
        top = ctd_top_strict(text, cfg)
        keys = list(top)
        for k in ('root', 'imports'):
            if len(top.get(k, [])) > 1: raise Refused('the containerd config %s sets %s %d times' % (cfg, k, len(top[k])))
        raw_root, raw_imports = (top.get('root') or [None])[0], (top.get('imports') or ['[]'])[0]
        root = raw_root[1:-1] if raw_root and raw_root[0] in '"\\x27' else (0 if raw_root is not None else None)
        imports = [] if re.fullmatch(r'\\[[ \\t]*\\]', raw_imports) else ['?']
    for k in keys:
        if k.lower() in ('root', 'imports') and k != k.lower():
            raise Refused('the containerd config %s spells %s as %r' % (cfg, k.lower(), k))
    if not isinstance(imports, list) or imports:
        raise Refused('the containerd config %s uses imports, which can override its root' % cfg)
    if root is None: return CTD_DEFAULT_ROOT
    if not isinstance(root, str) or not root.startswith('/'): raise Refused('the containerd config %s has an unreadable root' % cfg)
    return root


def docker(*a, check=False, timeout=None, cwd=None):
''')

# ---------------------------------------------------------------- F3 (VM side) and F4
if 'F3' in ONLY:
    edit(CTL, ''''path outside the secrets directory': 'outside-dir', 'cannot read (error)': 'read-error'}''',
         ''''path outside the secrets directory': 'outside-dir', 'cannot read (error)': 'read-error',
                  'both JOB_ENV_ and JOB_ENVFILE_ are set': 'conflict'}''')
    JEF = 'apps/job-dispatcher/src/job-env-file.ts'
    edit(JEF, '''export function envFileError(entry: Pick<JobEnvFileEntry, 'id'>, reason: string): string {
  return `job env file for ${entry.id}: ${reason}`;
}
''', '''export function envFileError(entry: Pick<JobEnvFileEntry, 'id'>, reason: string): string {
  return `job env file for ${entry.id}: ${reason}`;
}

/** The phrase rw-ship's gate (c) maps to `error:conflict` (selfhost-ctl.py DISP_ERR_WORDS). */
export const ENVFILE_CONFLICT = 'both JOB_ENV_ and JOB_ENVFILE_ are set';

/**
 * The one conflict check launch and boot share (receipt bugtracker-pr1377-gate-v2 F3): the kind's own JOB_ENV_ var for
 * the same VAR makes every launch 501, so boot must not report that key `ok`.
 */
export function envFileConflict(entry: Pick<JobEnvFileEntry, 'varName'>, baseEnv: Record<string, string> | undefined): boolean {
  return baseEnv !== undefined && Object.prototype.hasOwnProperty.call(baseEnv, entry.varName);
}
''')
    edit(JEF, '''    if (Object.prototype.hasOwnProperty.call(baseEnv, entry.varName)) {
      return { ok: false, error: envFileError(entry, 'both JOB_ENV_ and JOB_ENVFILE_ are set') };
    }
''', '''    if (envFileConflict(entry, baseEnv)) return { ok: false, error: envFileError(entry, ENVFILE_CONFLICT) };
''')
    edit(JEF, '''export function bootEnvFileStatusLines(config: { jobEnvFiles: JobEnvFiles; jobEnvFileDir: string }): string[] {
  const lines: string[] = [];
  for (const entry of config.jobEnvFiles.entries) {
    let read: JobEnvFileRead;
''', '''export function bootEnvFileStatusLines(config: {
  jobEnvFiles: JobEnvFiles;
  jobEnvFileDir: string;
  jobBaseEnv: Record<JobKind, Record<string, string>>;
}): string[] {
  const lines: string[] = [];
  for (const entry of config.jobEnvFiles.entries) {
    if (envFileConflict(entry, config.jobBaseEnv[entry.kind])) {
      lines.push(envFileError(entry, ENVFILE_CONFLICT));
      continue;
    }
    let read: JobEnvFileRead;
''')
    edit('apps/job-dispatcher/src/boot-check.ts', '''  const lines = bootEnvFileStatusLines({ jobEnvFiles: config.jobEnvFiles, jobEnvFileDir: envFileDir });''',
         '''  const lines = bootEnvFileStatusLines({ jobEnvFiles: config.jobEnvFiles, jobEnvFileDir: envFileDir, jobBaseEnv: config.jobBaseEnv });''')
if 'F4' in ONLY:
    edit(CTL, '''def cmd_envfile_key(stk, a):
    path = os.path.join(stk.env_dir, 'dispatcher.env')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        n = sum(1 for l in f.read().split(b'\\n') if l.rstrip(b'\\r') == JOBSECRET_KEY_LINE.encode())
    out({'count': n}); return 0
''', '''def cmd_envfile_key(stk, a):
    """Gate (b): `count` is every non-comment line of dispatcher.env that names the key at all (any assignment syntax, a
    JOB_ENV_ twin included), `canonical` the lines that are byte for byte the canonical line. rw-ship passes only 1 and 1
    (receipt bugtracker-pr1377-gate-v2 F4: a second, different assignment changes the effective value)."""
    path = os.path.join(stk.env_dir, 'dispatcher.env')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        lines = [l.rstrip(b'\\r') for l in f.read().split(b'\\n')]
    name = JOBSECRET_KEY_LINE.split('=', 1)[0][len('JOB_ENVFILE_'):].encode()
    named = [l for l in lines if name in l and not l.lstrip().startswith(b'#')]
    out({'count': len(named), 'canonical': sum(1 for l in named if l == JOBSECRET_KEY_LINE.encode())}); return 0
''')
    edit(SHIP, '''    JSK=$(jget "$(vmctl envfile-key 2>/dev/null | grep -m1 '^{')" count)
    say "job secret gate (b) key lines in dispatcher.env: ${JSK:-unreadable}"
    [ "$JSK" = 1 ] || js_refuse "(b) dispatcher.env names the key ${JSK:-an unreadable number of} time(s), not once"
''', '''    JSKJ=$(vmctl envfile-key 2>/dev/null | grep -m1 '^{'); JSK=$(jget "$JSKJ" count); JSC=$(jget "$JSKJ" canonical)
    say "job secret gate (b) key lines in dispatcher.env: ${JSK:-unreadable}${JSK:+ (canonical ${JSC:-unreadable})}"
    [ "$JSK" = 1 ] && [ "$JSC" = 1 ] || js_refuse "(b) dispatcher.env names the key ${JSK:-an unreadable number of} time(s), ${JSC:-unreadable} of them the canonical line; it must be exactly the one canonical line"
''')

# ---------------------------------------------------------------- F5
if 'F5' in ONLY:
    edit(RH + 'ac13-count.py', '''    and so is an int beyond +-2**53 (receipt pr1370-v2c F1: it never reaches a float conversion, so no traceback)."""
    if isinstance(v, bool): return None
    if isinstance(v, int): return v if -MAX_TIME <= v <= MAX_TIME else None
    return v if isinstance(v, float) and math.isfinite(v) else None
''', '''    and so is an int beyond +-2**53 (receipt pr1370-v2c F1: it never reaches a float conversion, so no traceback), and a
    finite float beyond +-2**53 (receipt bugtracker-pr1377-gate-v2 F5: 1e100 would otherwise fall outside every window and
    vanish instead of counting as unknown)."""
    if isinstance(v, bool): return None
    if isinstance(v, int): return v if -MAX_TIME <= v <= MAX_TIME else None
    return v if isinstance(v, float) and math.isfinite(v) and -MAX_TIME <= v <= MAX_TIME else None
''')

# ---------------------------------------------------------------- F2
if 'F2' in ONLY:
    edit(SHIP, '''  sh_fail_rollback(){ # sh_fail_rollback <why>: the switch went wrong after this run changed the stack
    [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1"
''', '''  sh_fail_rollback(){ # sh_fail_rollback <why>: the switch went wrong after this run changed the stack
    # receipt bugtracker-pr1377-gate-v2 F2: once the switch's `up` ran and until gate (c) passed, a released
    # intelligence-worker may be running without a verified key: re-hold it FIRST, whatever failed
    if [ -n "${SH_UP_RAN:-}" ] && [ -z "${JS_C_OK:-}" ] && ! held intelligence-worker; then js_hold_fail "$1"; fi
    [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1"
''')
    edit(SHIP, '''    js_rehold "${STAMP}h" || js_nohold "$1, then the dispatcher-only re-hold failed ($(grep -m1 -E '^(UP_|REFUSED|FAILED)' "$RD/up-${STAMP}h.txt" "$RD/pin-${STAMP}h.txt" 2>/dev/null | cut -d: -f2- | cut -c1-200))"
''', '''    js_rehold "${STAMP}h" || js_rehold_failed "$1, then the dispatcher-only re-hold failed ($(grep -m1 -E '^(UP_|REFUSED|FAILED)' "$RD/up-${STAMP}h.txt" "$RD/pin-${STAMP}h.txt" 2>/dev/null | cut -d: -f2- | cut -c1-200))"
''')
    edit(SHIP, '''  js_hold_fail(){ # js_hold_fail <why>: gate (c) failed after the switch. Re-hold FIRST (dispatcher only), then roll back as usual
''', '''  js_intel(){ # js_intel <state json>: "held", or the JOB_IMAGE_INTELLIGENCE_WORKER value, or nothing when unreadable/ambiguous
    python3 -c 'import json,sys
try: s=json.loads(sys.argv[1])
except Exception: sys.exit()
j=s.get("jobs") if isinstance(s,dict) else None
if not isinstance(j,dict) or "error" in j: sys.exit()
v=j.get("JOB_IMAGE_INTELLIGENCE_WORKER"); h=s.get("jobs_held")
if not isinstance(v,str) or not v or "\\n" in v or not isinstance(h,list): sys.exit()
print("held" if "JOB_IMAGE_INTELLIGENCE_WORKER" in h else v)' "$1" 2>/dev/null; }
  js_rehold_failed(){ # js_rehold_failed <why>: the dispatcher-only re-hold failed. After a migration: stop (exit 8). Before any
    # (lead ruling wa5b72dea2cf): roll back; exit 5 only when the previous release is back (live API at BEFORE) and its
    # intelligence-worker line is held or byte for byte what it was before this run; anything else is exit 8.
    [ "${MIG_APPLIED:-0}" = 0 ] || js_nohold "$1"
    say "$1; no migration was applied, so rolling the self-host stack back to $RB_API"
    rb_guard "rolling back ($1)" api || lost "rollback refused ($1); intelligence-worker is NOT re-held"
    infl rollback; local v="" iw="" how="" rbok=1
    # a re-hold pin that went through (only its up failed) installed files of its own: undo it first, or the run's own
    # restore is refused as stale (compose changed after this run installed it)
    if grep -q '^{' "$RD/pin-${STAMP}h.txt" 2>/dev/null; then
      vmctl restore --stamp "${STAMP}h" > "$RD/restore-${STAMP}h.txt" 2>&1 || { rbok=""; head -3 "$RD/restore-${STAMP}h.txt" | cut -c1-300 | tee -a "$LOG"; }; fi
    if [ -n "$rbok" ] && sh_rollback; then for i in $(seq 1 18); do v=$(live_sha); [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ] && break; sleep 10; done; fi
    iw=$(js_intel "$(sh_state)")
    if [ "$iw" = held ]; then how=held; elif [ -n "$iw" ] && [ "$iw" = "$INTEL_PRE" ]; then how=same-as-before; fi
    say "intelligence-worker after the rollback: ${iw:-unreadable} (before this run: ${INTEL_PRE:-unreadable})"
    if [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ] && [ -n "$how" ]; then
      say "ROLLED BACK: live API is $v again; intelligence-worker on the restored release: $how"
      dbx "$NAME" deploy-failed "$v" "$1; rolled back to the previous stack $RB_API (intelligence-worker $how); run $RD"; exit 5; fi
    js_nohold "$1; the rollback did not restore a verified previous release (live API ${v:-unreadable}, intelligence-worker ${iw:-unreadable}, before this run ${INTEL_PRE:-unreadable})"; }
  js_hold_fail(){ # js_hold_fail <why>: gate (c) failed after the switch. Re-hold FIRST (dispatcher only), then roll back as usual
''')
    edit(SHIP, '''    say "job secret gate: intelligence-worker is released by this run; derive blob $(js_blob | cut -c1-12)"
''', '''    say "job secret gate: intelligence-worker is released by this run; derive blob $(js_blob | cut -c1-12)"
    INTEL_PRE=$(js_intel "$SH_BEFORE")   # the VM state read before anything changed (selfhost-before.json)
    say "job secret gate: intelligence-worker before this run: ${INTEL_PRE:-unreadable}"
    [ -n "$INTEL_PRE" ] || js_refuse "the VM state before this run does not name one readable JOB_IMAGE_INTELLIGENCE_WORKER value, so a failed switch could not prove its rollback"
''')
    edit(SHIP, '''  vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up.txt" 2>&1; rc=$?
''', '''  SH_UP_RAN=1   # from here a released intelligence-worker may be running: every failure re-holds it first (F2)
  vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up.txt" 2>&1; rc=$?
''')
    edit(SHIP, '''    [ "$DST" = ok ] || js_hold_fail "the recreated job-dispatcher did not log the GitHub App key file ok (${DST:-unreadable}, gate c)"
  fi
''', '''    [ "$DST" = ok ] || js_hold_fail "the recreated job-dispatcher did not log the GitHub App key file ok (${DST:-unreadable}, gate c)"
    JS_C_OK=1
  fi
''')
    edit(SHIP, '''MIGLOG="ssh build machine: ~/rw/mig-*.log"; MIG_APPLIED=0; SWITCH_AT=""; SH_BEFORE=""
''', '''MIGLOG="ssh build machine: ~/rw/mig-*.log"; MIG_APPLIED=0; SWITCH_AT=""; SH_BEFORE=""; SH_UP_RAN=""; JS_C_OK=""; INTEL_PRE=""
''')
print('code applied:', ' '.join(sorted(ONLY)))
