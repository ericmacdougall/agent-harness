"""goodqa#16136 hold as a launch block (main approved option a, via the lead). python3 patch_hold.py DIR
A held JOB_IMAGE_* line is written as `KEY: "" # held`. Both the guard (create-guard-main.ts drops empty values from its
allowlist) and the dispatcher (server.ts: no image for the kind -> 501 "no image configured for job kind", docker never
invoked; the API treats 501 as definitive_not_started) then refuse that kind, whether or not an older image is on the host.
No guard or dispatcher code changes. An empty value is not an image ref, so nothing passes it to docker: presence and
post-switch checks already skip held keys."""
import os, sys
D = sys.argv[1]


def patch(name, pairs):
    p = os.path.join(D, name); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (name, t.count(old), old[:90]); t = t.replace(old, new)
    open(p, 'w').write(t)


patch('selfhost-ctl.py', [
    ('''each key must appear exactly once in the whole file, in that block); --job-hold keeps the
                                 current line.''',
     '''each key must appear exactly once in the whole file, in that block); --job-hold writes the
                                 line as `KEY: "" # held`: the guard drops an empty value from its allowlist and the
                                 dispatcher answers 501 "no image configured" without calling docker, so a held kind never
                                 starts even if an older image of it is on this host.'''),
    ('''JOB_LINE_RE = re.compile(''', '''HELD_VALUE = '""'   # goodqa#16136: a held job line's value; an empty string, never an image ref
JOB_LINE_RE = re.compile('''),
    ('''        for k in held:
            m = JOB_LINE_RE.match(lines[res[k]])
            lines[res[k]] = '      %s: %s # held' % (k, m.group(2))''',
     '''        for k in held:
            lines[res[k]] = '      %s: %s # held' % (k, HELD_VALUE)'''),
    ('''    want = dict(before_jobs, **new_jobs)
''', '''    want = dict(before_jobs, **new_jobs, **{k: HELD_VALUE for k in held})
'''),
])

patch('rw-ship.sh', [
    ('''SELFHOST_JOB_HOLD (default intelligence-worker,transcribe; "none" = no hold) keeps a
  # kind on its current pin (intelligence-worker), or holds transcription at the guard (GUARD_HELD_ENV) while MP4 runs.''',
     '''SELFHOST_JOB_HOLD (default intelligence-worker,transcribe; "none" = no hold) blocks a
  # kind (its line becomes "" # held, so the dispatcher refuses it with 501 and the guard has no image for it), or holds
  # transcription at the guard (GUARD_HELD_ENV) while MP4 runs.'''),
    ('''so the whole transcode image stays on its current pin"''',
     '''so the whole transcode image is held (its line emptied; the dispatcher refuses every transcode launch)"'''),
])

patch('README.md', [
    ('''  A held image keeps its current line, marked `# held`.''',
     '''  A held kind's line becomes `KEY: "" # held`: the dispatcher answers 501 "no image configured" (docker is never called)
  and the guard has no image for it, so it never starts, even if an older image of it is on the host.'''),
])
print('patched hold')
