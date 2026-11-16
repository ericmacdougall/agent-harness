"""goodqa#16136 E4: "" is a held value only with the # held marker and only on a holdable key. python3 patch_e4.py DIR"""
import os, sys
D = sys.argv[1]
p = os.path.join(D, 'selfhost-ctl.py'); t = open(p).read()
pairs = [
    ("HELD_VALUE = '\"\"'", "HOLDABLE_KEYS = ('JOB_IMAGE_INTELLIGENCE_WORKER', 'JOB_IMAGE_TRANSCODE')   # the only kinds a release may hold\nHELD_VALUE = '\"\"'"),
    ("""            if k in res: raise Refused('compose.yaml: %s appears more than once' % k)
""", """            if k in res: raise Refused('compose.yaml: %s appears more than once' % k)
            v, marked = m.group(2), bool(m.group(3))
            if (marked or v in ('""', "''")) and k not in HOLDABLE_KEYS:
                raise Refused('compose.yaml line %d: %s cannot be held (only %s)' % (i + 1, k, ', '.join(HOLDABLE_KEYS)))
            if marked and v != HELD_VALUE:
                raise Refused('compose.yaml line %d: %s is marked # held but its value is not ""' % (i + 1, k))
            if v in ('""', "''") and not marked:
                raise Refused('compose.yaml line %d: %s is empty without the # held marker' % (i + 1, k))
"""),
    ("""        if k not in JOB_KEYS: raise Refused('--job-hold %s is not a job image key' % name)
""", """        if k not in JOB_KEYS: raise Refused('--job-hold %s is not a job image key' % name)
        if k not in HOLDABLE_KEYS: raise Refused('--job-hold %s: that kind cannot be held (only %s)' % (k, ', '.join(HOLDABLE_KEYS)))
"""),
]
for o, n in pairs:
    assert t.count(o) == 1, o[:80]; t = t.replace(o, n)
open(p, 'w').write(t); print('patched e4')
