"""goodqa#16136 G3: a JOB_IMAGE_* line holds a digest-pinned ref (plain or quoted) or `"" # held`, nothing else.
python3 patch_g3.py DIR"""
import os, sys
D = sys.argv[1]
p = os.path.join(D, 'selfhost-ctl.py'); t = open(p).read()
pairs = [
    ("JOB_LINE_RE = re.compile(r'^      (JOB_IMAGE_[A-Z0-9_]+):[ \\t]*(\\S+)(?:[ \\t]+#[ \\t]*(held))?[ \\t]*$')",
     "JOB_LINE_RE = re.compile(r'^      (JOB_IMAGE_[A-Z0-9_]+):[ \\t]*(\\S*)(?:[ \\t]+#[ \\t]*(held))?[ \\t]*$')\n"
     "# goodqa#16136 G3: the only non-held value: a digest-pinned image ref, optionally in matching quotes (no YAML null, no\n"
     "# `~`, no ${...} interpolation, no tag)\n"
     "JOB_PIN_VALUE_RE = re.compile(r'^([\"\\']?)[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}\\1$')"),
    ("""            if v in ('""', "''") and not marked:
                raise Refused('compose.yaml line %d: %s is empty without the # held marker' % (i + 1, k))
""", """            if v in ('""', "''") and not marked:
                raise Refused('compose.yaml line %d: %s is empty without the # held marker' % (i + 1, k))
            if not marked and not JOB_PIN_VALUE_RE.match(v):
                raise Refused('compose.yaml line %d: %s must be a digest-pinned image ref or "" # held (got %s)'
                              % (i + 1, k, re.sub(r'[^A-Za-z0-9@:/._${}~"\\'-]', '?', v)[:40] or 'no value'))
"""),
]
for o, n in pairs:
    assert t.count(o) == 1, o[:80]; t = t.replace(o, n)
open(p, 'w').write(t); print('patched g3')
