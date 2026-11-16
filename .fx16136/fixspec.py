import re, sys
p = sys.argv[1]; t = open(p).read()
F = 'file:config/goodqa-release/bin/'


def collapse(t, head):
    lines = t.split('\n'); out = []; i = 0
    while i < len(lines):
        l = lines[i]
        if l.startswith('- ' + head + ':') or l.startswith('- ' + head + ' '):
            buf = [l.rstrip()]; i += 1
            while i < len(lines) and not lines[i].startswith('- ') and not lines[i].startswith('#'):
                s = lines[i].strip()
                if s: buf.append(re.sub(r'^(\d+\.|-)\s*', '', s))
                i += 1
            out.append(' '.join(buf)); out.append('')
            continue
        out.append(l); i += 1
    return '\n'.join(out)


for h in ('AC-4', 'AC-10', 'NEG-2'):
    t = collapse(t, h)
t = re.sub(r'\n\n\n+', '\n\n', t)
R = [
    ('`goodqa-<job>@sha256:<64 hex image id on the host>`', '`goodqa-JOB@sha256:` followed by the 64-hex image id on the host'),
    ('goodqa-<job>@sha256:<id>', 'goodqa-JOB@sha256:ID'),
    ('`goodqa-<job>:<sha12>-<stamp>`', '`goodqa-JOB:SHA12-STAMP`'),
    ('`repo@sha256:<id>`', '`repo@sha256:ID`'),
    ('systemctl --user stop <unit>', 'systemctl --user stop UNIT'),
    ('Source: inferred: from production containerd store -- the only digest form a loaded, never-pushed image has',
     'Source: inferred: from ticket:GoodQA goodqa#16136 ; file:apps/job-dispatcher/src/config.ts:106@68b84c55a42 -- AUD-031 needs a digest ref and a loaded never-pushed image only has its local image id as digest'),
    ('Source: inferred: from selfhost-ctl.py restore contract -- the job pins now change per release so they must roll back',
     'Source: inferred: from ' + F + 'selfhost-ctl.py:304@1786659bb -- the job pins now change per release so they must roll back with the compose backup'),
    ('Source: inferred: from existing build-failure contract for web/job-dispatcher',
     'Source: inferred: from ' + F + 'rw-ship.sh:697@1786659bb -- same build-failure contract as web and job-dispatcher'),
    ('Source: inferred: from existing image-id-mismatch contract',
     'Source: inferred: from ' + F + 'rw-ship.sh:718@1786659bb -- same image-id mismatch contract as the three app images'),
    ('Source: inferred: from the free-disk gate, which assumed three images',
     'Source: inferred: from ' + F + 'rw-ship.sh:672@1786659bb -- the free-disk gate assumed three images'),
    ('Source: inferred: from release checklist rollback-not-blocked',
     'Source: inferred: from ' + F + 'selfhost-ctl.py:304@1786659bb -- release checklist item rollback-not-blocked'),
    ("Source: inferred: from AUD-031 and the guard allowlist -- the pin is the guard's trust root",
     'Source: inferred: from file:apps/job-dispatcher/src/create-guard-main.ts:62@68b84c55a42 -- the JOB_IMAGE pins are the guard allowlist, its trust root'),
    ('Cap and kill: builds run', 'Cap and kill: real image builds (AC-4 proof) run'),
    ('; pytest bounded by `timeout 600`', '; pytest runs capped by `timeout 600`, terminated on expiry'),
    ('- transport-proof: covered by', '- transport-proof: NEG-8 covers it; also'),
    ('- staging-exists: covered in Risks.', '- staging-exists: NEG-9 covers it.'),
    ('\n## Resource budget',
     '- NEG-8 (AC-5): transport-proof. A job reported started whose run never reaches a terminal success through the real product API counts as failed; the dispatcher status line and the product API body are kept verbatim as evidence. Source: ticket:GoodQA goodqa#16136\n'
     '- NEG-9 (AC-9): staging-exists. If the goodqa#16130 staging gate is not ready, the ship is labelled TARGET_MISMATCH on the ticket and in the deploy note, never presented as staged. Source: ticket:GoodQA goodqa#16136\n\n## Resource budget'),
]
for a, b in R:
    if a not in t: print('MISS', a[:60])
    t = t.replace(a, b)
open(p, 'w').write(t)
