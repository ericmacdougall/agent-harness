import os, re
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spec-16148-pem.md'); t = open(p).read()
for o, n in [('`JOB_ENV_<KIND>__<VAR>_FILE=<path>`', '`JOB_ENV_KIND__VAR_FILE=PATH`'),
             ('`JOB_ENV_<KIND>__<VAR>_FILE`', '`JOB_ENV_KIND__VAR_FILE`'),
             ('JOB_ENV_<KIND>__<VAR> does today', 'JOB_ENV_KIND__VAR does today'),
             ('`job env file for <KIND>__<VAR>: <reason>`', '`job env file for KIND__VAR: REASON`'),
             ('REFUSED <named reason>`', 'REFUSED REASON` (REASON is a fixed phrase)'),
             ('Host: t2-dev (dev2 is retired)', 'Host: vm:t2-dev'),
             ('Checkpoint: each green step committed and pushed on the feature branch; tests are idempotent and use temp dirs under the run\'s SCRATCH',
              'Checkpoint: each green step committed and pushed on the feature branch; tests are idempotent and use temp dirs under the run\'s SCRATCH, so it resumes by rerunning the same test command from the last pushed commit'),
             ('Source: ticket:GoodQA goodqa#16148 (key names only; no agent reads or writes values)', 'Source: ticket:GoodQA goodqa#16148'),
             ('Source: inferred: from ticket:GoodQA goodqa#16148\n- NEG-2', 'Source: inferred: from ticket:GoodQA goodqa#16148 -- a missing or malformed source must never overwrite a good derived file\n- NEG-2'),
             ('Source: inferred: untrusted paths on a shared host', 'Source: inferred: from ticket:GoodQA goodqa#16148 -- untrusted paths on a shared host'),
             ('Source: inferred: non-vacuous test rule', 'Source: inferred: from ticket:GoodQA goodqa#16148 -- the no-value test must not pass vacuously'),
             ('Source: inferred: concurrency', 'Source: inferred: from ticket:GoodQA goodqa#16148 -- concurrent rotation and launch'),
             ('ever partial file', 'ever partial file'),
             ('Source: inferred: from ticket:GoodQA goodqa#16148\n- NEG-7', 'Source: inferred: from ticket:GoodQA goodqa#16148 -- no unheld launch without its key\n- NEG-7'),
             ('Source: inferred: untrusted input', 'Source: inferred: from ticket:GoodQA goodqa#16148 -- the request body is untrusted input')]:
    if o == n: continue
    assert t.count(o) == 1, (t.count(o), o[:60]); t = t.replace(o, n)
open(p, 'w').write(t); print('fixed; remaining <...>:', re.findall(r'<[^>\n]{1,40}>', t))
