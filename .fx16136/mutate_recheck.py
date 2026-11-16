"""goodqa#16136: broken variants of the transcode id-recheck skip. python3 mutate_recheck.py rw-ship.sh always|never"""
import sys
p, m = sys.argv[1:]; t = open(p).read()
old = "if job['name'] == 'transcode' and '--job-hold JOB_IMAGE_TRANSCODE' in holds: continue"
assert t.count(old) == 1, t.count(old)
new = "if job['name'] == 'transcode': continue" if m == 'always' else "if False: continue"
open(p, 'w').write(t.replace(old, new)); print('mutant', m)
