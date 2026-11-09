#!/bin/bash
# READ-ONLY on t2-dev: unattached docker volumes with size, compose project label, name, age. Writes ~/gq-branch-clean/vols.tsv
out=/home/eric/gq-branch-clean/vols.tsv
docker system df -v --format '{{json .Volumes}}' 2>/dev/null > /home/eric/gq-branch-clean/volsdf.json
python3 - <<'EOF'
import json, subprocess, os
d = json.load(open('/home/eric/gq-branch-clean/volsdf.json'))
rows = []
for v in d:
    if int(v.get('Links') or 0) != 0:
        continue
    name = v['Name']
    ins = json.loads(subprocess.run(['docker', 'volume', 'inspect', name], capture_output=True, text=True).stdout)[0]
    lab = ins.get('Labels') or {}
    rows.append((v.get('Size'), name, lab.get('com.docker.compose.project', '-'), lab.get('com.docker.compose.volume', '-'), (ins.get('CreatedAt') or '')[:10]))
def mb(s):
    s = s.upper()
    for u, m in (('GB', 1024), ('MB', 1), ('KB', 1 / 1024), ('B', 1 / 1048576)):
        if s.endswith(u):
            return float(s[:-len(u)]) * m
    return 0
rows.sort(key=lambda r: -mb(r[0]))
with open('/home/eric/gq-branch-clean/vols.tsv', 'w') as f:
    for r in rows:
        f.write('\t'.join(r) + '\n')
print('unattached', len(rows), 'total MB', int(sum(mb(r[0]) for r in rows)))
for r in rows[:40]:
    print('\t'.join(r))
EOF
echo VOLS_DONE
