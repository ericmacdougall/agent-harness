import subprocess, json
out = subprocess.run(['python3', '-I', '/Users/eric/.claude/hooks/ah.py', 'owners'], capture_output=True, text=True).stdout
d = json.loads(out)
live = [o for o in d['owners'] if o.get('state') in ('live', 'SILENT-HIGH', 'DROPPED') and not o.get('disposition')]
live += [o for o in d['owners'] if o.get('state') == 'live' and o not in live]
print('live-ish owners:', len(live))
for o in live[:20]:
    print(o['agent_id'], o['state'], o.get('type'), '|', (o.get('task') or '')[:150].replace('\n', ' '))
