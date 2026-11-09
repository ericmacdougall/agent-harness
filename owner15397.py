import subprocess, json
d = json.loads(subprocess.run(['python3', '-I', '/Users/eric/.claude/hooks/ah.py', 'owners'], capture_output=True, text=True).stdout)
for o in d['owners']:
    t = (o.get('task') or '')
    if '15397' in t or 'browser_batch' in t:
        print(o['agent_id'], o.get('state'), o.get('type'), '|', t[:200].replace('\n', ' '))
