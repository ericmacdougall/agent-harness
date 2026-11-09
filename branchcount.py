import subprocess, json
rows = []
for r in ['timbar', 'poopyduck', 'interview-prep', 'bugtracker', 'bugtracker-harness', 't2-sites', 'transition2-squeeze', 't2-course', 'agent-harness', 'agent-fabric', 'Android-security', 'hawkeye']:
    b = subprocess.run(['gh', 'api', 'repos/ericmacdougall/%s/branches?per_page=100' % r, '--paginate', '-q', '.[].name'], capture_output=True, text=True).stdout.split()
    rows.append((r, len(b)))
print(rows)
allr = json.loads(subprocess.run(['gh', 'repo', 'list', 'ericmacdougall', '--limit', '100', '--json', 'name'], capture_output=True, text=True).stdout)
over = []
for x in allr:
    n = x['name']
    if n == 'optinrouter' or 'yates' in n.lower():
        continue
    b = subprocess.run(['gh', 'api', 'repos/ericmacdougall/%s/branches?per_page=100' % n, '--paginate', '-q', '.[].name'], capture_output=True, text=True).stdout.split()
    if len(b) >= 10:
        over.append((n, len(b)))
print('repos with 10 or more branches (excluding optinrouter and yates):', over)
