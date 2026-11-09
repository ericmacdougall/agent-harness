import subprocess, json
def gh(*a):
    r = subprocess.run(['gh', 'api', *a], capture_output=True, text=True)
    return r.stdout
commits = json.loads(gh('repos/ericmacdougall/t2-course/commits?per_page=15'))
tot = 0
apps = set()
for c in commits:
    cr = json.loads(gh('repos/ericmacdougall/t2-course/commits/%s/check-runs' % c['sha']) or '{}')
    st = json.loads(gh('repos/ericmacdougall/t2-course/commits/%s/status' % c['sha']) or '{}')
    n = cr.get('total_count', 0) + len(st.get('statuses', []))
    tot += n
    for x in cr.get('check_runs', []):
        apps.add(x['app']['slug'])
    for x in st.get('statuses', []):
        apps.add(x['context'])
print('commits checked', len(commits), 'check-runs+statuses total', tot, 'apps/contexts', sorted(apps))
print('repo webhooks:', gh('repos/ericmacdougall/t2-course/hooks').strip()[:80])
print('actions workflows:', json.loads(gh('repos/ericmacdougall/t2-course/actions/workflows')).get('total_count'))
