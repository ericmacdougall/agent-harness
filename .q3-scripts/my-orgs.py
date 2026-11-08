# Print only the three named orgs from the user's own org list; the token is never printed.
import json, os, time, urllib.request, urllib.error
tok = open(os.path.expanduser('~/.config/goodqa/user-token')).read().strip()
r = None
for i in range(5):
    try:
        r = urllib.request.urlopen(urllib.request.Request('https://goodqa.app/v1/orgs', headers={'Authorization': 'Bearer ' + tok}), timeout=30)
        break
    except urllib.error.HTTPError as e:
        print('status', e.code)
        time.sleep(20)
orgs = json.load(r)['orgs']
print('total', len(orgs))
for x in orgs:
    n = x.get('name') or ''
    if any(k in n.lower() for k in ('eric', 'p51', 'framebright')):
        print(x['id'], n)
