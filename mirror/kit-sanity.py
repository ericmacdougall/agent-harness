import json
import urllib.request
import urllib.error

S = json.load(open('/home/eric/g15561-click/run/summary.json'))
F = S['files']
API = 'http://127.0.0.1:43561'
org = S['orgId']
seg = S['segmentId']


def get(path, tokfile):
    t = open(tokfile).read().strip()
    r = urllib.request.Request(API + path, headers={'authorization': 'Bearer ' + t})
    try:
        with urllib.request.urlopen(r) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


for label in ('crm', 'nocrm'):
    tf = F[label + 'SessionAccessFile']
    for p in (f'/v1/orgs/{org}/crm/contacts', f'/v1/orgs/{org}/crm/segments/{seg}/preview', f'/v1/orgs/{org}/crm/contacts/00000000-0000-4000-8000-000000000000', '/v1/me'):
        st, b = get(p, tf)
        detail = b.get('error', {}).get('code') if st >= 300 else {k: (len(v) if isinstance(v, list) else v) for k, v in b.items() if k in ('contacts', 'count')}
        print(label, st, p.replace(org, 'ORG'), detail)
print(S['orgSlug'], S['ownerEmail'])
