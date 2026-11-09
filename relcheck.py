"""Does anything point at release/* branches? GitHub side (read-only): branch protection, rulesets, environments (with branch policies), workflows referencing release, repo settings, webhooks."""
import subprocess, json, sys
repos = sys.argv[1:] or ['timbar']


def gh(*a):
    r = subprocess.run(['gh', 'api', *a], capture_output=True, text=True)
    try:
        return json.loads(r.stdout) if r.stdout.strip() else None
    except Exception:
        return r.stdout.strip()[:120]


for r in repos:
    base = 'repos/ericmacdougall/' + r
    meta = gh(base)
    print('==', r, 'default', meta.get('default_branch'), 'private', meta.get('private'))
    rs = gh(base + '/rulesets') or []
    print(' rulesets:', [(x.get('id'), x.get('name'), x.get('target')) for x in rs] if isinstance(rs, list) else rs)
    for x in rs if isinstance(rs, list) else []:
        d = gh(base + '/rulesets/%s' % x['id'])
        inc = ((d.get('conditions') or {}).get('ref_name') or {}).get('include')
        print('   ruleset', x['name'], 'ref include:', inc)
    bp = gh(base + '/branches?protected=true&per_page=100') or []
    print(' protected branches:', [b['name'] for b in bp] if isinstance(bp, list) else bp)
    env = gh(base + '/environments') or {}
    envs = env.get('environments', []) if isinstance(env, dict) else []
    print(' environments:', [(e['name'], e.get('deployment_branch_policy')) for e in envs])
    for e in envs:
        pol = gh(base + '/environments/%s/deployment-branch-policies' % e['name'])
        print('   env', e['name'], 'branch policies:', pol if not isinstance(pol, dict) else [p.get('name') for p in pol.get('branch_policies', [])])
    wf = gh(base + '/actions/workflows') or {}
    print(' workflows:', [(w['name'], w['path'], w['state']) for w in wf.get('workflows', [])] if isinstance(wf, dict) else wf)
    for w in (wf.get('workflows', []) if isinstance(wf, dict) else []):
        c = subprocess.run(['gh', 'api', base + '/contents/' + w['path'], '-H', 'Accept: application/vnd.github.raw'], capture_output=True, text=True).stdout
        print('   ', w['path'], 'mentions release:', 'release' in c)
    hooks = gh(base + '/hooks') or []
    print(' webhooks:', [h['config'].get('url', '')[:60] for h in hooks] if isinstance(hooks, list) else hooks)
    pg = gh(base + '/pages')
    print(' github pages:', (pg or {}).get('source') if isinstance(pg, dict) else pg)
