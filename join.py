"""Evidence join for the close-as-done pass. Output: join6.json {key: {...}} for open, unprotected-by-guards tickets.
merged PR  : bugtracker (goodqa + parent-proof tickets live there too?) -> we scan merged PRs of bugtracker and Android-security for '<proj>#N' refs in title/body/branch.
REALLY_TESTED: any WAL event in any session WAL whose note contains 'REALLY_TESTED' and names the ticket ref.
A ticket qualifies only with BOTH."""
import json, re, glob, subprocess, sys
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
W = '/Users/eric/.claude/wals/'
pat = re.compile(r'(?i)\b(goodqa|gq|parent-?proof|pp|work-tracker|wt)\s?#\s?(\d{1,6})\b')
norm = {'goodqa': 'goodqa', 'gq': 'goodqa', 'parentproof': 'parent-proof', 'parent-proof': 'parent-proof', 'pp': 'parent-proof', 'work-tracker': 'work-tracker-automatic', 'wt': 'work-tracker-automatic'}


def key(a, n):
    return norm[a.lower().replace('-', '') if a.lower().replace('-', '') in norm else a.lower()] + '#' + n


merged = {}
for repo in ['bugtracker', 'Android-security', 'agent-harness']:
    out = subprocess.run(['gh', 'pr', 'list', '-R', 'ericmacdougall/' + repo, '--state', 'merged', '--limit', '3000', '--json', 'number,title,body,headRefName,mergedAt'], capture_output=True, text=True).stdout
    for p in json.loads(out or '[]'):
        txt = ' '.join([p['title'] or '', p['headRefName'] or '', (p['body'] or '')[:4000]])
        for a, n in pat.findall(txt):
            merged.setdefault(key(a, n), []).append('%s!%d' % (repo, p['number']))
print('merged-PR-referenced tickets:', len(merged), file=sys.stderr)
rt = {}
for f in glob.glob(W + '*/*.jsonl'):
    for l in open(f, errors='ignore'):
        if 'REALLY_TESTED' not in l:
            continue
        try:
            j = json.loads(l)
        except Exception:
            continue
        note = j.get('note') or ''
        if 'REALLY_TESTED' not in note:
            continue
        for a, n in pat.findall(note + ' ' + (j.get('source') or '')):
            rt.setdefault(key(a, n), []).append(j.get('id'))
print('REALLY_TESTED-referenced tickets:', len(rt), file=sys.stderr)
json.dump({'merged': merged, 'rt': rt}, open(T + 'join6.json', 'w'))
O = json.load(open(T + 'classes5.json'))
both = [o for o in O if (o['proj'].split('/')[1] + '#' + str(o['n'])) in merged and (o['proj'].split('/')[1] + '#' + str(o['n'])) in rt]
monly = [o for o in O if (o['proj'].split('/')[1] + '#' + str(o['n'])) in merged and (o['proj'].split('/')[1] + '#' + str(o['n'])) not in rt]
print('open tickets with merged PR AND REALLY_TESTED:', len(both))
print('open tickets with merged PR only (stay open):', len(monly))
import collections
print(collections.Counter(o['status'] for o in both))
print(collections.Counter('prot' if o['prot'] else 'unprot' for o in both))
