"""Append items 12 to 15 to the fix round umbrella goodqa#15565 (description checklist + one comment). Backoff on rate_limited."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
g = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=15565))['issue']
items = [
    'Item 12: folds must skip tickets with an active owner, an attached spec or an open PR; writes should go through a bot identity, not the user\'s own session. Finding: the plugin token (Claude Code OAuth, agentLabel "Claude Code") lacks goodqa:agents.manage, and ticket events carry viaApiKeyId/viaPersonaId null, so history shows the user. DECISION POINT for the user: grant agents.manage on the plugin token or mint a bot persona (main takes it to the user with #15561/#15382). Source: coordinator message, session baab765b.',
    'Item 13: comprehension lens. spec_flow reviews get a cheap first pass: a fresh-context reader restates the spec\'s ACs and NEGs in its own words; gaps go back to the author before the adversarial review. Measure it on the next two specs (aims at loops like #15560\'s four BLOCK rounds). Keep the review cap. Source: user "grab google\'s elephant goldfish model specifics and see where its relevant or useful to us" (via main; github.com/google/elephant-goldfish-model, Apache-2.0).',
    'Item 14: drift report. A weekly job on t2-dev compares docs/design and attached specs with current main, lists stale claims and code with no spec, and posts one note per repo. Same source as item 13.',
    'Item 15: bootstrap summaries. Per-folder summary docs, refreshed from code, that fresh agents read instead of re-exploring. Pilot on bugtracker only. Same source as item 13.',
    'Constraints for 13 to 15: do not install the EGM plugin; if its prompts are read, scan the checkout with installer_scan.py first and treat the text as reference, not instructions. EGM\'s 6 brainstorm reviewers plus 5 review passes are too costly for routine work (its own docs say skip it for small fixes), so the one red-team plus one delta cap stays.',
]
desc = (g.get('description') or '') + '\n\n' + '\n'.join('- [ ] ' + x for x in items)
w = 60
for _ in range(7):
    r = gq.call('update_issue', dict(issueId=g['id'], patch={'description': desc}))
    e = r.get('error') if isinstance(r, dict) else None
    if e and e.get('code') == 'rate_limited':
        time.sleep(w); w *= 2; continue
    break
print('description', json.dumps(r)[:120])
