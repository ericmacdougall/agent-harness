"""File the t2-dev disk follow-up ticket and add item 16 to the fix round umbrella goodqa#15565. Backoff on rate_limited."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']


def bo(name, args):
    w = 60
    for _ in range(7):
        r = gq.call(name, args)
        e = r.get('error') if isinstance(r, dict) else None
        if not e or e.get('code') != 'rate_limited':
            return r
        time.sleep(w); w *= 2
    return r


desc = """t2-dev disk follow-up (2026-11-09 night). On 2026-11-09 t2-dev fell to 16 GB free (98%) during lesson voicing (pause floor 10 GB). Freed only derivable things: docker build cache 10.05 GB, ~/.gradle/caches 6.9 GB, node_modules of old bt-release-smoke trees; now 33 GB free (94%). Stopped there by main's ruling; the rest below needs each owner's confirmation. Scheduled after the user's interviews (Thursday). Nothing here was deleted.

TOP CONSUMERS at 16 GB free (GB): ~/wt 115 (linked worktrees, mostly shared objects); ~/repos 104; ~/repos/Android-security 24; ~/.local 18 (incl. fleet-ops/branch-pr-janitor/mirrors 9.2); ~/repos/hawk-cmp-t2 16 (standalone clones, head not on a remote, backup would be about 3 GB each); ~/repos/harness 15 (live deploy dir, protected); ~/sites-seo 12; ~/wt/compl-fix 12 (owner ae5111e, live); ~/rt-15477f 11.6, ~/rt-15477e 8.5, ~/rt-15477 6.9, ~/rt-15477d 4.6 (linked worktrees of bugtracker, clean, every HEAD on origin, red-team scratch of returned owners); ~/repos/bugtracker 10.7; ~/pp-josh-batch 8.1 (non-git proof trees, backup 6.6 GB); ~/opt 7.8; ~/repos/bugtracker-agent-runs-staging 7.4 (running service); ~/.gradle 7.5 (now about 0.6); ~/lessons2-t2c 6.1 (lessons work); ~/pp-hwq-prep-s654 5.2 (one uncommitted change in stg-aaf7248c); ~/rt561 4.5 (standalone clone, HEAD not on a remote, backup 1.7 GB).

DOCKER (docker system df): unattached local volumes 98, 31.5 GB, ALL anonymous (hash names, no compose project label, created 2026-11-06 to 11-08), so an owner cannot be derived from labels. Largest: 4.74, 4.63, 3.77, 3.62, 1.54, 1.51, 1.47, 1.31, 1.17, 1.15 GB, then 648 MB, six of about 220-240 MB, and about 70 volumes of 57-74 MB (fresh postgres data dirs). Full list with sizes: t2-dev ~/gq-branch-clean/vols.tsv. They hold database data of removed test stacks; removing them destroys it. Each owner confirms their own (match against the data you started a container for on those dates) or main decides a blanket removal with a sourced ruling. Running containers (14) were not touched.
Unused tagged images: 11.8 GB reclaimable. Question for main: may `docker image prune -a` run (re-pull or rebuild cost; could slow the lesson voicing image if it is unused at the moment)?
Janitor mirrors: ~/.local/state/fleet-ops/branch-pr-janitor/mirrors, 9.2 GB, a live service's rebuildable bare mirrors; its owner prunes or sets a size bound.

WORKTREES: the guard refused `git worktree remove` over ssh for clean pushed linked worktrees (~/wt-rev-a3be on t2-dev, ~/wt-0257-docs on dev2, ~/rt-15477*). Exact refusal: "git worktree remove is allowed only for one verified clean, published, registered linked worktree top; this target or command shape is not verified." Tracked as fix-round item 16 (goodqa#15565). Each owner removes their own once item 16 lands or runs the literal command locally on the host.
Held: ~/repos/bt-release-smoke-b33ada8231d9 until the combined ship is live."""
r = bo('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='t2-dev disk follow-up: volumes, images, janitor mirrors, leftover worktrees (owners confirm)', description=desc, type='task', priority='medium', labels=['harness', 'cleanup-2026-11n'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'diskfollow|20261109'))))
i = r.get('issue')
print('disk ticket', i and i['number'], '' if i else str(r)[:200])
g = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=15565))['issue']
item = ('Item 16: no agent has a guard-accepted way to remove a clean, pushed linked worktree on a remote host (command_guard refuses `git worktree remove` over ssh: "only for one verified clean, published, registered linked worktree top; this target or command shape is not verified"), so leftover worktrees pile up on t2-dev (see goodqa#%s). The fix must keep the safety property: verify clean and pushed on the remote, then remove the literal path. Source: coordinator message, session baab765b.' % (i and i['number']))
bo('comment_on_issue', dict(issueId=g['id'], body='Item added: \n\n- [ ] ' + item, operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'item16|15565'))))
r2 = bo('update_issue', dict(issueId=g['id'], patch={'description': (g.get('description') or '') + '\n- [ ] ' + item}))
print('item 16 added', 'issue' in r2)
