import sys, json, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
desc = """Found while finishing goodqa#14977 (repo hygiene). command_guard refuses `rm -rf` of an owner's own finished scratch tree under the session work dir, because the work dir is classed as a protected harness directory.

Case: an owner agent (ab8a7d1b) cloned t2-course shallow into ~/.agent-harness/work/<session>/agent-ab8a7d1bf54ed3c9a/fresh/t2c, ran a proof (npm ci, media:pull, build, verify: passed, results recorded in the WAL), and cannot delete the resulting 12 GB tree. The Mac data volume sits at 98% (9.7 GB free). The guard's suggested path (Dropbox backup plus `command_guard.py approve-delete`) is a person-only step and is wrong for a disposable clone that is already on GitHub.

Proposed rule: allow removal of a directory under ~/.agent-harness/work/<session>/<agent-id>/ when ALL hold: (1) the path was created by that agent (recorded when the agent wrote its first file there, or a marker file the agent writes, such as .owner-scratch); (2) it contains no WAL, log, transcript or receipt file by name or extension; (3) if it is a git checkout, `git status` is clean and every ref is on a remote (the guard can run those checks itself); (4) no live process has it as cwd or argument. Keep refusing everything else, including `mv` and python-based deletes. Log every approval.

Acceptance: an owner with a clean, fully pushed checkout it created can delete it with plain `rm -rf <literal path>`; the same command on a dirty or unpushed checkout, on a path holding a .jsonl WAL, or on another agent's path is still blocked with the current message.
Verify by: unit tests in the guard for the four conditions (each negative case blocked), then one real removal of the t2c tree above."""
r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='command_guard: allow an owner to remove its own verified-finished scratch tree under the session work dir', description=desc, type='improvement', priority='medium', labels=['guard', 'disk'], operationId=str(uuid.uuid4())))
print(json.dumps({k: (r.get('issue') or r).get(k) for k in ('number', 'id', 'error')}))
