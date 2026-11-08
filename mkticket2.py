import sys, json, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
desc = """Related: goodqa#15462 (permanent user token). Found during the goodqa#14977 ticket cleanup.

Problem: agents act through the user's personal GoodQA token, so every comment and ticket an agent writes carries the user's authorId and shows as him. In the 43 tickets I checked, all 723 recent comments have the same authorId (the user's account) even though the bodies are automated or agent status notes (ops-watch digests, bug-triage intake, owner checkpoints). Nothing in the comment record, metadata ({}), or kind says an agent wrote it. This makes the rules "never close a ticket a human commented on" and "human-reported" impossible to apply mechanically, and it will get worse once a permanent token exists.

Proposed fix: stamp each comment and ticket with the token's agent label (token name, agent id, and session) in comment metadata or createdViaLabel, and show it in the UI next to the author ("Eric via agent <label>"). A request made with a token flagged as an agent token must never be recorded as a plain human action. The permanent token the user is minting should carry a required label.

Acceptance: (1) a comment posted with a labelled token returns the label in metadata and in get_issue_comments; (2) the UI shows the label; (3) the bulk cleanup tooling can filter agent versus human comments without body heuristics.
Verify by: post a comment with a labelled token, read it back via get_issue_comments, and see the label in the web UI."""
r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Agent comments posted through a user token are indistinguishable from the user\'s; show the token agent label', description=desc, type='bug', priority='high', labels=['auth', 'tokens'], operationId=str(uuid.uuid4())))
print(json.dumps({k: (r.get('issue') or r).get(k) for k in ('number', 'id', 'error')}))
