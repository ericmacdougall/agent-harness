# Spec: {title}

Ticket: GoodQA {project}#{number}
Author: {author}
Click-test: required
Sign-off: {signoff}
Review-policy: standard

## Outcome

<What the user can do or observe when this ticket is done, in one or two sentences.>

## Scope

- In: <the behavior this work changes>.
- Out: <what this work deliberately leaves alone>.

## Acceptance criteria

- AC-1: <observable result>. Verify by: <test command or live check>. Source: <user:<session>/<uuid> "verbatim words" | ticket:GoodQA <project>#<n> | wal:<path>#<id> | file:<path>:<line>@<sha> | inferred: from <source> -- <why>>

## Negative cases

- NEG-1 (AC-1): <input or situation that must be refused or handled>. Source: <as above>

## Resource budget

Host: <mac or dev2>
Fan-out: agents=<n> jobs=<n> processes=<n> browser_pages=<n> test_workers=<n>
Peak memory: <n GB> (method: <how estimated>)
CPU: <n cores> (method: <how estimated>)
Disk: <n GB> (method: <how estimated>)
Network: <n MB> (method: <how estimated>)
Wall time: <n min>
Cap and kill: <run_capped.py cap, pause behavior, kill mechanism per heavy step>
Checkpoint: <durable output under the work dir, idempotent steps, how it resumes; required over 10 min or 4 GB>

## Risks

- <risk>: <mitigation>.
