import re
p = '../spec-15561-v4.md'
s = open(p).read()
failed = []


def rep(old, new, count=1):
    global s
    if s.count(old) != count:
        failed.append((old[:70], s.count(old)))
        return
    s = s.replace(old, new)


# C1: entitlements and members are delegated page-support reads
rep("`crm` = the token-reachable routes under `/v1/orgs/:p/crm/**` that the CRM list, saved-view (segments) and record-read pages call;",
    "`crm` = the token-reachable routes under `/v1/orgs/:p/crm/**` that the CRM list, saved-view (segments) and record-read pages call, plus the two non-CRM page-support reads `GET /v1/orgs/:p/entitlements` and `GET /v1/orgs/:p/members` (ability `read` only; a token with `read` reaches both by bearer, the owner's RBAC applies);")
# C2
rep("(main accepted the check; deviation open)", "(decided by main, w212679a04a0)")
rep("Q9 accepted: the S0 check below.", "Q9: decided by main, admit operator (see the Q9 finding).")
# C3
rep("on the listed zero-write observation routes (ZERO_WRITE_READ_ROUTES) follows", "on the listed zero-write observation routes (the existing bearer-path set `ZERO_WRITE_READ_ROUTES` in `modules/user-tokens/zero-write-reads.ts`) follows")
rep("a refused request on a zero-write observation route on the listed", "a refused request on the listed")
# C4
m = re.search(r"- S1b \(API, CRM delegated door\):[^\n]*", s)
if m:
    s = s.replace(m.group(0), m.group(0) + ' NEG-39 (operator-bound session gets no host waivers) is also built here.', 1)
else:
    failed.append(('S1b line', 0))
m = re.search(r"- S4 \(web, honest refusal\):[^\n]*", s)
if m:
    s = s.replace(m.group(0), m.group(0) + ' AC-17 (live proof of the refusal copy) belongs here.', 1)
else:
    failed.append(('S4 line', 0))
m = re.search(r"- S1c \(API, Messages entries\):[^\n]*", s)
if m:
    s = s.replace(m.group(0), m.group(0) + ' AC-18 (live proof of Messages) belongs here.', 1)
else:
    failed.append(('S1c line', 0))
# C5
rep("(see the Q7 line below) (below)", "(see the Q7 line below)", count=s.count("(see the Q7 line below) (below)"))
# C6
rep("the production live proof reuses an existing token the owner supplies.", "the production live proof reuses an existing token the owner supplies as a token file on the mini (never pasted into chat, a ticket or a log).")
open(p, 'w').write(s)
print('failed:', failed)
