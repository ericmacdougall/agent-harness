"""Agent-comment pattern list for the evidence-based closes (goodqa#14977). A ticket's recent comments must ALL match one of these
(anchored at the start of the body, after stripping whitespace and an optional HTML comment line); otherwise the ticket stays open."""
import re, json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
PATTERNS = [
    ('ops-watch alert digest', r'^ops-watch: \d+ alert transition'),
    ('bug-triage intake bot', r'^(<!-- bug-triage -->\s*)?\[bug-triage intake\]'),
    ('merge-status note (not-yet-deployed)', r'^\*\*Merged \(not yet deployed or live\)\*\*'),
    ('ahd owner-dropped notice', r'^ahd: owner DROPPED'),
    ('spec-attached note', r'^\*\*Spec attached\*\*'),
    ('click-test result note', r'^\*\*Click-test (PASS|FAIL)\*\*'),
    ('dead-man alert', r'^(DEADMAN:|\[deadman\]|pp-prod-smoke dead-man)'),
    ('dev-decom status note', r'^Status \d{4}-\d{2}-\d{2} [\d:]+Z \(dev-decom'),
    ('PR/branch/commit checkpoint', r'^(PR #\d+|PR-\w+ status|Owner checkpoint|Fixer checkpoint|Publishing: branch|Branch fix/|branch fix/|Commit [0-9a-f]+|Ship SHA|Main merging PR|Fix-forward pushed|Owner \d+\. The R|R\d+-\d+ fix:|Review round|Q\d+ (plan|S\d+) checkpoint|S[A-Z0-9]+ checkpoint|QAC-A:|fleet/goodqa units)'),
    ('deploy record note', r'^Deployed to prod:'),
    ('main/coordinator decision note', r'^Decision \(made by main/coordinator'),
    ('red-team round note', r'^Red-team (round|delta)'),
    ('lane stuck auto-decider notice', r'^Lane \S+ is stuck: the auto-decider'),
    ('cleanup stamp (this program)', r'^cleanup-2026-11'),
    ('restore note (this program)', r'^goodqa#\d+ restore'),
    ('lifecycle bot', r'^\*\*Ticket lifecycle:'),
    ('status report block', r'^\*\*Status \(|^\*\*Status\b|^Status \('),
    ('bot html-marker comment', r'^<!-- (inventory-bot|bugfix-fleet|gorunner-status|bucket\d-bugfix|stagec-land|bug-triage)'),
    ('inventory bot', r'^\[inventory-bot\]'),
    ('ahd notice', r'^ahd:'),
    ('spec evidence record', r'^\*\*Evidence\*\* for AC-'),
    ('autopilot note', r'^\*\*goodqa autopilot\*\*'),
    ('owner checkpoint or pickup post', r'^(Checkpoint|CHECKPOINT|Test-hygiene checkpoint|Fable checkpoint|Pickup:|Commits on branch|Branch [\w/.-]+ pushed|PR-[A-C] |Live on |Fix in progress on branch|[A-Z]\d+ committed|Delivering |Round \d+ review|Also red on main|dev-decom \(|Orphan-ticket sweep|Knowledge-net PR|\*\*Prod move runbook|Merged to main \(|Test-hygiene follow-ups|Checkpoint \d)'),
    ('routing note', r'^Routing \((coordinator|GoodQA Desk)'),
]
CP = [(n, re.compile(p)) for n, p in PATTERNS]


def classify(body):
    b = body.strip()
    for n, p in CP:
        if p.search(b):
            return n
    return None


if __name__ == '__main__':
    out = json.load(open(T + 'recent_bodies7.json'))
    ok, bad = [], collections.Counter()
    for tid, cs in out.items():
        miss = [c for c in cs if classify(c['body']) is None]
        if miss:
            for c in miss:
                bad[c['body'][:70].replace('\n', ' ')] += 1
        else:
            ok.append(tid)
    print('tickets whose every recent comment matches:', len(ok), 'of', len(out))
    print('unmatched bodies (those tickets stay open):')
    for k, v in bad.most_common(15):
        print(' ', v, repr(k))
    json.dump(ok, open(T + 'pattern_ok7.json', 'w'))
