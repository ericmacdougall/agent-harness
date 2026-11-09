import sys, uuid
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
import gq
b = """MEASURED open tickets across all projects, 2026-11-09 (owner ab8a7d1b, fresh dump after the folds): 990 (was 6,552 on the morning of 11-08, 3,889 before the area-umbrella folds). By project: goodqa 214, work-tracker-automatic 204, parent-proof 175, parentproof-app 83, poopyduck-app 52, hawkeye-app 40, security-project 38, p51-ops 37, harness 28, reachscout-ai 24, the rest under 20. The under-300 target is NOT met.
Remainder by class: 179 epics and umbrellas (work surface, includes ~110 area umbrellas created in this program), 675 still foldable under the ruling and not yet folded (work-tracker-automatic 196, parent-proof 149, goodqa 91, parentproof-app 73, poopyduck-app 45, hawkeye-app 31, harness 27: skipped earlier by the comment guard or never folded), 65 other organisations' tickets, 47 security findings (security-project 38), 24 with a customer or teammate reporter.
Exact floor even if every foldable ticket folds: 179 + 65 + 47 + 24 = 315, plus about 40 new area umbrellas for those projects, so about 355. Under 300 needs a ruling on merging the umbrellas and epics themselves."""
print(str(gq.call('comment_on_issue', {'issueId': '861b09c7-cea1-4d8c-96f9-46242f652dbe', 'body': b, 'operationId': str(uuid.uuid4())}))[:30])
