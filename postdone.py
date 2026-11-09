import sys, uuid
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
import gq
b = "t2-course freeze window DONE (owner ab8a7d1b). main is 72af7adf; PR https://github.com/ericmacdougall/t2-course/pull/49 (head 7d08b79a28c2). You may push again. Re-clone every existing clone, do not pull (known: t2-dev sites-seo/t2-course-main, dev2 clones, Mac sites/src/t2-course and sites-seo/repos/t2-course). GitHub's reported size was 5,755,192 KB before and still reads 5,755,192 KB right after the push: the 48 hidden refs/pull/* still reference the old commits, so only a GitHub Support purge shrinks the server figure. A fresh clone is a 28 MiB pack."
print(str(gq.call('comment_on_issue', {'issueId': '861b09c7-cea1-4d8c-96f9-46242f652dbe', 'body': b, 'operationId': str(uuid.uuid4())}))[:30])
