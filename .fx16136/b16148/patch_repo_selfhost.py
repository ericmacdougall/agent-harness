"""goodqa#16148 AC-3/AC-11: put the host-apply result into the checked-in compose.yaml and env-keys.json. Repo root."""
import importlib.util
import json

spec = importlib.util.spec_from_file_location('a', 'infra/selfhost/app/apply-job-secrets-host.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

p = 'infra/selfhost/app/compose.yaml'
text = open(p).read()
new = m.compose_apply(text)
assert new != text and m.compose_restore(new) == text
open(p, 'w').write(new)

p = 'infra/selfhost/app/env-keys.json'
text = open(p).read()
anchor = '    "JOB_DISPATCH_TOKEN",\n'
assert text.count(anchor) == 1
text = text.replace(anchor, anchor + '    "%s",\n' % m.ENV_KEY)
data = json.loads(text)
assert data['dispatcher'] == sorted(data['dispatcher']), 'dispatcher keys stay sorted'
open(p, 'w').write(text)
print('patched')
