// goodqa#16148 spec v4 AC-3, AC-11 and NEG-16: the checked-in self-host files match what the AC-11 host apply leaves
// on the VM, so the CC8.1 selfhost-topology-drift gate (infra/selfhost-plan.mjs) is green after the apply and red
// without the checked-in change. Also the R4 cross-check: the host-apply wrapper takes the same deploy lock as rw-ship.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { planSelfhostDrift, loadDesired } from './selfhost-plan.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const APP = join(ROOT, 'infra/selfhost/app')
const desired = loadDesired(ROOT)
const KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY'

/** Run a function of apply-job-secrets-host.py on text, through python (the code the VM runs). */
function hostApply(fn, text) {
  const code = [
    'import importlib.util, sys',
    `s = importlib.util.spec_from_file_location("a", ${JSON.stringify(join(APP, 'apply-job-secrets-host.py'))})`,
    'm = importlib.util.module_from_spec(s); s.loader.exec_module(m)',
    `sys.stdout.write(getattr(m, ${JSON.stringify(fn)})(sys.stdin.read()) if ${JSON.stringify(fn)} != "consts" else "\\n".join([m.GROUP_LINE, m.VOL_LINE, m.ENV_LINE]))`,
  ].join('\n')
  const r = spawnSync('python3', ['-I', '-c', code], { input: text, encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  return r.stdout
}

function block(compose, service) {
  const lines = compose.split('\n')
  const start = lines.indexOf(`  ${service}:`)
  assert.ok(start >= 0, service)
  let end = start + 1
  while (end < lines.length && (lines[end] === '' || lines[end].startsWith('    '))) end += 1
  return lines.slice(start, end)
}

test('AC-3: only job-dispatcher has the read-only secrets mount and group_add 64910', () => {
  const [groupLine, volLine] = hostApply('consts', '').split('\n')
  const disp = block(desired.compose, 'job-dispatcher')
  assert.ok(disp.includes(groupLine), 'job-dispatcher group_add')
  assert.ok(disp.includes(volLine), 'job-dispatcher mount')
  assert.match(volLine, /"\/etc\/goodqa\/job-secrets:\/run\/goodqa-secrets:ro"/)
  const elsewhere = desired.compose.split('\n').filter((l) => (l.includes('job-secrets') || l.includes('64910')) && !disp.includes(l))
  assert.deepEqual(elsewhere, [], 'no other service mounts the secrets or gets the group')
  assert.ok(disp.includes('    read_only: true') && disp.includes('    tmpfs: ["/tmp"]'))
})

test('AC-11: the host apply on the pre-change compose yields exactly the checked-in compose, and restore undoes it', () => {
  const before = hostApply('compose_restore', desired.compose)
  assert.notEqual(before, desired.compose)
  assert.equal(hostApply('compose_apply', before), desired.compose)
  assert.equal(hostApply('compose_apply', desired.compose), desired.compose, 'idempotent')
})

test('AC-11: env-keys.json names the dispatcher JOB_ENVFILE key, and only for the dispatcher', () => {
  assert.ok(desired.env.dispatcher.includes(KEY))
  assert.ok(!desired.env.api.includes(KEY) && !desired.env.web.includes(KEY))
  const envLine = hostApply('consts', '').split('\n')[2]
  assert.equal(envLine.split('=')[0], KEY)
})

test('NEG-16: an applied VM is no drift against the checked-in files', () => {
  assert.deepEqual(planSelfhostDrift(desired, { compose: desired.compose, env: desired.env }), [])
})

test('NEG-16: the gate goes red if env-keys.json lacks the key (against an applied VM)', () => {
  const stale = { ...desired, env: { ...desired.env, dispatcher: desired.env.dispatcher.filter((k) => k !== KEY) } }
  const p = planSelfhostDrift(stale, { compose: desired.compose, env: desired.env })
  assert.equal(p.length, 1, p.join('\n'))
  assert.match(p[0], new RegExp(`dispatcher\\.env has key\\(s\\) not checked in: ${KEY}`))
})

test('NEG-16: the gate goes red if the checked-in compose lacks the mount (against an applied VM)', () => {
  const stale = { ...desired, compose: hostApply('compose_restore', desired.compose) }
  const p = planSelfhostDrift(stale, { compose: desired.compose, env: desired.env })
  assert.equal(p.length, 1, p.join('\n'))
  // The gate compares line by line, so the two inserted lines also shift every later line.
  assert.match(p[0], /compose\.yaml differs on \d+ line/)
  assert.ok(p[0].includes('group_add: [\\"64910\\"] # goodqa#16148 AC-11'), p[0])
})

test('R4: the host-apply wrapper takes the deploy lock rw-ship takes (main copy of rw-ship.sh)', () => {
  const ship = readFileSync(join(ROOT, 'infra/release-harness/rw-ship.sh'), 'utf8')
  const m = /^LOCKF=\$S\/(\S+?);/m.exec(ship)
  assert.ok(m, 'rw-ship.sh LOCKF line')
  const wrapper = readFileSync(join(APP, 'apply-job-secrets.sh'), 'utf8')
  const w = /^LOCK_REL=(\S+)$/m.exec(wrapper)
  assert.ok(w, 'wrapper LOCK_REL line')
  assert.equal(w[1], m[1])
  assert.match(ship, /INFL=\$\{LOCKF%\.lock\}\.inflight\.json/)
  assert.match(wrapper, /inflight\.json/)
})
