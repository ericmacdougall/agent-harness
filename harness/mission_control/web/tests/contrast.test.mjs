// Text contrast of the page's own tokens, both themes (goodqa#15920 AC-10): 4.5:1 for every text role on every surface.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../mission.css', import.meta.url), 'utf8');
const block = re => Object.fromEntries([...re.exec(css)[1].matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/gi)].map(m => [m[1], m[2]]));
const dark = block(/:root \{([^}]*)\}/);
const light = { ...dark, ...block(/:root\[data-theme="light"\] \{([^}]*)\}/) };
const lum = hex => { const c = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255).map(v => (v <= .03928 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4)); return .2126 * c[0] + .7152 * c[1] + .0722 * c[2]; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + .05) / (y + .05); };

for (const [name, t] of [['dark', dark], ['light', light]]) {
  test(`${name} theme: text roles meet 4.5:1 on every surface`, () => {
    for (const surface of ['bg', 'panel', 'panel-2'])
      for (const role of ['text', 'muted', 'dim', 'accent', 'ok', 'warn', 'bad', 'info'])
        assert.ok(ratio(t[role], t[surface]) >= 4.5, `${role} on ${surface}: ${ratio(t[role], t[surface]).toFixed(2)}`);
  });
  test(`${name} theme: filled controls keep readable ink`, () => {
    assert.ok(ratio(t['accent-ink'], t.accent) >= 4.5, 'accent ink on accent');
    assert.ok(ratio(t['accent-ink'], t.ok) >= 4.5, 'ink on ok');
    assert.ok(ratio(t['accent-ink'], t.bad) >= 4.5, 'ink on bad');
    assert.ok(ratio(t.focus, t.bg) >= 3, 'focus ring vs page');
    for (const surface of ['bg', 'panel', 'panel-2']) assert.ok(ratio(t['line-strong'], t[surface]) >= 3, `control border on ${surface}: ${ratio(t['line-strong'], t[surface]).toFixed(2)}`);
  });
}
test('no text is set below 12px', () => {
  const small = [...css.matchAll(/font(?:-size)?:\s*(\d+(?:\.\d+)?)px/g)].filter(m => Number(m[1]) < 12);
  assert.deepEqual(small.map(m => m[0]), []);
});

test('the system-light path (no data-theme) gets the light tokens through theme.js, and forced-colors has its own rules', () => {
  const theme = readFileSync(new URL('../js/theme.js', import.meta.url), 'utf8');
  assert.match(theme, /prefers-color-scheme: light/);
  assert.match(css, /@media \(forced-colors: active\)/);
  assert.match(css, /@media \(max-width: 760px\)/);
});
