import { getState, subscribe, select, highlight } from './store.js';
import { button, el } from './ui.js';
import { layout, describe, tree, cueForChange, cueForEvent, repos as recentRepos, nodeColor, severityColor, escalationColor,
  TYPE_COLORS, EVENT_MAP, LEVELS, UNKNOWN, ageText, isLive } from './org.js';

// The live org graph (goodqa#15950). It replaces the old constellation, which laid out a hand-written
// initiatives.json. One canvas and one animation clock; every node also has an HTML button, and a list view shows the
// same graph as a keyboard tree, so the page works without WebGL and under reduced motion.
const MAX_PULSES = 40;
const MAX_QUEUE = 60;
const SHORT = { coordinator: 'Main', user: 'You' };

function shortModel(model) {
  if (!model || model === UNKNOWN) return UNKNOWN;
  return String(model).replace(/^claude-/, '').replace(/-\d{8}$/, '');
}
function labelText(node) {
  if (node.kind === 'user') return node.inbox == null ? 'You · asks loading…' : `You · ${node.inbox} open ask${node.inbox === 1 ? '' : 's'}`;
  if (node.kind === 'coordinator') return `Main · ${shortModel(node.model)} · ${node.effort}`;
  if (node.kind === 'work') return `${node.ref}${node.done ? ' ✓' : ''}`;
  if (node.kind === 'repo') return `⌘ ${node.label}`;
  const state = node.kind === 'owner' && !isLive(node) ? ' · idle' : '';
  return `${node.label} · ${shortModel(node.model)}${state}`;
}
function ariaText(node, byId) {
  const kind = TYPE_COLORS[node.kind]?.label || node.kind;
  const fields = node.kind === 'repo' ? [] : describe(node, byId).map(([k, v]) => `${k}: ${v}`);
  return `${kind} ${node.kind === 'work' ? node.ref : node.label}. ${fields.join('. ')}`.slice(0, 600);
}
function palette() {
  const css = getComputedStyle(document.documentElement);
  const read = (name, fallback) => (css.getPropertyValue(name).trim() || fallback);
  const types = {};
  for (const [kind, { color }] of Object.entries(TYPE_COLORS)) types[kind] = read(`--org-${kind}`, color);
  return { types, done: read('--org-done', '#7c8580'), edge: read('--org-edge', '#8b967f'), ok: read('--org-ok', '#7edb8a'),
    sev: { warn: read('--org-sev-warn', '#ffa94d'), high: read('--org-sev-high', '#ff6b5b') },
    esc: ['', read('--org-esc-1', '#ffd166'), read('--org-esc-2', '#ff9f43'), read('--org-esc-3', '#ff5c5c')] };
}

export async function mountScene() {
  const stage = document.getElementById('scene-stage');
  const labels = document.getElementById('scene-labels');
  const poster = document.getElementById('scene-poster');
  const mode = document.getElementById('scene-mode');
  const meta = document.getElementById('org-meta');
  const cueLine = document.getElementById('org-cue');
  const announcer = document.getElementById('org-announcer');
  const listWrap = document.getElementById('org-list-wrap');
  const list = document.getElementById('org-list');
  const toggle = document.getElementById('org-view-toggle');
  const nodes = new Map(), labelNodes = new Map();
  let graph = null, byId = new Map(), positions = new Map(), modelSig = '', lastSeq = -1;
  let THREE, renderer, camera, world, scene, colors = palette();
  let available = false, visible = true, frame = 0, lastFrame = -Infinity, elapsed = 0, lastTime = 0;
  let yaw = 0, targetYaw = 0, tilt = 0, targetTilt = 0, dragging = false, pointerStart = null, zoom = 1;
  let stageRect, pulses = [], queue = [], flashTimers = new Map(), lastAnnounce = 0;
  let renderWidth = 0, renderHeight = 0, renderRatio = 0, extent = 3;
  let listMode = false;

  // ---- legend and event table (static text, shown in every mode)
  function legend() {
    const box = document.getElementById('org-legend');
    const group = (title, items) => {
      const wrap = el('div', 'legend-group');
      wrap.append(el('span', 'legend-title', title));
      for (const [label, variable, ring] of items) {
        const item = el('span', 'legend-item');
        const swatch = el('span', `org-swatch${ring ? ' ring' : ''}`); swatch.style.setProperty('--swatch', `var(${variable})`); swatch.setAttribute('aria-hidden', 'true');
        item.append(swatch, document.createTextNode(label));
        wrap.append(item);
      }
      return wrap;
    };
    box.replaceChildren(
      group('Node type', Object.entries(TYPE_COLORS).map(([kind, { label }]) => [label, `--org-${kind}`])),
      group('Severity (halo)', [['warn', '--org-sev-warn', true], ['high', '--org-sev-high', true]]),
      group('Escalation (rings, steps up the model ladder)', [['1 step', '--org-esc-1', true], ['2 steps', '--org-esc-2', true], ['3+ steps', '--org-esc-3', true]]));
    const rows = document.getElementById('org-event-rows');
    rows.replaceChildren(...EVENT_MAP.map(entry => { const tr = el('tr'); tr.append(el('td', '', entry.label), el('td', '', entry.source), el('td', '', entry.cue)); return tr; }));
  }

  // ---- list view: a WAI-ARIA tree with a roving tabindex
  function renderList() {
    const focusedId = document.activeElement?.closest?.('#org-list [role="treeitem"]')?.dataset.nodeId;
    list.replaceChildren();
    const build = (entries, parent, level) => {
      entries.forEach((entry, index) => {
        const li = el('li');
        li.setAttribute('role', 'treeitem');
        li.setAttribute('aria-level', String(level));
        li.setAttribute('aria-setsize', String(entries.length));
        li.setAttribute('aria-posinset', String(index + 1));
        li.dataset.nodeId = entry.node.id;
        li.dataset.kind = entry.node.kind;
        li.tabIndex = -1;
        const row = el('div', 'org-row');
        row.append(el('span', 'org-kind', TYPE_COLORS[entry.node.kind]?.label || entry.node.label || entry.node.kind),
          el('span', 'org-name', entry.node.kind === 'group' ? entry.node.label : entry.node.kind === 'work' ? `${entry.node.ref} · ${entry.node.title}` : labelText(entry.node)));
        if (entry.node.kind !== 'group') {
          const fields = el('div', 'org-fields');
          for (const [k, v] of describe(entry.node, byId)) { const f = el('span'); f.append(document.createTextNode(`${k}: `), el('b', '', v)); fields.append(f); }
          row.append(fields);
        }
        li.append(row);
        if (entry.children.length) {
          li.setAttribute('aria-expanded', 'true');
          const ul = el('ul'); ul.setAttribute('role', 'group');
          build(entry.children, ul, level + 1);
          li.append(ul);
        }
        parent.append(li);
      });
    };
    build(tree(graph), list, 1);
    const items = visibleItems();
    const target = items.find(i => i.dataset.nodeId === focusedId) || items[0];
    if (target) { target.tabIndex = 0; if (focusedId) target.focus(); }
  }
  const visibleItems = () => [...list.querySelectorAll('[role="treeitem"]')].filter(item => !item.parentElement.closest('[role="treeitem"][aria-expanded="false"]'));
  function moveFocus(item) { if (!item) return; list.querySelectorAll('[role="treeitem"]').forEach(i => { i.tabIndex = -1; }); item.tabIndex = 0; item.focus(); }
  list.addEventListener('keydown', event => {
    const item = event.target.closest('[role="treeitem"]');
    if (!item) return;
    const items = visibleItems(), i = items.indexOf(item);
    const expanded = item.getAttribute('aria-expanded');
    let handled = true;
    if (event.key === 'ArrowDown') moveFocus(items[i + 1]);
    else if (event.key === 'ArrowUp') moveFocus(items[i - 1]);
    else if (event.key === 'Home') moveFocus(items[0]);
    else if (event.key === 'End') moveFocus(items[items.length - 1]);
    else if (event.key === 'ArrowRight') { if (expanded === 'false') item.setAttribute('aria-expanded', 'true'); else if (expanded === 'true') moveFocus(item.querySelector('[role="treeitem"]')); }
    else if (event.key === 'ArrowLeft') { if (expanded === 'true') item.setAttribute('aria-expanded', 'false'); else moveFocus(item.parentElement.closest('[role="treeitem"]')); }
    else if (event.key === 'Enter' || event.key === ' ') { if (byId.has(item.dataset.nodeId)) select('org', item.dataset.nodeId); }
    else handled = false;
    if (handled) { event.preventDefault(); event.stopPropagation(); }
  });
  list.addEventListener('click', event => {
    const item = event.target.closest('[role="treeitem"]');
    if (!item) return;
    moveFocus(item);
    if (byId.has(item.dataset.nodeId)) select('org', item.dataset.nodeId);
  });
  list.addEventListener('focusin', event => { const item = event.target.closest('[role="treeitem"]'); if (item) highlight(item.dataset.nodeId); });
  function setListMode(on) {
    listMode = on;
    listWrap.hidden = !on;
    document.body.dataset.orgView = on ? 'list' : 'spatial';
    toggle.setAttribute('aria-pressed', String(on));
    toggle.textContent = on ? 'Show in 3D' : 'Show as list';
    if (on) { stop(); renderList(); } else { size(); start(); }
  }
  toggle.addEventListener('click', () => setListMode(!listMode));

  // ---- labels (every node has a focusable button)
  function rebuildLabels() {
    labels.replaceChildren(); labelNodes.clear();
    const all = [...(graph?.nodes || []), ...repoNodes()];
    for (const node of all) {
      if (!positions.has(node.id)) continue;
      const label = button('node-label', '', event => {
        if (pointerStart?.moved) return;
        event.stopPropagation();
        if (node.kind === 'repo') select('repo', node.repo); else select('org', node.id);
      });
      label.dataset.nodeId = node.id; label.dataset.kind = node.kind;
      if (node.severity && node.severity !== 'info') label.dataset.sev = node.severity;
      label.append(el('span', 'node-full', labelText(node)));
      if (node.escalation) { const esc = el('span', 'org-esc', `⇡${node.escalation}`); esc.setAttribute('aria-hidden', 'true'); label.append(esc); }
      label.title = labelText(node);
      label.setAttribute('aria-label', node.kind === 'repo' ? `Open repository ${node.repo}` : `Open ${ariaText(node, byId)}`);
      label.addEventListener('pointerenter', () => highlight(node.id));
      label.addEventListener('pointerleave', () => highlight(null));
      label.addEventListener('focus', () => highlight(node.id));
      label.addEventListener('blur', () => highlight(null));
      labels.append(label);
      labelNodes.set(node.id, { label, node });
    }
  }
  function repoNodes() { return recentRepos(getState().events).map(repo => ({ id: `repo:${repo}`, kind: 'repo', label: repo.split('/').pop(), repo })); }
  function positionStatic() {
    // Without WebGL the labels sit on a front view of the same pyramid: x across, height down the page.
    const rect = stage.getBoundingClientRect();
    const width = rect.width || 600, height = rect.height || 420;
    const top = LEVELS.user + .3, bottom = Math.min(...[...positions.values()].map(p => p[1]), -1.5) - .3;
    for (const { label, node } of labelNodes.values()) {
      const [x, y, z] = positions.get(node.id);
      const half = label.offsetWidth / 2 + 6, halfHeight = label.offsetHeight / 2 + 6;
      label.style.left = `${Math.max(half, Math.min(width - half, width * (.5 + (x + z * .35) / (extent * 2.4))))}px`;
      label.style.top = `${Math.max(halfHeight, Math.min(height - halfHeight, height * ((top - y) / (top - bottom))))}px`;
    }
    if (window.innerWidth >= 768) cull();
  }
  function fallback(reason = 'STATIC VIEW') {
    available = false;
    if (renderer) renderer.domElement.hidden = true;
    poster.hidden = false;
    mode.textContent = reason;
    positionStatic();
    stop();
  }
  function flash(id) {
    const item = labelNodes.get(id);
    const row = list.querySelector(`[data-node-id="${CSS.escape(id)}"]`);
    for (const [target, cls] of [[item?.label, 'static-flash'], [row, 'org-flash']]) {
      if (!target) continue;
      const key = `${cls}:${id}`;
      clearTimeout(flashTimers.get(key));
      target.classList.add(cls);
      flashTimers.set(key, setTimeout(() => { target.classList.remove(cls); flashTimers.delete(key); }, 900));
    }
  }
  function start() { if (!frame && available && !listMode && !getState().fallback && visible && !document.hidden) { lastTime = 0; frame = requestAnimationFrame(draw); } }
  function stop() { cancelAnimationFrame(frame); frame = 0; lastTime = 0; }
  function size() {
    stageRect = stage.getBoundingClientRect();
    if (!available) { positionStatic(); return; }
    if (!renderer || !camera || stageRect.width < 1 || stageRect.height < 1) return;
    const width = window.innerWidth, height = window.innerHeight;
    const ratio = Math.min(devicePixelRatio || 1, width < 768 ? 1 : 1.5);
    if (ratio !== renderRatio || width !== renderWidth || height !== renderHeight) {
      renderer.setPixelRatio(ratio); renderer.setSize(width, height);
      renderWidth = width; renderHeight = height; renderRatio = ratio;
    }
    camera.setViewOffset(stageRect.width, stageRect.height, -stageRect.left, -stageRect.top, width, height);
    camera.fov = width < 768 ? 40 : 34;
    camera.updateProjectionMatrix();
    start();
  }

  // ---- the 3D scene
  const v3 = p => new THREE.Vector3(p[0], p[1], p[2]);
  function line(points, color, opacity = .35) {
    const object = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({ color, transparent: true, opacity, depthWrite: false }));
    world.add(object); return object;
  }
  function circle(radius, segments = 64) { return Array.from({ length: segments + 1 }, (_, i) => { const a = i / segments * Math.PI * 2; return new THREE.Vector3(Math.cos(a) * radius, 0, Math.sin(a) * radius); }); }
  function dispose(object) { object.traverse(child => { child.geometry?.dispose(); const m = child.material; (Array.isArray(m) ? m : m ? [m] : []).forEach(x => x.dispose()); }); }
  function geometry(kind) {
    switch (kind) {
      case 'user': return new THREE.TorusGeometry(.26, .08, 12, 32);
      case 'coordinator': return new THREE.IcosahedronGeometry(.42, 1);
      case 'owner': return new THREE.OctahedronGeometry(.32);
      case 'reviewer': return new THREE.TetrahedronGeometry(.22);
      case 'work': return new THREE.BoxGeometry(.3, .2, .3);
      case 'repo': return new THREE.BoxGeometry(.2, .2, .2);
      default: return new THREE.SphereGeometry(.18, 18, 14);
    }
  }
  function build() {
    if (world) { scene.remove(world); dispose(world); }
    pulses = []; nodes.clear();
    world = new THREE.Group(); scene.add(world);
    colors = palette();
    // The planes of the pyramid: owners, agents and each DAG step, as faint rings sized to their content.
    const planes = new Map();
    for (const p of positions.values()) { const key = p[1].toFixed(2); planes.set(key, Math.max(planes.get(key) || 0, Math.hypot(p[0], p[2]))); }
    for (const [y, r] of planes) { if (r < .2) continue; const ringLine = line(circle(r + .45), colors.edge, .12); ringLine.position.y = Number(y); }
    const all = [...(graph?.nodes || []), ...repoNodes()];
    for (const node of all) {
      const p = positions.get(node.id); if (!p) continue;
      const position = v3(p);
      const core = new THREE.Group(); core.position.copy(position); world.add(core);
      const base = node.kind === 'repo' ? colors.types.repo : node.kind === 'work' && node.done ? colors.done : colors.types[node.kind] || colors.edge;
      const mesh = new THREE.Mesh(geometry(node.kind), new THREE.MeshStandardMaterial({ color: base, emissive: base, emissiveIntensity: .35, roughness: .4, metalness: .2,
        transparent: node.kind === 'work' && node.done, opacity: node.kind === 'work' && node.done ? .6 : 1 }));
      if (node.kind === 'owner' && !isLive(node)) { mesh.material.transparent = true; mesh.material.opacity = .45; }
      core.add(mesh);
      // Severity: a halo ring. Escalation: one thin ring per ladder step, stacked above the node.
      const sev = node.severity === 'high' || node.severity === 'critical' ? colors.sev.high : node.severity === 'warn' || node.severity === 'medium' ? colors.sev.warn : '';
      if (sev) { const halo = new THREE.Mesh(new THREE.RingGeometry(.4, .48, 40), new THREE.MeshBasicMaterial({ color: sev, side: THREE.DoubleSide, transparent: true, opacity: .9, depthWrite: false })); halo.rotation.x = -Math.PI / 2; core.add(halo); }
      for (let i = 0; i < Math.min(3, node.escalation || 0); i++) {
        const esc = new THREE.Mesh(new THREE.TorusGeometry(.3 + i * .07, .02, 6, 32), new THREE.MeshBasicMaterial({ color: colors.esc[Math.min(3, node.escalation)] }));
        esc.rotation.x = -Math.PI / 2; esc.position.y = .26 + i * .06; core.add(esc);
      }
      nodes.set(node.id, { core, position, mesh, node });
    }
    const edgeColor = kind => ({ spawn: colors.edge, review: colors.types.reviewer, works_on: colors.types.work, next: colors.types.work, depends: colors.types.work, parent: colors.edge, inbox: colors.types.user }[kind] || colors.edge);
    for (const edge of graph?.edges || []) {
      const a = nodes.get(edge.from)?.position, b = nodes.get(edge.to)?.position;
      if (!a || !b) continue;
      line([a, b], edgeColor(edge.kind), edge.kind === 'spawn' ? .28 : edge.kind === 'review' ? .7 : .5);
    }
  }
  function signature() {
    return [...positions.entries()].map(([id, p]) => `${id}:${p.map(v => v.toFixed(2)).join(',')}`).join('|') + '|' +
      (graph?.nodes || []).map(n => `${n.id}:${n.state}:${n.severity}:${n.escalation}:${n.done}:${n.model}:${n.effort}:${n.inbox ?? ''}`).join('|') + '|' + (graph?.edges || []).length;
  }
  function rebuild(state) {
    graph = state.orggraph;
    byId = new Map((graph?.nodes || []).map(n => [n.id, n]));
    positions = layout(graph, recentRepos(state.events));
    // Frame the live part of the pyramid; the outer ring of idle owners may run past the edge.
    extent = Math.max(3, ...[...positions.entries()].filter(([id]) => { const n = byId.get(id); return !(n?.kind === 'owner' && !isLive(n)) && !id.startsWith('repo:'); }).map(([, p]) => Math.hypot(p[0], p[2])));
    const sig = signature();
    renderMeta(state);
    if (sig === modelSig) return false;
    modelSig = sig;
    rebuildLabels();
    if (listMode) renderList();
    if (available && THREE) { build(); fitCamera(); }
    if (!available) positionStatic();
    size(); start();
    return true;
  }
  function renderMeta(state) {
    const g = state.orggraph;
    if (!g) { meta.textContent = 'Waiting for the org graph from the server…'; return; }
    const c = g.counts || {};
    meta.textContent = `${c.live_owners ?? 0} live of ${c.owner ?? 0} owners · ${c.subagent ?? 0} sub-agents · ${c.reviewer ?? 0} reviewers · ${c.work ?? 0} work items${c.hidden_agents ? ` · ${c.hidden_agents} older agents not drawn` : ''} · graph last changed ${ageText(g.generated, state.now)} · session ${g.session ? String(g.session).slice(0, 8) : 'unknown'} · from ah owners, transcripts and GoodQA`;
    const gaps = document.getElementById('org-gaps');
    gaps.replaceChildren(...(g.gaps || []).map(text => el('li', '', text)));
  }
  function fitCamera() {
    if (!camera) return;
    const d = (3 + extent * 1.45) * zoom;
    camera.position.set(0, 1.4 + d * .32, d);
    camera.lookAt(0, -.1, 0);
  }
  const scratch = { v: null };
  function projectLabels() {
    if (!camera || !stageRect) return;
    const v = scratch.v ||= new THREE.Vector3();
    for (const [id, { label }] of labelNodes) {
      const entry = nodes.get(id); if (!entry) continue;
      entry.core.getWorldPosition(v); v.project(camera);
      const x = (v.x * .5 + .5) * window.innerWidth - stageRect.left;
      const y = (-v.y * .5 + .5) * window.innerHeight - stageRect.top + 20;
      // A label whose node is off the stage is hidden (still focusable), never squeezed against the edge.
      label.classList.toggle('offstage', v.z > 1 || x < 0 || y < 0 || x > stageRect.width || y > stageRect.height);
      label.style.left = `${x}px`;
      label.style.top = `${y}px`;
    }
    cull();
  }
  // Labels never overlap: place them by priority, hide (not remove) the rest; a hidden label stays focusable.
  const rank = node => (node.severity === 'high' || node.severity === 'critical' ? .5 : node.kind === 'owner' ? (isLive(node) ? 1 : 4.5) : PRIORITY[node.kind] ?? 6);
  const PRIORITY = { coordinator: 0, user: 0, subagent: 2, reviewer: 2.5, work: 3, repo: 5 };
  function cull() {
    const state = getState();
    const entries = [...labelNodes.values()].filter(entry => !entry.label.classList.contains('offstage')).map(entry => ({ entry, p: state.highlight === entry.node.id || state.selection?.id === entry.node.id ? -1 : rank(entry.node),
      x: parseFloat(entry.label.style.left), y: parseFloat(entry.label.style.top), w: entry.label.offsetWidth + 6, h: entry.label.offsetHeight + 4 })).sort((a, b) => a.p - b.p);
    const placed = [];
    for (const item of entries) {
      const box = { l: item.x - item.w / 2, r: item.x + item.w / 2, t: item.y - item.h / 2, b: item.y + item.h / 2 };
      const clash = item.w > 6 && placed.some(o => box.l < o.r && box.r > o.l && box.t < o.b && box.b > o.t);
      item.entry.label.classList.toggle('culled', clash && item.p > 0);
      if (!clash || item.p <= 0) placed.push(box);
    }
  }
  function renderOnce() {
    if (!available || listMode || getState().fallback || !visible || document.hidden) return;
    try {
      renderer.setScissorTest(false); renderer.clear();
      renderer.setScissor(stageRect.left, window.innerHeight - stageRect.bottom, stageRect.width, stageRect.height);
      renderer.setScissorTest(true); renderer.render(scene, camera);
      projectLabels();
    } catch { fallback('RENDER FALLBACK'); }
  }
  function disposePulse(pulse) { world.remove(pulse.mesh); dispose(pulse.mesh); }
  function draw(time) {
    frame = 0;
    if (!available || listMode || getState().fallback || !visible || document.hidden) return;
    const moving = getState().motion;
    if (time - lastFrame < 1000 / 30) { frame = requestAnimationFrame(draw); return; }
    const dt = lastTime ? Math.min((time - lastTime) / 1000, .1) : 0;
    lastTime = time; lastFrame = time;
    if (moving) elapsed += dt;
    yaw += (targetYaw - yaw) * .1; tilt += (targetTilt - tilt) * .1;
    world.rotation.y = yaw + (moving ? Math.sin(elapsed * .05) * .06 : 0);
    world.rotation.x = tilt;
    const state = getState();
    for (const [id, entry] of nodes) {
      const lit = state.highlight === id || state.selection?.id === id;
      entry.mesh.scale.setScalar(lit ? 1.45 : 1);
      if (moving && entry.node.kind === 'coordinator') entry.mesh.rotation.y = elapsed * .3;
      labelNodes.get(id)?.label.classList.toggle('active', lit);
    }
    for (let i = pulses.length - 1; i >= 0; i--) {
      const pulse = pulses[i]; pulse.age += dt;
      pulse.mesh.visible = pulse.age >= 0;
      if (pulse.age < 0) continue;
      const t = pulse.age / pulse.duration;
      if (t >= 1 || !moving) { disposePulse(pulse); pulses.splice(i, 1); continue; }
      if (pulse.kind === 'wave') { pulse.mesh.scale.setScalar(.4 + t * 2.6); pulse.mesh.material.opacity = (1 - t) * .85; }
      else pulse.mesh.position.copy(pulse.curve.getPoint(t));
    }
    renderOnce();
    if (moving || pulses.length || Math.abs(targetYaw - yaw) > .001 || Math.abs(targetTilt - tilt) > .001) frame = requestAnimationFrame(draw);
  }

  // ---- cues: every org change and every relevant feed event animates (or flashes, under reduced motion)
  function describeCue(cue) {
    const map = EVENT_MAP.find(e => e.id === cue.map);
    const name = id => { const n = byId.get(id); return n ? (n.kind === 'work' ? n.ref : SHORT[n.kind] || n.label) : String(id || '').replace(/^repo:/, ''); };
    const path = cue.from && cue.to ? `${name(cue.from)} → ${name(cue.to)}` : name(cue.ring || cue.to);
    return `${map ? map.label : cue.map}${cue.verdict ? ` (${cue.verdict})` : ''}: ${path}`;
  }
  function play(cue) {
    if (!cue) return;
    const target = cue.to && (nodes.has(cue.to) || labelNodes.has(cue.to)) ? cue.to : cue.ring;
    if (target) flash(target);
    if (cue.from && !cue.quiet) flash(cue.from);
    if (!cue.quiet) {
      cueLine.textContent = describeCue(cue);
      if (Date.now() - lastAnnounce > 4000) { announcer.textContent = describeCue(cue); lastAnnounce = Date.now(); }
    }
    if (!available || listMode || !getState().motion || document.hidden || !visible) return;
    const color = new THREE.Color(cue.color || colors.types.coordinator);
    const end = nodes.get(cue.to)?.position || nodes.get(cue.ring)?.position;
    const begin = cue.from ? nodes.get(cue.from)?.position : null;
    if (begin && end && !cue.quiet) {
      const lift = Math.max(.5, begin.distanceTo(end) * .3);
      const curve = new THREE.QuadraticBezierCurve3(begin.clone(), begin.clone().lerp(end, .5).add(new THREE.Vector3(0, lift, 0)), end.clone());
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(cue.merge ? .1 : .07, 10, 10), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .95, depthWrite: false }));
      mesh.position.copy(begin); world.add(mesh);
      pulses.push({ mesh, kind: 'travel', curve, age: 0, duration: 1.3 });
    }
    if (end) {
      const wave = new THREE.Mesh(new THREE.RingGeometry(.18, .21, 40), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .85, side: THREE.DoubleSide, depthWrite: false }));
      wave.position.copy(end); wave.rotation.x = -Math.PI / 2; wave.visible = false; world.add(wave);
      pulses.push({ mesh: wave, kind: 'wave', age: begin && !cue.quiet ? -1.3 : 0, duration: cue.quiet ? .6 : 1 });
    }
    while (pulses.length > MAX_PULSES) disposePulse(pulses.shift());
    start();
  }
  // A burst is spread out: at most one cue every 250 ms, and the queue is bounded (NEG-8).
  setInterval(() => { if (queue.length) play(queue.shift()); }, 250);
  const enqueue = cue => { if (!cue) return; queue.push(cue); if (queue.length > MAX_QUEUE) queue.splice(0, queue.length - MAX_QUEUE); };

  subscribe((next, reason) => {
    if (reason === 'orggraph' || reason === 'seed') {
      rebuild(next);
      const g = next.orggraph;
      if (g && g.seq !== lastSeq) { if (lastSeq !== -1) g.changes.forEach(change => enqueue(cueForChange(change, g))); lastSeq = g.seq; }
    }
    if (reason === 'event' && next.lastEvent && !next.lastEvent.historic) {
      if (['push', 'release'].includes(next.lastEvent.kind)) rebuild(next);
      enqueue(cueForEvent(next.lastEvent, next.orggraph));
    }
    if (reason === 'tick') renderMeta(next);
    if (reason === 'motion') { pulses.forEach(disposePulse); pulses = []; stop(); start(); }
    if (reason === 'theme') { requestAnimationFrame(() => { if (available && THREE) { build(); start(); } }); }
    if (reason === 'highlight' || reason === 'selection') { labelNodes.forEach(({ label }, id) => label.classList.toggle('active', next.highlight === id || next.selection?.id === id)); start(); }
    if (reason === 'tab') requestAnimationFrame(() => { size(); start(); });
  });
  document.getElementById('scene-reset').addEventListener('click', () => { targetYaw = 0; targetTilt = 0; zoom = 1; fitCamera(); if (!getState().motion) { yaw = 0; tilt = 0; } start(); });
  stage.addEventListener('pointerdown', event => {
    if (event.target.closest('button')) return;
    dragging = true; pointerStart = { x: event.clientX, y: event.clientY, yaw: targetYaw, tilt: targetTilt, moved: false }; stage.setPointerCapture(event.pointerId);
  });
  stage.addEventListener('pointermove', event => {
    if (!dragging || !pointerStart || !available) return;
    const dx = event.clientX - pointerStart.x, dy = event.clientY - pointerStart.y;
    pointerStart.moved = Math.abs(dx) + Math.abs(dy) > 5;
    targetYaw = pointerStart.yaw + dx * .005;
    targetTilt = Math.max(-.35, Math.min(.5, pointerStart.tilt + dy * .003));
    if (!getState().motion) { yaw = targetYaw; tilt = targetTilt; }
    start();
  });
  stage.addEventListener('wheel', event => { if (!available || !event.ctrlKey && !event.metaKey) return; event.preventDefault(); zoom = Math.max(.5, Math.min(2.2, zoom * (event.deltaY > 0 ? 1.08 : .92))); fitCamera(); start(); }, { passive: false });
  // Keyboard: with focus on the stage background, arrows rotate and tilt, + and - zoom.
  stage.tabIndex = 0;
  stage.setAttribute('aria-label', 'Org graph 3D view. Arrow keys rotate and tilt, plus and minus zoom; Tab moves through the nodes.');
  stage.addEventListener('keydown', event => {
    if (event.target !== stage) return;
    const steps = { ArrowLeft: [-.15, 0], ArrowRight: [.15, 0], ArrowUp: [0, -.06], ArrowDown: [0, .06] };
    if (steps[event.key]) { targetYaw += steps[event.key][0]; targetTilt = Math.max(-.35, Math.min(.5, targetTilt + steps[event.key][1])); if (!getState().motion) { yaw = targetYaw; tilt = targetTilt; } }
    else if (event.key === '+' || event.key === '=') { zoom = Math.max(.5, zoom * .9); fitCamera(); }
    else if (event.key === '-') { zoom = Math.min(2.2, zoom * 1.1); fitCamera(); }
    else return;
    event.preventDefault(); start();
  });
  const release = () => { dragging = false; pointerStart = null; };
  stage.addEventListener('pointerup', release); stage.addEventListener('pointercancel', release);
  new IntersectionObserver(entries => { visible = entries[0].isIntersecting; if (visible) { size(); start(); } else stop(); }).observe(stage);
  new ResizeObserver(size).observe(stage);
  window.addEventListener('resize', size);
  window.addEventListener('scroll', () => { size(); start(); }, { passive: true });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); else { size(); start(); } });
  legend();
  const hash = new URLSearchParams(location.hash.slice(1));
  rebuild(getState());
  lastSeq = getState().orggraph?.seq ?? -1;
  if (hash.get('org') === 'list') setListMode(true);
  try {
    // #gl=off forces the static view, so the no-WebGL path can be tested anywhere.
    if (hash.get('gl') === 'off') throw new Error('gl=off');
    THREE = await import('../vendor/three.module.min.js');
    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: window.innerWidth >= 768, powerPreference: 'low-power' });
    renderer.setClearColor(0x000000, 0);
    renderer.debug.onShaderError = () => fallback('SHADER FALLBACK');
    document.getElementById('scene-layer').append(renderer.domElement);
    camera = new THREE.PerspectiveCamera(34, 1, .1, 120);
    scene = new THREE.Scene();
    scene.add(new THREE.AmbientLight('#ffffff', 1.6));
    const key = new THREE.DirectionalLight('#ffffff', 2.2); key.position.set(3, 6, 5); scene.add(key);
    available = true; poster.hidden = true; build(); fitCamera();
    renderer.domElement.addEventListener('webglcontextlost', event => { event.preventDefault(); fallback('CONTEXT LOST · STATIC'); });
    renderer.domElement.addEventListener('webglcontextrestored', () => { available = true; renderer.domElement.hidden = false; poster.hidden = true; mode.textContent = 'SPATIAL VIEW'; build(); size(); start(); });
    size(); start();
  } catch { fallback(hash.get('gl') === 'off' ? 'STATIC VIEW' : 'STATIC VIEW · NO WEBGL'); }
}
