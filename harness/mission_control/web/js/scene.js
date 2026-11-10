import { getState, subscribe, select, highlight, KINDS } from './store.js';
import { button, el } from './ui.js';
import { repos as recentRepos } from './adapt.js';

// One canvas, one animation clock. HTML buttons mirror every meaningful node, so the scene is usable without WebGL.
// Layout is data-driven: the coordinating main is the hub, initiatives orbit it, live or failing owners hang off
// their initiative, and repositories with recent pushes sit on the outer ring.
const MAX_OWNERS = 14;
const RISK = /at risk|blocked/i;
const DONE = /^done|complete/i;

function shortName(text) {
  const words = String(text).replace(/^[A-Za-z]+:\s*/, '').split(/\s+/);
  let out = '';
  for (const word of words) { if ((out + ' ' + word).trim().length > 18) break; out = (out + ' ' + word).trim(); }
  return out || String(text).slice(0, 18);
}

function layout(state) {
  const initiatives = state.initiatives.slice(0, 16);
  const n = Math.max(initiatives.length, 1);
  const nodes = [{ id: 'hub', kind: 'hub', name: 'Main', short: 'Main', pos: [0, .45, 0] }];
  initiatives.forEach((item, i) => {
    const a = i / n * Math.PI * 2 - Math.PI / 2;
    const r = n > 9 ? 3.35 : n > 5 ? 3 : 2.6;
    nodes.push({ id: item.id, kind: 'initiative', name: item.initiative, short: shortName(item.initiative), item,
      pos: [Math.cos(a) * r, (i % 2 ? .35 : -.15) + Math.sin(i * 1.3) * .12, Math.sin(a) * r * .82] });
  });
  const shown = state.owners.filter(o => o.state === 'live' || o.severe || o.held).slice(0, MAX_OWNERS);
  shown.forEach((owner, i) => {
    const parent = nodes.find(node => node.id === owner.initiative_id) || nodes[0];
    const a = i * 1.7;
    nodes.push({ id: owner.agent_id, kind: 'owner', name: owner.name, short: owner.name, owner, parent: parent.id,
      pos: [parent.pos[0] + Math.cos(a) * .75, parent.pos[1] + .35, parent.pos[2] + Math.sin(a) * .65] });
  });
  recentRepos(state.events).forEach((repo, i) => {
    const a = i / 3 * Math.PI * 2 + .3;
    nodes.push({ id: `repo:${repo}`, kind: 'repo', name: repo, short: `⌘ ${repo.split('/').pop()}`, repo, pos: [Math.cos(a) * 4.4, 0, Math.sin(a) * 4.4] });
  });
  return nodes;
}

const signature = nodes => nodes.map(node => `${node.kind}:${node.id}:${node.parent || ''}`).join('|');

export async function mountScene() {
  const stage = document.getElementById('scene-stage');
  const labels = document.getElementById('scene-labels');
  const poster = document.getElementById('scene-poster');
  const mode = document.getElementById('scene-mode');
  const nodes = new Map(), labelNodes = new Map();
  let model = layout(getState()), modelSig = '';
  let THREE, renderer, camera, world, scene;
  let available = false, visible = true, frame = 0, lastFrame = -Infinity, elapsed = 0, lastTime = 0;
  let yaw = 0, targetYaw = 0, tilt = 0, targetTilt = 0, dragging = false, pointerStart = null;
  let stageRect, pulses = [], flashTimers = new Map();
  let renderWidth = 0, renderHeight = 0, renderRatio = 0;
  let layers = [], packets = [];
  let hoverX = 0, hoverY = 0, parallaxX = 0, parallaxY = 0;

  function addLabel(node) {
    const extra = node.kind === 'hub' ? 'central' : node.kind === 'owner' ? `owner-node${node.owner.severe ? ' severe' : ''}` : node.kind === 'repo' ? 'repo-node' : RISK.test(node.item.state) ? 'at-risk' : '';
    const label = button(`node-label ${extra}`, '', event => {
      if (pointerStart?.moved) return;
      event.stopPropagation();
      select(node.kind === 'repo' ? 'repo' : node.kind, node.kind === 'repo' ? node.repo : node.id);
    });
    label.replaceChildren(el('span', 'node-full', node.kind === 'initiative' ? node.short : node.name), el('span', 'node-short', node.short));
    label.dataset.nodeId = node.id;
    label.title = node.name;
    const what = node.kind === 'initiative' ? `initiative ${node.name}, ${node.item.state}${node.item.pct !== null ? `, ${node.item.pct}%` : ''}` : node.kind === 'owner' ? `owner ${node.name}, ${node.owner.state}` : node.kind === 'repo' ? `repository ${node.repo}` : 'the main coordinator';
    label.setAttribute('aria-label', `Open ${what}`);
    const key = node.kind === 'repo' ? null : node.id;
    label.addEventListener('pointerenter', () => highlight(key));
    label.addEventListener('pointerleave', () => highlight(null));
    label.addEventListener('focus', () => highlight(key));
    label.addEventListener('blur', () => highlight(null));
    labels.append(label);
    labelNodes.set(node.id, { label, node });
  }
  function rebuildLabels() {
    labels.replaceChildren();
    labelNodes.clear();
    model.forEach(addLabel);
  }
  function positionStatic() {
    const rect = stage.getBoundingClientRect();
    const width = rect.width || 600, height = rect.height || 260;
    for (const { label, node } of labelNodes.values()) {
      const [x, , z] = node.pos;
      const half = label.offsetWidth / 2 + 6, halfHeight = label.offsetHeight / 2 + 6;
      label.style.left = `${Math.max(half, Math.min(width - half, width * (.5 + x / 4.8 * .44)))}px`;
      label.style.top = `${Math.max(halfHeight, Math.min(height - halfHeight, height * (.5 + z / 4.8 * .42)))}px`;
    }
    if (window.innerWidth >= 768) cull();
  }
  function fallback(reason = 'STATIC VIEW') {
    available = false;
    if (renderer) renderer.domElement.hidden = true;
    poster.classList.remove('webgl-active');
    mode.textContent = reason;
    positionStatic();
    stop();
  }
  function staticFlash(id) {
    // On phones only the hub label is shown, so it is also the stationary event cue.
    const item = labelNodes.get(window.innerWidth < 768 ? 'hub' : id) || labelNodes.get('hub');
    if (!item) return;
    const key = item.label.dataset.nodeId;
    clearTimeout(flashTimers.get(key));
    item.label.classList.add('static-flash');
    flashTimers.set(key, setTimeout(() => { item.label.classList.remove('static-flash'); flashTimers.delete(key); }, 650));
  }
  function start() {
    if (!frame && available && !getState().fallback && visible && !document.hidden) { lastTime = 0; frame = requestAnimationFrame(draw); }
  }
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
    // The canvas covers the viewport; the camera's optical centre follows the HUD gap.
    camera.setViewOffset(stageRect.width, stageRect.height, -stageRect.left, -stageRect.top, width, height);
    camera.fov = width < 768 ? 27 : stageRect.width / stageRect.height < 1.6 ? 33 : 30;
    camera.updateProjectionMatrix();
    start();
  }
  const v3 = p => new THREE.Vector3(p[0], p[1], p[2]);
  function line(points, color = '#8b967f', opacity = .22) {
    const object = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({ color, transparent: true, opacity, depthWrite: false }));
    world.add(object); return object;
  }
  function arc(radius, start = 0, length = Math.PI * 2, y = 0, segments = 100) {
    return Array.from({ length: segments + 1 }, (_, i) => { const a = start + i / segments * length; return new THREE.Vector3(Math.cos(a) * radius, y, Math.sin(a) * radius); });
  }
  function glow(color, radius = .55, opacity = .6) {
    // A procedural billboard: soft falloff, no bitmap, postprocessing or extra clock.
    const material = new THREE.ShaderMaterial({
      uniforms: { tint: { value: new THREE.Color(color) }, strength: { value: opacity } },
      vertexShader: 'varying vec2 vUv; varying float vDepth; void main(){vUv=uv; vec4 p=modelViewMatrix*vec4(0.,0.,0.,1.); vDepth=-p.z; p.xy+=position.xy; gl_Position=projectionMatrix*p;}',
      fragmentShader: 'uniform vec3 tint; uniform float strength; varying vec2 vUv; varying float vDepth; void main(){float r=length(vUv-.5)*2.; float a=pow(max(0.,1.-r),3.)*strength*(1.-smoothstep(8.,18.,vDepth)); gl_FragColor=vec4(tint,a);}',
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    });
    return new THREE.Mesh(new THREE.PlaneGeometry(radius * 2, radius * 2), material);
  }
  function spark(color, radius = .07) {
    const group = new THREE.Group();
    group.add(new THREE.Mesh(new THREE.SphereGeometry(radius, 8, 8), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .95, depthWrite: false })));
    group.add(glow(color, radius * 5, .85));
    return group;
  }
  function dispose(object) {
    object.traverse(child => { child.geometry?.dispose(); const m = child.material; (Array.isArray(m) ? m : m ? [m] : []).forEach(x => x.dispose()); });
  }
  function build() {
    if (world) { scene.remove(world); dispose(world); }
    pulses = []; packets = []; layers = []; nodes.clear();
    world = new THREE.Group(); scene.add(world);
    [3.55, 4.3, 4.8].forEach((radius, i) => {
      const orbit = line(arc(radius), i === 1 ? '#d2dfb8' : '#a1b2a3', i === 1 ? .24 : .13);
      orbit.rotation.x = (i - 1) * .22; orbit.rotation.z = (i - 1) * .16; orbit.position.y = (i - 1) * .32;
    });
    [-1.8, 1.1].forEach((height, layerIndex) => {
      const stars = [];
      for (let i = 0; i < 65; i++) { const a = i * 2.39996, r = 1.5 + (i % 23) / 23 * 5.3; stars.push(Math.cos(a) * r, height + Math.sin(i * 7.7) * .6, Math.sin(a) * r); }
      const geometry = new THREE.BufferGeometry(); geometry.setAttribute('position', new THREE.Float32BufferAttribute(stars, 3));
      const layer = new THREE.Points(geometry, new THREE.PointsMaterial({ color: '#b5c29d', size: layerIndex ? .025 : .016, transparent: true, opacity: layerIndex ? .4 : .22, depthWrite: false }));
      world.add(layer); layers.push(layer);
    });
    const hub = model[0];
    const currents = [];
    for (const node of model) {
      const position = v3(node.pos);
      const core = new THREE.Group(); core.position.copy(position); world.add(core);
      let sphere;
      if (node.kind === 'hub') {
        sphere = new THREE.Mesh(new THREE.IcosahedronGeometry(.3, 2), new THREE.MeshPhysicalMaterial({ color: '#eaff9e', metalness: .8, roughness: .24, clearcoat: 1, emissive: '#a1c750', emissiveIntensity: .18 }));
        core.add(sphere, glow('#eaff9e', .95, .85));
        core.add(new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(.42, 0)), new THREE.LineBasicMaterial({ color: '#eaff9e', transparent: true, opacity: .35 })));
      } else if (node.kind === 'initiative') {
        const risk = RISK.test(node.item.state), done = DONE.test(node.item.state);
        const color = risk ? '#f1c782' : done ? '#7edbca' : '#d5e4bc';
        sphere = new THREE.Mesh(new THREE.IcosahedronGeometry(.16, 2), new THREE.MeshPhysicalMaterial({ color, metalness: .8, roughness: .24, clearcoat: 1, emissive: risk ? '#8a5a12' : '#a1c750', emissiveIntensity: .08 }));
        core.add(sphere, glow(risk ? '#f1c782' : '#eaff9e', .58, risk ? .7 : .5));
        core.add(new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(.21, 0)), new THREE.LineBasicMaterial({ color: '#eaff9e', transparent: true, opacity: .3 })));
        core.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(arc(.38)), new THREE.LineBasicMaterial({ color: '#66764c', transparent: true, opacity: .45 })));
        // The progress ring is the initiative's percentage, read from initiatives.json.
        if (node.item.pct !== null && node.item.pct > 0) core.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(arc(.38, -Math.PI / 2, node.item.pct / 100 * Math.PI * 2, .015, 64)), new THREE.LineBasicMaterial({ color: risk ? '#f1c782' : '#eaff9e', transparent: true, opacity: .95 })));
        const curve = new THREE.QuadraticBezierCurve3(position, new THREE.Vector3(position.x * .5, .75, position.z * .5), v3(hub.pos));
        line(curve.getPoints(60), risk ? '#c9a46a' : '#b4c88c', .26);
        currents.push(curve);
      } else if (node.kind === 'owner') {
        sphere = new THREE.Mesh(new THREE.OctahedronGeometry(.06), new THREE.MeshBasicMaterial({ color: node.owner.severe ? '#f1a6a6' : node.owner.runtime === 'codex' ? '#9ebfff' : '#cad9dc' }));
        core.add(sphere);
        if (node.owner.severe) core.add(glow('#f1a6a6', .3, .6));
        line([v3(model.find(m => m.id === node.parent).pos), position], node.owner.severe ? '#c98787' : '#b5cad6', .26);
      } else {
        sphere = new THREE.Mesh(new THREE.BoxGeometry(.1, .1, .1), new THREE.MeshBasicMaterial({ color: '#9ebfff' }));
        core.add(sphere);
        line(arc(4.4, Math.atan2(position.z, position.x) - .25, .5, 0, 12), '#9ebfff', .3);
      }
      nodes.set(node.id, { core, position, sphere, node });
    }
    // A slow ambient current runs from each initiative into the hub.
    currents.forEach((curve, i) => {
      const mesh = spark('#eaff9e', .03);
      world.add(mesh); packets.push({ mesh, curve, phase: i * .17, speed: .07 + (i % 3) * .015 });
    });
  }
  function rebuild(state) {
    model = layout(state);
    const sig = signature(model);
    if (sig === modelSig) return false;
    modelSig = sig;
    rebuildLabels();
    if (available && THREE) build();
    if (!available) positionStatic();
    size(); start();
    return true;
  }
  const scratch = { v: null };
  function projectLabels() {
    if (!camera || !stageRect) return;
    const v = scratch.v ||= new THREE.Vector3();
    const phone = window.innerWidth < 768;
    for (const [id, { label, node }] of labelNodes) {
      if (phone && id !== 'hub') continue;
      const entry = nodes.get(id); if (!entry) continue;
      entry.core.getWorldPosition(v); v.project(camera);
      const x = (v.x * .5 + .5) * window.innerWidth - stageRect.left;
      const y = (-v.y * .5 + .5) * window.innerHeight - stageRect.top + (node.kind === 'owner' ? 0 : node.kind === 'repo' ? 17 : 22);
      const half = label.offsetWidth / 2 + 6, halfHeight = label.offsetHeight / 2 + 6;
      label.style.left = `${Math.max(half, Math.min(stageRect.width - half, x))}px`;
      label.style.top = `${Math.max(halfHeight, Math.min(stageRect.height - halfHeight, y))}px`;
    }
    if (!phone) cull();
  }
  // Labels never overlap: place them by priority and hide (not remove) the ones that would collide.
  // A hidden label stays keyboard-focusable and reappears when its node is highlighted.
  function priority({ node }, state) {
    if (node.kind === 'hub' || state.highlight === node.id || state.selection?.id === node.id) return 0;
    if (node.kind === 'initiative') return RISK.test(node.item.state) ? 1 : 2;
    if (node.kind === 'owner') return node.owner.severe ? 1 : 4;
    return 3;
  }
  function cull() {
    const state = getState();
    const entries = [...labelNodes.values()].map(entry => ({ entry, p: priority(entry, state), x: parseFloat(entry.label.style.left), y: parseFloat(entry.label.style.top),
      w: entry.label.offsetWidth + 6, h: entry.label.offsetHeight + 4 })).sort((a, b) => a.p - b.p);
    const placed = [];
    for (const item of entries) {
      const box = { l: item.x - item.w / 2, r: item.x + item.w / 2, t: item.y - item.h / 2, b: item.y + item.h / 2 };
      const clash = item.w > 6 && placed.some(o => box.l < o.r && box.r > o.l && box.t < o.b && box.b > o.t);
      item.entry.label.classList.toggle('culled', clash && item.p > 0);
      if (!clash || item.p === 0) placed.push(box);
    }
  }
  function renderOnce() {
    if (!available || getState().fallback || !visible || document.hidden) return;
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
    if (!available || getState().fallback || !visible || document.hidden) return;
    const moving = getState().motion;
    const interval = 1000 / (window.innerWidth < 768 ? 18 : 25);
    if (time - lastFrame < interval) { frame = requestAnimationFrame(draw); return; }
    const dt = lastTime ? Math.min((time - lastTime) / 1000, .1) : 0;
    lastTime = time; lastFrame = time;
    if (moving) elapsed += dt;
    yaw += (targetYaw - yaw) * .08; tilt += (targetTilt - tilt) * .08;
    parallaxX = moving ? parallaxX + (hoverX - parallaxX) * .07 : 0;
    parallaxY = moving ? parallaxY + (hoverY - parallaxY) * .07 : 0;
    world.rotation.y = yaw + (moving ? Math.sin(elapsed * .09) * .09 + parallaxX * .055 : 0);
    world.rotation.x = -.12 + tilt + parallaxY * .025;
    world.rotation.z = -.065;
    layers.forEach((layer, i) => { layer.rotation.y = moving ? Math.sin(elapsed * .035 + i) * .045 + parallaxX * (i ? -.035 : .04) : 0; layer.position.x = parallaxX * (i ? .12 : -.15); });
    packets.forEach(packet => { packet.mesh.visible = moving; packet.mesh.position.copy(packet.curve.getPoint((packet.phase + elapsed * packet.speed) % 1)); });
    const state = getState();
    for (const [id, entry] of nodes) {
      const lit = state.highlight === id || state.selection?.id === id || (entry.node.kind === 'repo' && state.selection?.id === entry.node.repo);
      entry.sphere.scale.setScalar(lit ? 1.4 : 1);
      if (entry.node.kind === 'owner' && entry.node.owner.severe && moving) entry.sphere.scale.multiplyScalar(1 + Math.sin(elapsed * 4) * .15);
      labelNodes.get(id)?.label.classList.toggle('active', lit);
    }
    for (let i = pulses.length - 1; i >= 0; i--) {
      const pulse = pulses[i]; pulse.age += dt;
      pulse.mesh.visible = pulse.age >= 0;
      if (pulse.age < 0) continue;
      const t = pulse.age / pulse.duration;
      if (t >= 1 || !moving) { disposePulse(pulse); pulses.splice(i, 1); continue; }
      if (pulse.kind === 'wave') { pulse.mesh.scale.setScalar(.3 + t * 4); pulse.mesh.material.opacity = (1 - t) * .7; }
      else pulse.mesh.position.copy(pulse.curve.getPoint(t));
    }
    renderOnce();
    if (moving || pulses.length || Math.abs(targetYaw - yaw) > .001 || Math.abs(targetTilt - tilt) > .001) frame = requestAnimationFrame(draw);
  }
  function endpoints(event) {
    const state = getState();
    const owner = state.owners.find(o => o.agent_id === event.actor.agent);
    const repoId = event.subject.repo ? `repo:${event.subject.repo}` : '';
    const to = nodes.has(event.subject.initiative) ? event.subject.initiative : owner?.initiative_id && nodes.has(owner.initiative_id) ? owner.initiative_id : 'hub';
    let from = nodes.has(event.actor.agent) ? event.actor.agent : nodes.has(repoId) ? repoId : to;
    if (from === to) from = to === 'hub' ? (nodes.has(repoId) ? repoId : null) : 'hub';
    return { from, to };
  }
  function eventPulse(event) {
    const { from, to } = endpoints(event);
    staticFlash(event.kind === 'wal' && nodes.has(event.actor.agent) ? event.actor.agent : to);
    if (!available || getState().fallback || !getState().motion || document.hidden || !visible) return;
    const color = KINDS[event.kind]?.color || '#eaff9e';
    const end = nodes.get(to).position.clone();
    if (event.quiet) {
      // Tool calls and lifecycle: a small ripple where the owner sits, no travelling spark.
      const at = nodes.get(event.actor.agent)?.position.clone() || end;
      const ripple = new THREE.Mesh(new THREE.RingGeometry(.08, .095, 32), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .45, side: THREE.DoubleSide, depthWrite: false }));
      ripple.position.copy(at); ripple.rotation.x = -Math.PI / 2; world.add(ripple);
      pulses.push({ mesh: ripple, kind: 'wave', age: 0, duration: .7 });
      while (pulses.length > 32) disposePulse(pulses.shift());
      start();
      return;
    }
    if (from) {
      const begin = nodes.get(from).position.clone();
      const curve = event.kind === 'push' && from.startsWith('repo:')
        ? new THREE.CatmullRomCurve3([begin, ...arc(4.3, Math.atan2(begin.z, begin.x), .6, 0, 10), end])
        : new THREE.QuadraticBezierCurve3(begin, begin.clone().lerp(end, .5).add(new THREE.Vector3(0, .7, 0)), end);
      const mesh = spark(color, .09); mesh.position.copy(begin); world.add(mesh);
      pulses.push({ mesh, kind: 'travel', curve, age: 0, duration: 1.45 });
    }
    const wave = new THREE.Mesh(new THREE.RingGeometry(.2, .225, 48), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .7, side: THREE.DoubleSide, depthWrite: false }));
    wave.position.copy(end); wave.rotation.x = -Math.PI / 2; wave.visible = false; world.add(wave);
    pulses.push({ mesh: wave, kind: 'wave', age: from ? -1.45 : 0, duration: .9 });
    while (pulses.length > 32) disposePulse(pulses.shift());
    start();
  }
  subscribe((next, reason) => {
    if (['initiatives', 'owners', 'seed'].includes(reason)) rebuild(next);
    if (reason === 'event' && next.lastEvent && !next.lastEvent.historic) {
      if (['push', 'release', 'deploy'].includes(next.lastEvent.kind)) rebuild(next);
      eventPulse(next.lastEvent);
    }
    if (reason === 'motion') { pulses.forEach(disposePulse); pulses = []; stop(); start(); }
    if (reason === 'highlight' || reason === 'selection') {
      labelNodes.forEach(({ label }, id) => label.classList.toggle('active', next.highlight === id || next.selection?.id === id)); start();
    }
    if (reason === 'tab') requestAnimationFrame(() => { size(); start(); });
  });
  document.getElementById('scene-reset').addEventListener('click', () => { targetYaw = 0; targetTilt = 0; hoverX = hoverY = 0; if (!getState().motion) { yaw = 0; tilt = 0; } start(); });
  stage.addEventListener('pointerdown', event => {
    if (event.target.closest('button')) return;
    dragging = true; pointerStart = { x: event.clientX, y: event.clientY, yaw: targetYaw, tilt: targetTilt, moved: false }; stage.setPointerCapture(event.pointerId);
  });
  stage.addEventListener('pointermove', event => {
    if (event.pointerType === 'mouse' && stageRect) { hoverX = (event.clientX - stageRect.left) / stageRect.width * 2 - 1; hoverY = (event.clientY - stageRect.top) / stageRect.height * 2 - 1; }
    if (!dragging || !pointerStart || !available) return;
    const dx = event.clientX - pointerStart.x, dy = event.clientY - pointerStart.y;
    pointerStart.moved = Math.abs(dx) + Math.abs(dy) > 5;
    targetYaw = Math.max(-.6, Math.min(.6, pointerStart.yaw + dx * .0025));
    targetTilt = Math.max(-.15, Math.min(.15, pointerStart.tilt + dy * .0015));
    if (!getState().motion) { yaw = targetYaw; tilt = targetTilt; }
    start();
  });
  stage.addEventListener('pointerleave', () => { hoverX = hoverY = 0; });
  const release = () => { dragging = false; pointerStart = null; };
  stage.addEventListener('pointerup', release); stage.addEventListener('pointercancel', release);
  new IntersectionObserver(entries => { visible = entries[0].isIntersecting; if (visible) { size(); start(); } else stop(); }).observe(stage);
  new ResizeObserver(size).observe(stage);
  window.addEventListener('resize', size);
  window.addEventListener('scroll', () => { size(); start(); }, { passive: true });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); else { size(); start(); } });
  rebuild(getState());
  try {
    // #gl=off forces the static view (a view preference, like #tab=), so the no-WebGL path can be tested anywhere.
    if (new URLSearchParams(location.hash.slice(1)).get('gl') === 'off') throw new Error('gl=off');
    THREE = await import('../vendor/three.module.min.js');
    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: window.innerWidth >= 768, powerPreference: 'low-power' });
    renderer.setClearColor(0x000000, 0);
    renderer.debug.onShaderError = () => fallback('SHADER FALLBACK');
    document.getElementById('scene-layer').append(renderer.domElement);
    camera = new THREE.PerspectiveCamera(30, 1, .1, 80); camera.position.set(.3, 5.9, 9.4); camera.lookAt(0, 0, 0);
    scene = new THREE.Scene();
    scene.fog = new THREE.Fog('#000000', 8, 18);
    scene.add(new THREE.AmbientLight('#b4c6ab', 2));
    const key = new THREE.DirectionalLight('#edffd4', 5); key.position.set(2, 5, 4); scene.add(key);
    const rim = new THREE.PointLight('#d8eaff', 35, 15); rim.position.set(-4, 3, -2); scene.add(rim);
    available = true; build();
    renderer.domElement.addEventListener('webglcontextlost', event => { event.preventDefault(); fallback('CONTEXT LOST · STATIC'); });
    renderer.domElement.addEventListener('webglcontextrestored', () => { available = true; renderer.domElement.hidden = false; poster.classList.add('webgl-active'); mode.textContent = 'SPATIAL VIEW'; build(); size(); start(); });
    poster.classList.add('webgl-active'); size(); start();
  } catch { fallback('STATIC VIEW'); }
}
