import { getState, subscribe, select, highlight, KINDS } from './store.js';
import { button } from './ui.js';

// One canvas, one animation clock. HTML buttons mirror every meaningful node.
export async function mountScene() {
  const stage = document.getElementById('scene-stage');
  const labels = document.getElementById('scene-labels');
  const poster = document.getElementById('scene-poster');
  const mode = document.getElementById('scene-mode');
  const state = getState(), nodes = new Map(), labelNodes = new Map();
  const names = ['Mission control','Event stream','Sessions','Release path','Tickets','Mobile runner','WAL collectors'];
  const positions = [[0,.2,0],[-2.65,.25,-1.2],[2.65,.15,-1.4],[2.7,.05,1.35],[-2.8,-.05,1.4],[-.15,.1,-2.5],[.4,-.15,2.6]];
  const staticPositions = [[50,50],[26,28],[74,28],[77,73],[24,73],[47,12],[52,89]];
  let THREE, renderer, camera, world;
  let available = false, visible = true, frame = 0, lastFrame = -Infinity, elapsed = 0, lastTime = 0;
  let yaw = 0, targetYaw = 0, tilt = 0, targetTilt = 0, dragging = false, pointerStart = null;
  let stageRect, pulses = [], forcePoster = state.fallback, flashTimers = new Map();
  let renderWidth = 0, renderHeight = 0, renderRatio = 0;
  function addLabel(id, name, kind, index, extraClass = '') {
    const label = button(`node-label ${extraClass}`, name, event => {
      if (pointerStart?.moved) return;
      event.stopPropagation();
      select(kind, id);
    });
    label.dataset.nodeId = id;
    label.setAttribute('aria-label', `Open ${kind} ${name}`);
    label.addEventListener('pointerenter', () => highlight(id));
    label.addEventListener('pointerleave', () => highlight(null));
    label.addEventListener('focus', () => highlight(id));
    label.addEventListener('blur', () => highlight(null));
    labels.append(label);
    labelNodes.set(id, { label, kind, index });
    return label;
  }
  state.initiatives.forEach((item, i) => addLabel(item.id, names[i], 'initiative', i, i === 0 ? 'central' : ''));
  state.owners.forEach((owner, i) => addLabel(owner.agent_id, owner.agent_id, 'owner', i, 'owner-node'));
  ['harness','t2-dev','collectors'].forEach((repo, i) => addLabel(repo, `⌘ ${repo}`, 'repo', i, 'repo-node'));
  function positionStatic() {
    for (const { label, kind, index } of labelNodes.values()) {
      let x, y;
      if (kind === 'initiative') [x,y] = staticPositions[index];
      else if (kind === 'owner') { const a = index / 8 * Math.PI * 2; x = 50 + Math.cos(a) * 36; y = 50 + Math.sin(a) * 34; }
      else { const a = index / 3 * Math.PI * 2 + .5; x = 50 + Math.cos(a) * 45; y = 50 + Math.sin(a) * 43; }
      label.style.left = `${x}%`; label.style.top = `${y}%`;
    }
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
    const item = labelNodes.get(id) || labelNodes.get('mission');
    if (!item) return;
    clearTimeout(flashTimers.get(id));
    item.label.classList.add('static-flash');
    flashTimers.set(id, setTimeout(() => { item.label.classList.remove('static-flash'); flashTimers.delete(id); }, 650));
  }
  positionStatic();
  function start() {
    if (!frame && available && !forcePoster && visible && !document.hidden) {
      lastTime = 0;
      frame = requestAnimationFrame(draw);
    }
  }
  function stop() { cancelAnimationFrame(frame); frame = 0; lastTime = 0; }
  function size() {
    stageRect = stage.getBoundingClientRect();
    if (!renderer || !camera || stageRect.width < 1 || stageRect.height < 1) return;
    const width = window.innerWidth, height = window.innerHeight;
    const ratio = Math.min(devicePixelRatio || 1, width < 768 ? 1 : 1.5);
    if (ratio !== renderRatio || width !== renderWidth || height !== renderHeight) {
      renderer.setPixelRatio(ratio); renderer.setSize(width, height);
      renderWidth = width; renderHeight = height; renderRatio = ratio;
    }
    // The canvas covers the viewport; the camera's optical centre follows the HUD gap.
    camera.setViewOffset(stageRect.width, stageRect.height, -stageRect.left, -stageRect.top, width, height);
    camera.updateProjectionMatrix();
    start();
  }
  function line(points, color = '#8b967f', opacity = .22) {
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    const object = new THREE.Line(geometry, new THREE.LineBasicMaterial({ color, transparent: true, opacity, depthWrite: false }));
    world.add(object); return object;
  }
  function arc(radius, start = 0, length = Math.PI * 2, y = 0, segments = 100) {
    return Array.from({ length: segments + 1 }, (_, i) => { const a = start + i / segments * length; return new THREE.Vector3(Math.cos(a) * radius, y, Math.sin(a) * radius); });
  }
  function build() {
    world = new THREE.Group();
    const scene = new THREE.Scene(); scene.add(world);
    scene.add(new THREE.AmbientLight('#b4c6ab', 2));
    const key = new THREE.DirectionalLight('#edffd4', 5); key.position.set(2,5,4); scene.add(key);
    const rim = new THREE.PointLight('#d8eaff', 35, 15); rim.position.set(-4,3,-2); scene.add(rim);
    renderer.scene = scene;
    // Nested silver orbits, offset just enough to suggest depth.
    [3.55,4.3,4.8].forEach((radius, i) => {
      const orbit = line(arc(radius), i === 1 ? '#d2dfb8' : '#a1b2a3', i === 1 ? .24 : .13);
      orbit.rotation.x = (i-1) * .16; orbit.rotation.z = (i-1) * .11;
    });
    const current = new THREE.CatmullRomCurve3([new THREE.Vector3(-5,-.1,1),new THREE.Vector3(-2.9,.18,-.1),new THREE.Vector3(0,.2,0),new THREE.Vector3(2.6,.3,.6),new THREE.Vector3(5,.05,-1)]);
    line(current.getPoints(180), '#eaff9e', .55);
    line(current.getPoints(180).map(p => p.clone().add(new THREE.Vector3(0,-.08,.07))), '#eaff9e', .16);
    const stars = [];
    for (let i=0;i<125;i++) { const n = i*2.39996; const r = 1.3 + (i%23)/23*5.5; stars.push(Math.cos(n)*r, Math.sin(i*7.7)*1.5-.5, Math.sin(n)*r); }
    const starGeometry = new THREE.BufferGeometry(); starGeometry.setAttribute('position', new THREE.Float32BufferAttribute(stars,3));
    world.add(new THREE.Points(starGeometry, new THREE.PointsMaterial({ color:'#b5c29d',size:.018,transparent:true,opacity:.4 })));
    state.initiatives.forEach((item, i) => {
      const position = new THREE.Vector3(...positions[i]);
      const core = new THREE.Group(); core.position.copy(position); world.add(core);
      const radius = i === 0 ? .27 : .15;
      const material = new THREE.MeshPhysicalMaterial({color:i === 0 ? '#eaff9e' : '#d5e4bc',metalness:.8,roughness:.24,clearcoat:1,emissive:'#a1c750',emissiveIntensity:i === 0 ? .16 : .06});
      const sphere = new THREE.Mesh(new THREE.IcosahedronGeometry(radius,2),material); core.add(sphere);
      const cage = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(radius*1.3,0)),new THREE.LineBasicMaterial({color:'#eaff9e',transparent:true,opacity:.35})); core.add(cage);
      const ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(arc(radius*2.4)),new THREE.LineBasicMaterial({color:'#66764c',transparent:true,opacity:.4})); core.add(ring);
      if (item.pct !== null) { const fill = new THREE.Line(new THREE.BufferGeometry().setFromPoints(arc(radius*2.4,0,item.pct/100*Math.PI*2,.015)),new THREE.LineBasicMaterial({color:'#eaff9e',transparent:true,opacity:.9})); core.add(fill); }
      if (i > 0) {
        const curve = new THREE.QuadraticBezierCurve3(position,new THREE.Vector3(position.x*.5,.6,position.z*.2),new THREE.Vector3(...positions[0]));
        line(curve.getPoints(70),'#b4c88c',.28);
      }
      nodes.set(item.id,{core,position,sphere,kind:'initiative'});
    });
    state.owners.forEach((owner,i) => {
      const parent = nodes.get(owner.initiative_id), a = i*1.7;
      const position = parent.position.clone().add(new THREE.Vector3(Math.cos(a)*.85,.35,Math.sin(a)*.75));
      const core = new THREE.Group(); core.position.copy(position); world.add(core);
      const sphere = new THREE.Mesh(new THREE.OctahedronGeometry(.055),new THREE.MeshBasicMaterial({color:owner.state === 'DROPPED' ? '#f1a6a6' : '#cad9dc'})); core.add(sphere);
      line([parent.position,position],'#b5cad6',.24);
      nodes.set(owner.agent_id,{core,position,sphere,kind:'owner',parent:owner.initiative_id});
    });
    ['harness','t2-dev','collectors'].forEach((repo,i) => {
      const a = i/3*Math.PI*2+.3, position = new THREE.Vector3(Math.cos(a)*4.4,0,Math.sin(a)*4.4);
      const core = new THREE.Group();core.position.copy(position);world.add(core);
      const sphere = new THREE.Mesh(new THREE.BoxGeometry(.09,.09,.09),new THREE.MeshBasicMaterial({color:'#97a6ad'})); core.add(sphere);
      nodes.set(repo,{core,position,sphere,kind:'repo'});
    });
  }
  const pointCache = { value: null };
  function projectLabels() {
    if (!camera || !stageRect) return;
    const v = pointCache.value ||= new THREE.Vector3();
    for (const [id, {label,kind}] of labelNodes) {
      const node = nodes.get(id); if (!node) continue;
      node.core.getWorldPosition(v); v.project(camera);
      const x = (v.x*.5+.5)*window.innerWidth-stageRect.left;
      const y = (-v.y*.5+.5)*window.innerHeight-stageRect.top + (kind === 'owner' ? 0 : kind === 'repo' ? 17 : 22);
      const half = label.offsetWidth/2+2;
      label.style.left = `${Math.max(half,Math.min(stageRect.width-half,x))}px`;
      label.style.top = `${Math.max(23,Math.min(stageRect.height-20,y))}px`;
    }
  }
  function renderOnce() {
    if (!available || forcePoster || !visible || document.hidden) return;
    try { renderer.render(renderer.scene,camera); if (available && !forcePoster) projectLabels(); }
    catch { fallback('RENDER FALLBACK'); }
  }
  function disposePulse(pulse) { world.remove(pulse.mesh);pulse.mesh.geometry.dispose();pulse.mesh.material.dispose(); }
  function draw(time) {
    frame = 0;
    if (!available || forcePoster || !visible || document.hidden) return;
    const moving = getState().motion;
    const interval = 1000/(window.innerWidth<768?18:25);
    if (time-lastFrame < interval) { frame = requestAnimationFrame(draw); return; }
    {
      const dt = lastTime ? Math.min((time-lastTime)/1000,.1) : 0;
      lastTime = time; lastFrame = time;
      if (moving) elapsed += dt;
      yaw += (targetYaw-yaw)*.08; tilt += (targetTilt-tilt)*.08;
      world.rotation.y = yaw + (moving ? Math.sin(elapsed*.09)*.09 : 0);
      world.rotation.x = tilt;
      for (const [id,node] of nodes) {
        const lit = getState().highlight === id || getState().selection?.id === id;
        node.sphere.scale.setScalar(lit ? 1.35 : 1);
        labelNodes.get(id)?.label.classList.toggle('active',lit);
      }
      for (let i=pulses.length-1;i>=0;i--) {
        const pulse = pulses[i]; pulse.age += dt;
        const t = pulse.age/pulse.duration;
        if (t>=1 || !moving) { disposePulse(pulse);pulses.splice(i,1);continue; }
        if (pulse.kind === 'wave') { pulse.mesh.scale.setScalar(.3+t*4);pulse.mesh.material.opacity=(1-t)*.7; }
        else if (pulse.kind === 'ring') { const a=pulse.angle+t*Math.PI*.8;pulse.mesh.position.set(Math.cos(a)*4.3,.05,Math.sin(a)*4.3);pulse.mesh.material.opacity=1-t*.6; }
        else { pulse.mesh.position.lerpVectors(pulse.from,pulse.to,t);pulse.mesh.position.y+=Math.sin(t*Math.PI)*.5; }
      }
      renderOnce();
    }
    if (moving || pulses.length || Math.abs(targetYaw-yaw)>.001 || Math.abs(targetTilt-tilt)>.001) frame=requestAnimationFrame(draw);
  }
  function eventPulse(event) {
    const id = nodes.has(event.actor.agent) ? event.actor.agent : labelNodes.has(event.subject.initiative) ? event.subject.initiative : labelNodes.has(event.subject.repo) ? event.subject.repo : 'mission';
    // A stationary cue accompanies every event, including filtered feed rows.
    staticFlash(id);
    if (!available || forcePoster || !getState().motion || document.hidden || !visible) return;
    const from=nodes.get(id)?.position.clone()||new THREE.Vector3();
    const to=nodes.get(event.subject.initiative)?.position.clone()||new THREE.Vector3();
    const wave=['deploy','release','ticket','owner','system'].includes(event.kind);
    const mesh=new THREE.Mesh(wave?new THREE.RingGeometry(.23,.25,64):new THREE.SphereGeometry(event.kind==='chat'?.075:.05,8,8),new THREE.MeshBasicMaterial({color:KINDS[event.kind].color,transparent:true,opacity:.9,side:THREE.DoubleSide,depthWrite:false}));
    mesh.position.copy(wave?to:from);if(wave)mesh.rotation.x=-Math.PI/2;
    world.add(mesh);
    if(event.kind==='chat'){from.copy(nodes.get('harness').position);to.copy(nodes.get(event.actor.agent)?.position||nodes.get('mission').position);}
    pulses.push({mesh,kind:wave?'wave':event.kind==='push'?'ring':'travel',from,to,age:0,duration:wave?1.5:1.15,angle:Math.atan2(from.z,from.x)});
    if(pulses.length>32)disposePulse(pulses.shift());
    start();
  }
  // Controls remain functional even if the renderer never initializes.
  subscribe((next,reason)=>{
    if(reason==='event')eventPulse(next.events[0]);
    if(reason==='motion'){
      pulses.forEach(disposePulse);pulses=[];
      stop();start();
    }
    if(reason==='highlight'||reason==='selection'){
      labelNodes.forEach(({label},id)=>label.classList.toggle('active',next.highlight===id||next.selection?.id===id));start();
    }
    if(reason==='fallback'){
      forcePoster=next.fallback;
      if(forcePoster)fallback();
      else if(renderer&&!renderer.getContext().isContextLost()){
        available=true;renderer.domElement.hidden=false;poster.classList.add('webgl-active');mode.textContent='SPATIAL VIEW';size();start();
      }
    }
    if(reason==='tab')requestAnimationFrame(()=>{size();start();});
  });
  document.getElementById('scene-reset').addEventListener('click',()=>{targetYaw=0;targetTilt=0;if(!getState().motion){yaw=0;tilt=0;}start();});
  stage.addEventListener('pointerdown',event=>{
    if(event.target.closest('button'))return;
    dragging=true;pointerStart={x:event.clientX,y:event.clientY,yaw:targetYaw,tilt:targetTilt,moved:false};stage.setPointerCapture(event.pointerId);
  });
  stage.addEventListener('pointermove',event=>{
    if(!dragging||!pointerStart||!available)return;
    const dx=event.clientX-pointerStart.x,dy=event.clientY-pointerStart.y;
    pointerStart.moved=Math.abs(dx)+Math.abs(dy)>5;
    targetYaw=Math.max(-.45,Math.min(.45,pointerStart.yaw+dx*.0025));
    targetTilt=Math.max(-.15,Math.min(.15,pointerStart.tilt+dy*.0015));
    if(!getState().motion){yaw=targetYaw;tilt=targetTilt;}
    start();
  });
  const release=()=>{dragging=false;pointerStart=null;};stage.addEventListener('pointerup',release);stage.addEventListener('pointercancel',release);
  const observer=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;if(visible){size();start();}else stop();});observer.observe(stage);
  new ResizeObserver(size).observe(stage);
  window.addEventListener('resize',size);
  window.addEventListener('scroll',()=>{size();start();},{passive:true});
  document.addEventListener('visibilitychange',()=>{if(document.hidden)stop();else{size();start();}});
  window.addEventListener('pageshow',event=>{if(event.persisted){size();start();}});
  try {
    THREE=await import('../vendor/three.module.min.js');
    renderer=new THREE.WebGLRenderer({alpha:true,antialias:window.innerWidth>=768,powerPreference:'low-power'});
    renderer.setClearColor(0x000000,0);
    renderer.debug.onShaderError=()=>fallback('SHADER FALLBACK');
    document.getElementById('scene-layer').append(renderer.domElement);
    camera=new THREE.PerspectiveCamera(30,1,.1,80);camera.position.set(.2,5.8,8.2);camera.lookAt(0,0,0);
    // The shared rAF timestamp is the only scene clock (no per-object timers).
    build();available=true;
    renderer.domElement.addEventListener('webglcontextlost',event=>{event.preventDefault();fallback('CONTEXT LOST · STATIC');});
    renderer.domElement.addEventListener('webglcontextrestored',()=>{if(!forcePoster){available=true;renderer.domElement.hidden=false;poster.classList.add('webgl-active');mode.textContent='SPATIAL VIEW';size();start();}});
    if(forcePoster)fallback();else{poster.classList.add('webgl-active');size();start();}
  } catch { fallback('STATIC VIEW'); }
}
