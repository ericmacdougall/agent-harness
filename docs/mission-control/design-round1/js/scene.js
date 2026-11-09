import { getState, subscribe, select, highlight, KINDS } from './store.js';
import { button, el } from './ui.js';

// One canvas, one animation clock. HTML buttons mirror every meaningful node.
export async function mountScene() {
  const stage = document.getElementById('scene-stage');
  const labels = document.getElementById('scene-labels');
  const poster = document.getElementById('scene-poster');
  const mode = document.getElementById('scene-mode');
  const state = getState(), nodes = new Map(), labelNodes = new Map();
  const names = ['Mission control','Event stream','Sessions','Release path','Tickets','Mobile runner','WAL collectors'];
  const positions = [[0,.45,0],[-2.65,.65,-1.5],[2.65,.1,-1.8],[2.7,-.3,1.55],[-2.8,.05,1.6],[-.15,.5,-3],[.4,-.35,2.8]];
  const staticPositions = [[50,50],[26,28],[74,28],[77,73],[24,73],[47,12],[52,89]];
  let THREE, renderer, camera, world;
  let available = false, visible = true, frame = 0, lastFrame = -Infinity, elapsed = 0, lastTime = 0;
  let yaw = 0, targetYaw = 0, tilt = 0, targetTilt = 0, dragging = false, pointerStart = null;
  let stageRect, pulses = [], forcePoster = state.fallback, flashTimers = new Map();
  let renderWidth = 0, renderHeight = 0, renderRatio = 0;
  const layers = [], currents = [], packets = [];
  let hoverX = 0, hoverY = 0, parallaxX = 0, parallaxY = 0;
  function addLabel(id, name, kind, index, extraClass = '') {
    const label = button(`node-label ${extraClass}`, name, event => {
      if (pointerStart?.moved) return;
      event.stopPropagation();
      select(kind, id);
    });
    label.replaceChildren(el('span', 'node-full', name), el('span', 'node-short', kind === 'initiative' ? (index === 0 ? 'Mission' : name.split(' ')[0]) : name));
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
      else if (kind === 'owner') { const a = index / state.owners.length * Math.PI * 2; x = 50 + Math.cos(a) * 36; y = 50 + Math.sin(a) * 34; }
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
    // The phone's single core label is also its static event cue.
    const item = labelNodes.get(window.innerWidth < 768 ? 'mission' : id) || labelNodes.get('mission');
    if (!item) return;
    const key = item.label.dataset.nodeId;
    clearTimeout(flashTimers.get(key));
    item.label.classList.add('static-flash');
    flashTimers.set(key, setTimeout(() => { item.label.classList.remove('static-flash'); flashTimers.delete(key); }, 650));
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
    camera.fov = width < 768 ? 26 : 30;
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
  function glow(color, radius = .55, opacity = .6) {
    // A procedural billboard: soft falloff, no bitmap, postprocessing or extra clock.
    const material = new THREE.ShaderMaterial({
      uniforms: { tint: { value: new THREE.Color(color) }, strength: { value: opacity } },
      vertexShader: 'varying vec2 vUv; varying float vDepth; void main(){vUv=uv; vec4 p=modelViewMatrix*vec4(0.,0.,0.,1.); vDepth=-p.z; p.xy+=position.xy; gl_Position=projectionMatrix*p;}',
      fragmentShader: 'uniform vec3 tint; uniform float strength; varying vec2 vUv; varying float vDepth; void main(){float r=length(vUv-.5)*2.; float a=pow(max(0.,1.-r),3.)*strength*(1.-smoothstep(8.,18.,vDepth)); gl_FragColor=vec4(tint,a);}',
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    });
    return new THREE.Mesh(new THREE.PlaneGeometry(radius*2,radius*2),material);
  }
  function spark(color, radius = .07) {
    const group = new THREE.Group();
    group.add(new THREE.Mesh(new THREE.SphereGeometry(radius,8,8),new THREE.MeshBasicMaterial({color,transparent:true,opacity:.95,depthWrite:false})));
    group.add(glow(color,radius*5,.85));
    return group;
  }
  function build() {
    world = new THREE.Group();
    const scene = new THREE.Scene(); scene.add(world);
    scene.fog = new THREE.Fog('#000000',8,18);
    scene.add(new THREE.AmbientLight('#b4c6ab', 2));
    const key = new THREE.DirectionalLight('#edffd4', 5); key.position.set(2,5,4); scene.add(key);
    const rim = new THREE.PointLight('#d8eaff', 35, 15); rim.position.set(-4,3,-2); scene.add(rim);
    renderer.scene = scene;
    // Nested silver orbits, offset just enough to suggest depth.
    [3.55,4.3,4.8].forEach((radius, i) => {
      const orbit = line(arc(radius), i === 1 ? '#d2dfb8' : '#a1b2a3', i === 1 ? .24 : .13);
      orbit.rotation.x = (i-1) * .22; orbit.rotation.z = (i-1) * .16;
      orbit.position.y = (i-1)*.32;
    });
    const current = new THREE.CatmullRomCurve3([new THREE.Vector3(-5,-.4,2),new THREE.Vector3(...positions[1]),new THREE.Vector3(...positions[0]),new THREE.Vector3(...positions[3]),new THREE.Vector3(5,.2,-2)]);
    currents.push(current);
    line(current.getPoints(180), '#eaff9e', .72);
    line(current.getPoints(180).map(p => p.clone().add(new THREE.Vector3(0,-.06,.08))), '#eaff9e', .18);
    [-1.8,1.1].forEach((height, layerIndex) => {
      const stars=[];
      for(let i=0;i<65;i++){const a=i*2.39996,r=1.5+(i%23)/23*5.3;stars.push(Math.cos(a)*r,height+Math.sin(i*7.7)*.6,Math.sin(a)*r);}
      const geometry=new THREE.BufferGeometry();geometry.setAttribute('position',new THREE.Float32BufferAttribute(stars,3));
      const layer=new THREE.Points(geometry,new THREE.PointsMaterial({color:'#b5c29d',size:layerIndex?.025:.016,transparent:true,opacity:layerIndex?.4:.22,depthWrite:false}));
      world.add(layer);layers.push(layer);
    });
    state.initiatives.forEach((item, i) => {
      const position = new THREE.Vector3(...positions[i]);
      const core = new THREE.Group(); core.position.copy(position); world.add(core);
      const radius = i === 0 ? .27 : .15;
      const material = new THREE.MeshPhysicalMaterial({color:i === 0 ? '#eaff9e' : '#d5e4bc',metalness:.8,roughness:.24,clearcoat:1,emissive:'#a1c750',emissiveIntensity:i === 0 ? .16 : .06});
      const sphere = new THREE.Mesh(new THREE.IcosahedronGeometry(radius,2),material); core.add(sphere);
      core.add(glow('#eaff9e',i===0?.85:.55,i===0?.8:.5));
      const cage = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(radius*1.3,0)),new THREE.LineBasicMaterial({color:'#eaff9e',transparent:true,opacity:.35})); core.add(cage);
      const ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(arc(radius*2.4)),new THREE.LineBasicMaterial({color:'#66764c',transparent:true,opacity:.4})); core.add(ring);
      if (item.pct !== null) { const fill = new THREE.Line(new THREE.BufferGeometry().setFromPoints(arc(radius*2.4,0,item.pct/100*Math.PI*2,.015)),new THREE.LineBasicMaterial({color:'#eaff9e',transparent:true,opacity:.9})); core.add(fill); }
      if (i > 0) {
        const curve = new THREE.QuadraticBezierCurve3(position,new THREE.Vector3(position.x*.5,.6,position.z*.2),new THREE.Vector3(...positions[0]));
        line(curve.getPoints(70),'#b4c88c',.28);
        currents.push(curve);
      }
      nodes.set(item.id,{core,position,sphere,kind:'initiative'});
    });
    state.owners.forEach((owner,i) => {
      const parent = nodes.get(owner.initiative_id), a = i*1.7;
      const position = parent.position.clone().add(new THREE.Vector3(Math.cos(a)*.85,.35,Math.sin(a)*.75));
      const core = new THREE.Group(); core.position.copy(position); world.add(core);
      const sphere = new THREE.Mesh(new THREE.OctahedronGeometry(.055),new THREE.MeshBasicMaterial({color:['DROPPED','SILENT'].includes(owner.state) ? '#f1a6a6' : '#cad9dc'})); core.add(sphere);
      line([parent.position,position],'#b5cad6',.24);
      nodes.set(owner.agent_id,{core,position,sphere,kind:'owner',parent:owner.initiative_id});
    });
    ['harness','t2-dev','collectors'].forEach((repo,i) => {
      const a = i/3*Math.PI*2+.3, position = new THREE.Vector3(Math.cos(a)*4.4,0,Math.sin(a)*4.4);
      const core = new THREE.Group();core.position.copy(position);world.add(core);
      const sphere = new THREE.Mesh(new THREE.BoxGeometry(.09,.09,.09),new THREE.MeshBasicMaterial({color:'#97a6ad'})); core.add(sphere);
      nodes.set(repo,{core,position,sphere,kind:'repo'});
    });
    currents.forEach((curve,i)=>{
      const count=i===0?5:1;
      for(let n=0;n<count;n++){
        const mesh=spark('#eaff9e',i===0?.045:.032);
        world.add(mesh);packets.push({mesh,curve,phase:n/count+i*.13,speed:i===0?.065:.1});
      }
    });
  }
  const pointCache = { value: null };
  function projectLabels() {
    if (!camera || !stageRect) return;
    const v = pointCache.value ||= new THREE.Vector3();
    for (const [id, {label,kind}] of labelNodes) {
      if (window.innerWidth < 768 && id !== 'mission') continue;
      const node = nodes.get(id); if (!node) continue;
      node.core.getWorldPosition(v); v.project(camera);
      const x = (v.x*.5+.5)*window.innerWidth-stageRect.left;
      const y = (-v.y*.5+.5)*window.innerHeight-stageRect.top + (kind === 'owner' ? 0 : kind === 'repo' ? 17 : 22);
      const half = label.offsetWidth/2+6, halfHeight = label.offsetHeight/2+6;
      label.style.left = `${Math.max(half,Math.min(stageRect.width-half,x))}px`;
      label.style.top = `${Math.max(halfHeight,Math.min(stageRect.height-halfHeight,y))}px`;
    }
  }
  function renderOnce() {
    if (!available || forcePoster || !visible || document.hidden) return;
    try {
      // Keep the short phone band self-contained, even during drag and parallax.
      renderer.setScissorTest(false); renderer.clear();
      renderer.setScissor(stageRect.left,window.innerHeight-stageRect.bottom,stageRect.width,stageRect.height);
      renderer.setScissorTest(true); renderer.render(renderer.scene,camera);
      if (available && !forcePoster) projectLabels();
    }
    catch { fallback('RENDER FALLBACK'); }
  }
  function disposePulse(pulse) { world.remove(pulse.mesh);pulse.mesh.traverse(object=>{object.geometry?.dispose();object.material?.dispose();}); }
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
      parallaxX = moving ? parallaxX+(hoverX-parallaxX)*.07 : 0;
      parallaxY = moving ? parallaxY+(hoverY-parallaxY)*.07 : 0;
      world.rotation.y = yaw + (moving ? Math.sin(elapsed*.09)*.09+parallaxX*.055 : 0);
      world.rotation.x = -.12+tilt+parallaxY*.025;
      world.rotation.z = -.065;
      layers.forEach((layer,i)=>{layer.rotation.y=moving?Math.sin(elapsed*.035+i)*.045+parallaxX*(i?-.035:.04):0;layer.position.x=parallaxX*(i?.12:-.15);});
      packets.forEach(packet=>{packet.mesh.visible=moving;packet.mesh.position.copy(packet.curve.getPoint((packet.phase+elapsed*packet.speed)%1));});
      for (const [id,node] of nodes) {
        const lit = getState().highlight === id || getState().selection?.id === id;
        node.sphere.scale.setScalar(lit ? 1.35 : 1);
        labelNodes.get(id)?.label.classList.toggle('active',lit);
      }
      for (let i=pulses.length-1;i>=0;i--) {
        const pulse = pulses[i]; pulse.age += dt;
        pulse.mesh.visible = pulse.age >= 0;
        if(pulse.age<0)continue;
        const t = pulse.age/pulse.duration;
        if (t>=1 || !moving) { disposePulse(pulse);pulses.splice(i,1);continue; }
        if (pulse.kind === 'wave') { pulse.mesh.scale.setScalar(.3+t*4);pulse.mesh.material.opacity=(1-t)*.7; }
        else pulse.mesh.position.copy(pulse.curve.getPoint(t));
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
    const to=nodes.get(event.subject.initiative)?.position.clone()||nodes.get('mission').position.clone();
    if(['chat','push','system'].includes(event.kind))from.copy(nodes.get(event.subject.repo)?.position||nodes.get('harness').position);
    if(from.distanceTo(to)<.1)from.copy(nodes.get('harness').position);
    let curve;
    if(event.kind==='push'){
      const angle=Math.atan2(from.z,from.x);
      curve=new THREE.CatmullRomCurve3([from,...arc(4.3,angle,.9,0,16),to]);
    }else curve=new THREE.QuadraticBezierCurve3(from,from.clone().lerp(to,.5).add(new THREE.Vector3(0,.7,0)),to);
    const mesh=spark(KINDS[event.kind].color,.095);mesh.position.copy(from);world.add(mesh);
    pulses.push({mesh,kind:'travel',curve,age:0,duration:1.45});
    const wave=new THREE.Mesh(new THREE.RingGeometry(.2,.225,48),new THREE.MeshBasicMaterial({color:KINDS[event.kind].color,transparent:true,opacity:.7,side:THREE.DoubleSide,depthWrite:false}));
    wave.position.copy(to);wave.rotation.x=-Math.PI/2;wave.visible=false;world.add(wave);
    pulses.push({mesh:wave,kind:'wave',age:-1.45,duration:.9});
    while(pulses.length>32)disposePulse(pulses.shift());
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
  document.getElementById('scene-reset').addEventListener('click',()=>{targetYaw=0;targetTilt=0;hoverX=hoverY=0;if(!getState().motion){yaw=0;tilt=0;}start();});
  stage.addEventListener('pointerdown',event=>{
    if(event.target.closest('button'))return;
    dragging=true;pointerStart={x:event.clientX,y:event.clientY,yaw:targetYaw,tilt:targetTilt,moved:false};stage.setPointerCapture(event.pointerId);
  });
  stage.addEventListener('pointermove',event=>{
    if(event.pointerType==='mouse'&&stageRect){hoverX=(event.clientX-stageRect.left)/stageRect.width*2-1;hoverY=(event.clientY-stageRect.top)/stageRect.height*2-1;}
    if(!dragging||!pointerStart||!available)return;
    const dx=event.clientX-pointerStart.x,dy=event.clientY-pointerStart.y;
    pointerStart.moved=Math.abs(dx)+Math.abs(dy)>5;
    targetYaw=Math.max(-.45,Math.min(.45,pointerStart.yaw+dx*.0025));
    targetTilt=Math.max(-.15,Math.min(.15,pointerStart.tilt+dy*.0015));
    if(!getState().motion){yaw=targetYaw;tilt=targetTilt;}
    start();
  });
  stage.addEventListener('pointerleave',()=>{hoverX=hoverY=0;});
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
    camera=new THREE.PerspectiveCamera(30,1,.1,80);camera.position.set(.3,5.7,9);camera.lookAt(0,0,0);
    // The shared rAF timestamp is the only scene clock (no per-object timers).
    build();available=true;
    renderer.domElement.addEventListener('webglcontextlost',event=>{event.preventDefault();fallback('CONTEXT LOST · STATIC');});
    renderer.domElement.addEventListener('webglcontextrestored',()=>{if(!forcePoster){available=true;renderer.domElement.hidden=false;poster.classList.add('webgl-active');mode.textContent='SPATIAL VIEW';size();start();}});
    if(forcePoster)fallback();else{poster.classList.add('webgl-active');size();start();}
  } catch { fallback('STATIC VIEW'); }
}
