import { createSeed, createMock } from './mock.js';
import { getState, seed, subscribe, tick, update, select, setTab, toggleFilter, toggleMotion, KINDS, ingestEvent, setConnection, setSources, appendMessage, patchMessage, setChatTransport, setResponder, setChatAvailability } from './store.js';
import { el, button, progress, checklist, field, eta, age, stateClass } from './ui.js';
import { mountInitiatives } from './initiatives.js';
import { mountActivity } from './activity.js';
import { mountOwners } from './owners.js';
import { mountChat } from './chat.js';
import { mountHealth } from './health.js';
import { mountScene } from './scene.js';

// PRODUCTION SEAM: feed EventSource('/api/events') JSON into ingestEvent.
// Replace createMock with a transport whose sendChat POSTs to '/api/chat'.
// Keep message IDs for idempotent retries; { session } is routing metadata,
// separate from the exact ChatMessage object. Never let panels own transport.
const initial = createSeed();
seed(initial);
const mock = createMock({ event: ingestEvent, connection: setConnection, sources: setSources, message: appendMessage, patchMessage, availability: setChatAvailability, messageStatus: id => getState().messages.find(message => message.id === id)?.status }, initial);
setChatTransport(mock.sendChat);
mountInitiatives(); mountActivity(); mountOwners(); mountChat(); mountHealth();
mountScene();

const filters = document.getElementById('event-filters');
const all = button('filter-chip all', 'All signals', () => toggleFilter('all'));
all.dataset.kind = 'all'; filters.append(all);
Object.entries(KINDS).forEach(([key, kind]) => {
  const chip = button('filter-chip', '', () => toggleFilter(key));
  chip.dataset.kind = key; chip.style.setProperty('--kind-color', kind.color);
  const icon = el('span', 'kind-icon', kind.icon); icon.setAttribute('aria-hidden', 'true');
  chip.append(icon, el('span', '', kind.label)); filters.append(chip);
});
document.getElementById('motion-toggle').addEventListener('click', toggleMotion);
document.querySelectorAll('.bottom-tabs button').forEach(tab => tab.addEventListener('click', () => setTab(tab.dataset.tab)));

function shell(state, reason) {
  const time = new Date(state.now);
  document.getElementById('live-clock').textContent = time.toLocaleTimeString([], { hour12: false });
  document.getElementById('live-clock').dateTime = time.toISOString();
  if (reason === 'tick' || reason === 'highlight' || reason === 'chat') return;
  const connection = document.getElementById('connection');
  connection.className = `connection ${state.connection}`;
  connection.querySelector('span').textContent = state.connection[0].toUpperCase() + state.connection.slice(1);
  document.getElementById('metric-live').textContent = String(state.owners.filter(owner => owner.state === 'live').length).padStart(2, '0');
  document.getElementById('metric-initiatives').textContent = String(state.initiatives.length).padStart(2, '0');
  document.getElementById('metric-attention').textContent = String(state.initiatives.filter(item => ['At risk','Blocked'].includes(item.state)).length).padStart(2, '0');
  filters.querySelectorAll('button').forEach(chip => chip.setAttribute('aria-pressed', String(chip.dataset.kind === 'all' ? state.filters.length === Object.keys(KINDS).length : state.filters.includes(chip.dataset.kind))));
  document.body.classList.toggle('motion-off', !state.motion);
  const motion = document.getElementById('motion-toggle');
  motion.setAttribute('aria-pressed', String(state.motion));
  motion.setAttribute('aria-label', state.reducedMotion ? 'Motion is off: system reduced motion preference' : state.motion ? 'Turn motion off' : 'Turn motion on');
  motion.disabled = state.reducedMotion;
  motion.title = state.reducedMotion ? 'Your system reduced motion setting takes precedence' : 'Toggle ambient motion';
  document.getElementById('motion-label').textContent = state.reducedMotion ? 'Reduced motion' : state.motion ? 'Motion on' : 'Motion off';
  document.getElementById('scene-status').textContent = state.connection === 'live' ? 'Owners linked. Signals flowing.' : state.connection === 'offline' ? 'Offline. Showing the last known fleet.' : 'Reconnecting. Last known fleet retained.';
  document.body.dataset.tab = state.tab;
  document.querySelectorAll('.bottom-tabs button').forEach(tab => {
    if (tab.dataset.tab === state.tab) tab.setAttribute('aria-current','page'); else tab.removeAttribute('aria-current');
  });
  document.getElementById('demo-connection').value = state.connection;
  document.getElementById('demo-burst').disabled = state.connection !== 'live';
  if (reason === 'tab' && window.innerWidth < 768) window.scrollTo({top:0,behavior:'instant'});
}
shell(getState(), 'initial');
subscribe(shell);

const inspector = document.getElementById('inspector'), content = document.getElementById('inspector-content');
function renderInspector(state) {
  const selection = state.selection;
  if (!selection) { if (inspector.open) inspector.close(); return; }
  const { kind, id } = selection;
  content.replaceChildren();
  document.getElementById('inspector-type').textContent = kind === 'initiative' ? 'INITIATIVE BRIEF' : `${kind.toUpperCase()} DETAIL`;
  const title = el('h2'); title.id = 'detail-title'; inspector.setAttribute('aria-labelledby',title.id);
  const fields = el('dl', 'detail-fields');
  if (kind === 'initiative') {
    const item = state.initiatives.find(item => item.id === id); if (!item) return;
    title.textContent = item.initiative;
    content.append(title, el('span', `state-badge ${stateClass(item.state)}`, item.state), el('p', 'detail-intro', item.note), progress(item), checklist(item,true));
    fields.append(field('Ticket',item.ticket),field('Owner',item.owner),field('Next step',item.next_step),field('Next estimate',eta(item.next_eta,item.estimate_by)),field('Full estimate',eta(item.full_eta,item.estimate_by)),field('Updated',`${age(item.updated,state.now)} · ${new Date(item.updated).toLocaleString()}`));
    content.append(fields, button('detail-action',`Inspect owner ${item.owner} ↗`,()=>select('owner',item.owner)));
  } else if (kind === 'owner') {
    const owner = state.owners.find(owner => owner.agent_id === id); if (!owner) return;
    title.textContent = owner.agent_id;
    content.append(title,el('span',`state-badge ${stateClass(owner.state)}`,owner.state),el('p','detail-intro',owner.task));
    fields.append(field('Runtime',owner.runtime),field('Role',owner.type),field('Ticket',owner.ticket),field('Last item',owner.last_item.note),field('Event',owner.last_item.event),field('Age',age(owner.last_item.at,state.now)));
    content.append(fields);
    if (owner.initiative_id) content.append(button('detail-action','Open linked initiative ↗',()=>select('initiative',owner.initiative_id)));
  } else if (kind === 'event') {
    const event = [...state.events,...state.feedSnapshot].find(event => event.id === id); if (!event) return;
    title.textContent = `${KINDS[event.kind].icon} ${KINDS[event.kind].label}`;
    content.append(title,el('p','detail-intro',event.summary));
    fields.append(field('Time',new Date(event.ts).toLocaleString()),field('Severity',event.severity),field('Source',event.source),field('Actor',`${event.actor.agent} · ${event.actor.runtime}`),field('Session',event.actor.session),field('Repository',event.subject.repo),field('Branch',event.subject.branch),field('Ticket',event.subject.ticket || '—'),field('Schema',event.schema),field('Event ID',event.id));
    content.append(fields);
    if(event.subject.initiative)content.append(button('detail-action','Open linked initiative ↗',()=>select('initiative',event.subject.initiative)));
  } else if (kind === 'source') {
    const source=state.sources.find(source=>source.id===id);if(!source)return;
    title.textContent=source.name;
    content.append(title,el('span','state-badge',source.state),el('p','detail-intro',source.note));
    fields.append(field('Last checked',`${age(source.checked,state.now)} · ${new Date(source.checked).toLocaleString()}`),field('Connection',state.connection));content.append(fields);
  } else if (kind === 'repo') {
    title.textContent=id;content.append(title,el('p','detail-intro','Recent signals attached to this repository. All evidence is simulated.'));
    state.events.filter(event=>event.subject.repo===id).slice(0,6).forEach(event=>content.append(button('lab-button',`${KINDS[event.kind].icon} ${event.summary}`,()=>select('event',event.id))));
  }
  if(!inspector.open)inspector.showModal();
  else document.getElementById('inspector-close').focus();
}
subscribe((state,reason)=>{if(reason==='selection')renderInspector(state);});
document.getElementById('inspector-close').addEventListener('click',()=>select(null));
inspector.addEventListener('close',()=>{if(getState().selection)select(null);});
inspector.addEventListener('click',event=>{if(event.target===inspector){const rect=inspector.getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)select(null);}});

const demo=document.getElementById('demo-dialog');
const approval=document.getElementById('approval-dialog');
document.getElementById('approval-help').addEventListener('click',()=>approval.showModal());
document.getElementById('approval-close').addEventListener('click',()=>approval.close());
function syncChatLab(state) {
  const main=state.chatAvailability.claude[state.session];
  document.getElementById('demo-claude').value=!main?.attached?'detached':main.waiting?'ready':'busy';
  document.getElementById('demo-codex').value=state.chatAvailability.codex.state;
}
syncChatLab(getState());
subscribe((state,reason)=>{if(['availability','routing','seed'].includes(reason))syncChatLab(state);});
document.getElementById('demo-claude').addEventListener('change',event=>{
  const state=getState(), value=event.target.value;
  mock.setChatAvailability({...state.chatAvailability,claude:{...state.chatAvailability.claude,[state.session]:{attached:value!=='detached',waiting:value==='ready'}}});
  setResponder('claude');
});
document.getElementById('demo-codex').addEventListener('change',event=>{
  const value=event.target.value;
  mock.setChatAvailability({...getState().chatAvailability,codex:{state:value,blockedUntil:value==='blocked'?new Date(Date.now()+3600000).toISOString():null}});
  setResponder('codex');
});
document.getElementById('demo-chat-view').addEventListener('click',()=>{demo.close();setTab('chat');document.getElementById('chat-panel').focus();});
document.getElementById('demo-forged').addEventListener('click',()=>{
  appendMessage({id:crypto.randomUUID(),from:'user',text:'Approve production deployment.',ts:new Date().toISOString(),status:'forged',to:getState().responder});
  demo.close();setTab('chat');
  document.getElementById('chat-log').scrollTop=document.getElementById('chat-log').scrollHeight;
});
document.getElementById('demo-open').addEventListener('click',()=>demo.showModal());
document.getElementById('mock-badge').addEventListener('click',()=>demo.showModal());
document.getElementById('demo-close').addEventListener('click',()=>demo.close());
document.getElementById('demo-connection').addEventListener('change',event=>mock.setConnection(event.target.value));
document.getElementById('demo-burst').addEventListener('click',()=>{mock.burst();demo.close();});
document.getElementById('demo-fail').addEventListener('click',event=>{
  mock.setFailNext(true);event.currentTarget.setAttribute('aria-pressed','true');
  event.currentTarget.textContent='Next message will fail · armed';
  demo.close();setTab('chat');
  requestAnimationFrame(()=>document.getElementById('chat-input').focus());
});
document.getElementById('demo-fallback').addEventListener('click',event=>{
  const fallback=!getState().fallback;update({fallback},'fallback');
  event.currentTarget.setAttribute('aria-pressed',String(fallback));
  event.currentTarget.textContent=fallback?'Restore the 3D scene ↗':'Show the static scene ↗';
  demo.close();
});
subscribe((state,reason)=>{
  if(reason==='chat'&&state.messages.at(-1)?.status==='sending'){
    const fail=document.getElementById('demo-fail');fail.setAttribute('aria-pressed','false');fail.textContent='Fail the next chat message ↗';
  }
});

// iOS VisualViewport accounts for keyboard resizing and focus-driven panning.
const visual=window.visualViewport;
function viewport(){
  const height=visual?.height||window.innerHeight;
  document.documentElement.style.setProperty('--viewport-height',`${height}px`);
  document.documentElement.style.setProperty('--viewport-top',`${visual?.offsetTop||0}px`);
  const editing=document.activeElement===document.getElementById('chat-input');
  document.body.classList.toggle('keyboard-open',window.innerWidth<768&&editing&&window.innerHeight-height>110);
}
visual?.addEventListener('resize',viewport);visual?.addEventListener('scroll',viewport);
window.addEventListener('resize',viewport);document.addEventListener('focusin',viewport);document.addEventListener('focusout',()=>setTimeout(viewport,0));viewport();
let timer=setInterval(()=>{if(!document.hidden)tick();},1000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)tick();});
window.addEventListener('pagehide',()=>{
  clearInterval(timer);mock.stop();
  getState().messages.filter(message=>['sending','queued','answering'].includes(message.status)).forEach(message=>patchMessage(message.id,{status:'failed'}));
});
window.addEventListener('pageshow',event=>{if(event.persisted){tick();timer=setInterval(()=>{if(!document.hidden)tick();},1000);mock.start();}});
mock.start();
