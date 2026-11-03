const sections = [
  ['profiles', 'Provider profiles'], ['defaults', 'Defaults'], ['ladders', 'Model & review ladders'],
  ['instructions', 'Instructions & memory'], ['hooks', 'Hooks'], ['environment', 'Agent environment'], ['goodqa', 'GoodQA'],
];
let context, snapshot, body;
let selectedSection = 'profiles';
let renderGeneration = 0;
let changed = false;

export async function openSettings(services) {
  const dialog = document.querySelector('#settings-dialog');
  let notice = dialog.querySelector('#settings-notice');
  if (!notice) {
    notice = services.el('p', 'settings-feedback');
    notice.id = 'settings-notice';
    notice.hidden = true;
    dialog.querySelector('#settings-content').before(notice);
  }
  context = { ...services, notify: (message, failure = false) => {
    notice.textContent = message;
    notice.classList.toggle('warning', failure);
    notice.setAttribute('role', failure ? 'alert' : 'status');
    notice.hidden = false;
    services.notify(message, failure);
  } };
  notice.hidden = true;
  if (!dialog.open) dialog.showModal();
  if (!dialog.dataset.closeGuard) {
    const permit = () => !changed || window.confirm('Discard unsaved Settings changes?');
    dialog.addEventListener('cancel', event => { if (!permit()) event.preventDefault(); });
    dialog.addEventListener('click', event => {
      const bounds = dialog.getBoundingClientRect();
      const outside = event.target === dialog && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom);
      if ((event.target.closest('[data-close]') || outside) && !permit()) { event.preventDefault(); event.stopImmediatePropagation(); }
    }, true);
    dialog.dataset.closeGuard = 'true';
  }
  dialog.onclose = () => {
    renderGeneration++;
    for (const input of dialog.querySelectorAll('[data-secret-input]')) input.value = '';
  };
  await reload();
}

async function reload() {
  const target = document.querySelector('#settings-content');
  target.replaceChildren(context.el('p', 'settings-loading', 'Reading local settings…'));
  try {
    snapshot = await context.api('/api/settings');
    changed = false;
    render();
  } catch (error) {
    const panel = context.el('div', 'settings-empty');
    panel.append(context.el('p', '', error.message || 'Settings could not be loaded.'), button('Try again', reload));
    target.replaceChildren(panel);
  }
}

function render() {
  renderGeneration++;
  const layout = context.el('div', 'settings-layout');
  const navigation = context.el('nav', 'settings-nav');
  navigation.setAttribute('aria-label', 'Settings sections');
  for (const [id, title] of sections) {
    const node = button(title, () => {
      if (changed && !window.confirm('Discard unsaved changes in this section?')) return;
      changed = false;
      selectedSection = id;
      render();
    }, '');
    node.setAttribute('aria-current', selectedSection === id ? 'page' : 'false');
    node.setAttribute('aria-selected', String(selectedSection === id));
    navigation.append(node);
  }
  body = context.el('section', 'settings-section');
  body.dataset.settingsSection = selectedSection;
  body.addEventListener('input', () => { changed = true; });
  body.addEventListener('change', () => { changed = true; });
  layout.append(navigation, body);
  document.querySelector('#settings-content').replaceChildren(layout);
  ({ profiles, defaults, ladders, instructions, hooks, environment, goodqa })[selectedSection]();
}

function heading(title, text) {
  body.append(context.el('h3', '', title), context.el('p', 'settings-intro', text));
}
function button(label, action, className = 'quiet-button') {
  const node = context.el('button', className, label);
  node.type = 'button';
  node.addEventListener('click', async () => {
    node.disabled = true;
    try { await action(); }
    catch (error) { context.notify(error.message || 'Settings action failed.', true); }
    finally { if (node.isConnected) node.disabled = false; }
  });
  return node;
}
function card(title, detail, parent = body) {
  const node = context.el('div', 'settings-card');
  if (title) node.append(context.el('h4', '', title));
  if (detail) node.append(context.el('p', '', detail));
  parent.append(node);
  return node;
}
function field(parent, label, value = '', type = 'text') {
  const wrapper = context.el('label', 'settings-field');
  wrapper.append(context.el('span', 'field-label', label));
  const input = context.el(type === 'textarea' ? 'textarea' : 'input');
  if (type !== 'textarea') input.type = type;
  input.value = value ?? '';
  if (type === 'password') {
    input.autocomplete = 'new-password';
    input.spellcheck = false;
    input.dataset.secretInput = 'true';
  }
  wrapper.append(input);
  parent.append(wrapper);
  return input;
}
function select(parent, label, value, options) {
  const wrapper = context.el('label', 'settings-field');
  wrapper.append(context.el('span', 'field-label', label));
  const input = context.el('select');
  for (const option of options) {
    const [key, title] = Array.isArray(option) ? option : [option, option.replaceAll('_', ' ')];
    const node = context.el('option', '', title);
    node.value = key;
    input.append(node);
  }
  input.value = value || '';
  if (!value && input.selectedIndex < 0 && input.options.length) input.selectedIndex = 0;
  wrapper.append(input);
  parent.append(wrapper);
  return input;
}
function toggle(parent, label, checked, onChange = () => {}) {
  const wrapper = context.el('label', 'toggle-label');
  const input = context.el('input');
  input.type = 'checkbox'; input.checked = !!checked;
  input.addEventListener('change', () => onChange(input.checked));
  wrapper.append(input, document.createTextNode(label)); parent.append(wrapper);
  return input;
}
function status(parent, text, warning = false) {
  parent.append(context.el('p', `settings-status${warning ? ' warning' : ''}`, text));
}
function actions(parent, ...nodes) {
  const row = context.el('div', 'settings-actions'); row.append(...nodes); parent.append(row);
}
function settingsOnly() {
  const { schema, profiles, defaults, cascade, reviewLadder, environment, goodqa } = snapshot;
  return structuredClone({ schema, profiles, defaults, cascade, reviewLadder, environment, goodqa });
}
async function save(settings) {
  await context.api('/api/settings', { expectedRevision: snapshot.revision, settings });
  context.notify('Preferences saved. Authentication and harness readiness are shown separately.');
  await reload(); await context.refresh();
}
function profileOptions(provider, includeBlank = false) {
  return [...(includeBlank ? [['', 'Provider default profile']] : []), ...snapshot.profiles.filter(p => !provider || p.provider === provider).map(p => [p.id, `${p.name}${p.allowed ? '' : ' (disabled)'}`])];
}
function capabilityNotes(parent) {
  for (const cap of snapshot.capabilities || []) {
    if (!cap.available && cap.reason) status(parent, `${cap.name}: ${cap.reason}`, true);
  }
}

function profiles() {
  heading('Provider profiles', 'Keep separate signed-in accounts or API keys. Allowed profiles may be selected for new requests; rotation requires verified harness execution.');
  const vault = snapshot.vault;
  status(body, `Credential store: ${vault.backend || 'unavailable'} · ${vault.available ? 'available' : vault.reason || 'unavailable'}${vault.cleanupPending ? ` · ${vault.cleanupPending} retired credentials awaiting cleanup` : ''}`, !vault.available || !!vault.cleanupPending);
  capabilityNotes(body);
  for (const profile of snapshot.profiles) {
    const panel = card(profile.name, `${profile.provider} · ${profile.kind}`);
    status(panel, `Authentication: ${profile.auth.state} — ${profile.auth.reason || 'No additional details'}`, profile.auth.state !== 'signed_in');
    status(panel, `Harness: ${profile.harness.state} — ${profile.harness.reason || 'No additional details'}`, profile.harness.state !== 'ready');
    if (profile.auth.storage) status(panel, `Auth storage: ${profile.auth.storage}`);
    const name = field(panel, 'Display name', profile.name);
    const allowed = toggle(panel, 'Allowed for new requests', profile.allowed);
    const rotate = toggle(panel, 'Eligible for rotation', profile.rotate);
    if (profile.harness.state !== 'ready' && !profile.rotate) rotate.disabled = true;
    const saveProfile = button('Save profile', () => {
      const settings = settingsOnly();
      Object.assign(settings.profiles.find(p => p.id === profile.id), { name: name.value.trim(), allowed: allowed.checked, rotate: rotate.checked });
      return save(settings);
    }, 'primary-button');
    const controls = [saveProfile, button('Read actual usage', () => readUsage(profile, panel))];
    if (['device', 'subscription'].includes(profile.kind)) controls.push(button('Sign in', () => startLogin(profile, panel)));
    if (profile.kind !== 'global') controls.push(button('Delete profile', async () => {
      if (!window.confirm(`Delete ${profile.name}? Active sessions keep their existing binding; the server may refuse deletion while it is in use.`)) return;
      const settings = settingsOnly(); settings.profiles = settings.profiles.filter(p => p.id !== profile.id);
      await save(settings);
    }, 'danger-button'));
    actions(panel, ...controls);
    if (profile.kind === 'api_key') secretEditor(panel, profile.id, profile.generation, 'api_key', profile.apiKeyPresent, 'Provider API key');
  }
  const add = card('Add a profile');
  const name = field(add, 'Display name', '');
  const provider = select(add, 'Provider', 'codex', ['codex', 'claude']);
  const kind = select(add, 'Authentication', 'api_key', [['api_key', 'API key'], ['device', 'Codex device sign-in']]);
  provider.addEventListener('change', () => {
    kind.replaceChildren();
    for (const [value, label] of [['api_key', 'API key'], [provider.value === 'codex' ? 'device' : 'subscription', provider.value === 'codex' ? 'Codex device sign-in' : 'Claude subscription sign-in']]) {
      const option = context.el('option', '', label); option.value = value; kind.append(option);
    }
  });
  actions(add, button('Create profile', async () => {
    if (!name.value.trim()) throw new Error('Enter a display name.');
    const settings = settingsOnly();
    settings.profiles.push({ id: '', generation: '', name: name.value.trim(), provider: provider.value, kind: kind.value, allowed: true, rotate: false });
    await save(settings);
  }, 'primary-button'));
}

function secretEditor(parent, profileId, generation, name, present, label) {
  const area = context.el('div', 'secret-editor'); parent.append(area);
  status(area, `${label}: ${present ? 'stored (value is never returned)' : 'not stored'}`);
  const input = field(area, `New ${label.toLowerCase()}`, '', 'password');
  input.placeholder = present ? 'Leave blank to keep the existing value' : 'Enter a value to store securely';
  status(area, 'Sensitive values require at least 8 UTF-8 bytes. Ordinary short flags belong in explicitly non-sensitive environment entries.');
  const write = button('Store securely', async () => {
    const value = input.value;
    input.value = '';
    if (!value) throw new Error('Enter a nonempty value. Use Remove credential to delete.');
    if (new TextEncoder().encode(value).length < 8) throw new Error('Sensitive values require at least 8 UTF-8 bytes. Use an explicitly non-sensitive environment entry for an ordinary short flag.');
    const response = await context.api('/api/settings/secrets', { expectedRevision: snapshot.revision, profileId, profileGeneration: generation, name, value });
    snapshot.revision = response.revision;
    context.notify('Credential stored. Its value is not returned to this page.');
    changed = false;
    await reload();
  });
  write.disabled = !snapshot.vault.available;
  const remove = button('Remove credential', async () => {
    if (!window.confirm(`Remove the stored ${label.toLowerCase()}?`)) return;
    input.value = '';
    const response = await context.api('/api/settings/secrets', { expectedRevision: snapshot.revision, profileId, profileGeneration: generation, name, remove: true });
    snapshot.revision = response.revision; changed = false;
    await reload(); context.notify('Stored credential removed.');
  }, 'danger-button');
  remove.disabled = !present;
  actions(area, write, remove);
}

async function readUsage(profile, parent) {
  let output = parent.querySelector('.usage-result');
  if (!output) { output = context.el('div', 'usage-result'); parent.append(output); }
  output.replaceChildren(context.el('p', '', 'Reading provider telemetry…'));
  try {
    const result = await context.api(`/api/settings/usage?profileId=${encodeURIComponent(profile.id)}`);
    output.replaceChildren();
    status(output, `${result.source || 'Provider telemetry'} · checked ${result.checkedAt ? new Date(result.checkedAt).toLocaleString() : 'at unknown time'}`);
    if (!result.available) status(output, result.reason || 'Usage is unavailable. No balance is inferred.', true);
    for (const measurement of result.measurements || []) {
      status(output, `${measurement.name}: ${measurement.value} ${measurement.unit || ''}${measurement.limit === undefined ? '' : ` / ${measurement.limit}`}${measurement.resetsAt ? ` · resets ${new Date(measurement.resetsAt).toLocaleString()}` : ''}`);
    }
    if (result.available && !result.measurements?.length) status(output, 'No measurements were returned.');
  } catch (error) { output.replaceChildren(context.el('p', 'settings-status warning', error.message)); }
}

async function startLogin(profile, parent) {
  const result = await context.api('/api/settings/profiles/login', { expectedRevision: snapshot.revision, profileId: profile.id, profileGeneration: profile.generation });
  let output = parent.querySelector('.login-result');
  if (!output) { output = context.el('div', 'login-result'); parent.append(output); }
  const show = value => {
    output.replaceChildren();
    status(output, `Sign-in: ${value.state} · ${value.reason || ''}`);
    if (value.code) status(output, `Device code: ${value.code}`);
    if (value.url) {
      const url = new URL(value.url);
      if (url.protocol === 'https:') {
        const link = context.el('a', 'quiet-button', 'Open official sign-in page');
        link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; output.append(link);
      }
    }
    if (['running', 'awaiting_user'].includes(value.state)) output.append(button('Check sign-in status', async () => {
      const update = await context.api(`/api/settings/profiles/login?id=${encodeURIComponent(value.id)}`);
      show(update);
      if (update.state === 'complete') { changed = false; await reload(); }
    }));
  };
  show(result);
}

function defaults() {
  heading('Default behavior', 'Saved preferences apply to new console requests. Permissions in another app remain controlled by that app. Unsupported combinations are rejected by the backend.');
  const panel = card('Session defaults');
  const values = snapshot.defaults;
  const provider = select(panel, 'Provider', values.provider, ['codex', 'claude']);
  const profile = select(panel, 'Profile', values.profileId, profileOptions(values.provider));
  provider.addEventListener('change', () => {
    profile.replaceChildren(...profileOptions(provider.value).map(([value, title]) => { const option = context.el('option', '', title); option.value = value; return option; }));
  });
  const model = field(panel, 'Model', values.model); model.placeholder = 'Provider default';
  const effort = select(panel, 'Reasoning effort', values.effort, [['', 'Provider default'], 'low', 'medium', 'high', 'xhigh', 'max']);
  const tier = select(panel, 'Speed tier', values.serviceTier, [['normal', 'Normal (provider default)'], ['priority', 'Priority']]);
  const permissions = select(panel, 'Permission mode', values.permissions, [['full_access', 'Full access'], ['workspace_write', 'Workspace write'], ['read_only', 'Read only']]);
  const approval = select(panel, 'Approval policy', values.approvalPolicy, [['never', 'Never ask for local tool approval'], ['on_request', 'Ask when required']]);
  const harness = select(panel, 'Harness', values.harness, [['agent_harness', 'Agent Harness'], ['provider_default', 'Provider default']]);
  actions(panel, button('Save defaults', () => {
    const settings = settingsOnly();
    settings.defaults = { provider: provider.value, profileId: profile.value, model: model.value.trim(), effort: effort.value, serviceTier: tier.value, permissions: permissions.value, approvalPolicy: approval.value, harness: harness.value };
    return save(settings);
  }, 'primary-button'));
}

function ladders() {
  heading('Model and review ladders', 'Order is explicit. Routing applies to new stages and never replays an uncertain action. A saved stage still requires a usable, verified profile.');
  const settings = settingsOnly();
  function ladder(key, title) {
    const panel = card(title);
    const list = context.el('div', 'ladder-list'); panel.append(list);
    const draw = () => {
      list.replaceChildren();
      if (!settings[key].length) {
        status(list, key === 'reviewLadder' ? 'Use harness default — independent review remains enabled.' : 'No explicit cascade stages configured.');
        if (key === 'reviewLadder') {
          for (const [index, stage] of (snapshot.effectiveReviewLadder || []).entries()) {
            const profile = snapshot.profiles.find(item => item.id === stage.profileId);
            status(list, `${index + 1}. ${stage.provider} · ${stage.model || 'provider model'} · ${stage.effort || 'default effort'} · ${profile?.name || stage.profileId}`);
          }
          if (!snapshot.effectiveReviewLadder?.length) status(list, 'Effective default details have not been returned by this backend.', true);
        }
      }
      settings[key].forEach((stage, index) => {
        const row = card(`Stage ${index + 1}`, '', list);
        const provider = select(row, 'Provider', stage.provider, ['codex', 'claude']);
        const profile = select(row, 'Profile', stage.profileId, profileOptions(stage.provider));
        const model = field(row, 'Model', stage.model);
        const effort = select(row, 'Effort', stage.effort, [['', 'Provider default'], 'low', 'medium', 'high', 'xhigh', 'max']);
        provider.addEventListener('change', () => { stage.provider = provider.value; stage.profileId = profileOptions(provider.value)[0]?.[0] || ''; changed = true; draw(); });
        profile.addEventListener('change', () => { stage.profileId = profile.value; });
        model.addEventListener('input', () => { stage.model = model.value.trim(); });
        effort.addEventListener('change', () => { stage.effort = effort.value; });
        const up = button('Move up', () => { [settings[key][index - 1], settings[key][index]] = [stage, settings[key][index - 1]]; changed = true; draw(); }); up.disabled = index === 0;
        const down = button('Move down', () => { [settings[key][index + 1], settings[key][index]] = [stage, settings[key][index + 1]]; changed = true; draw(); }); down.disabled = index === settings[key].length - 1;
        actions(row, up, down, button('Remove stage', () => { settings[key].splice(index, 1); changed = true; draw(); }, 'danger-button'));
      });
    };
    draw();
    actions(panel, button('Add stage', () => { settings[key].push({ provider: 'codex', profileId: profileOptions('codex')[0]?.[0] || '', model: '', effort: 'high' }); changed = true; draw(); }));
  }
  ladder('cascade', 'Execution cascade'); ladder('reviewLadder', 'Cross-review ladder');
  actions(body, button('Save ladders', () => save(settings), 'primary-button'));
}

async function descriptors() {
  const cwd = context.cwd?.() || '';
  return context.api(`/api/settings/documents?cwd=${encodeURIComponent(cwd)}`);
}
async function instructions() {
  heading('Instructions and memory', 'Edit only discovered instruction files. Every change requires a digest-checked preview and explicit apply; a private backup is made by the backend.');
  const generation = renderGeneration;
  const loading = context.el('p', 'settings-loading', 'Discovering instruction documents…'); body.append(loading);
  try {
    const result = await descriptors();
    if (generation !== renderGeneration) return;
    loading.remove();
    if (!result.documents.length) status(body, 'No instruction documents are available for this working directory.');
    for (const item of result.documents) {
      const panel = card(item.kind, item.path);
      status(panel, item.exists ? 'Existing file' : 'File does not exist');
      if (!item.editable) status(panel, item.reason || 'This file is read-only.', true);
      panel.append(button(item.editable ? 'Open editor' : 'Read file', async () => {
        const doc = await context.api(`/api/settings/document?id=${encodeURIComponent(item.id)}`);
        if (!panel.isConnected) return;
        panel.querySelector('.document-editor')?.remove();
        const editor = context.el('div', 'document-editor'); panel.append(editor);
        const content = field(editor, 'File contents', doc.content, 'textarea'); content.spellcheck = false; content.rows = 14; content.readOnly = !doc.editable;
        if (doc.editable) editor.append(button('Preview change', async () => {
          const preview = await context.api('/api/settings/preview', { kind: 'document', id: doc.id, expectedDigest: doc.digest, content: content.value });
          previewApply(editor, preview);
        }, 'primary-button'));
      }));
    }
  } catch (error) { if (generation === renderGeneration) loading.replaceWith(context.el('p', 'settings-status warning', error.message)); }
}
function previewApply(parent, preview) {
  parent.querySelector('.settings-preview')?.remove();
  const panel = context.el('div', 'settings-preview'); parent.append(panel);
  status(panel, `Preview: ${preview.path}`);
  const summary = context.el('pre', '', typeof preview.summary === 'string' ? preview.summary : JSON.stringify(preview.summary, null, 2)); panel.append(summary);
  if (preview.expiresAt) status(panel, `Expires ${new Date(preview.expiresAt).toLocaleString()}`);
  panel.append(button('Apply this preview', async () => {
    const result = await context.api('/api/settings/apply', { previewId: preview.previewId });
    changed = false;
    context.notify(`Applied ${result.path}${result.backupCreated ? ' with a private backup.' : '.'}`);
    render();
  }, 'primary-button'));
}
async function hooks() {
  heading('Lifecycle hooks', 'Inspect discovered hooks before changing them. A toggle creates a preview; it does not change a hook until you apply the preview. Disabled integrations remain disabled.');
  const generation = renderGeneration;
  const loading = context.el('p', 'settings-loading', 'Reading hook descriptors…'); body.append(loading);
  try {
    const result = await descriptors();
    if (generation !== renderGeneration) return;
    loading.remove();
    if (!result.hooks.length) status(body, 'No supported hooks were discovered.');
    for (const hook of result.hooks) {
      const panel = card(hook.label || hook.event, `${hook.event} · ${hook.path}`);
      status(panel, `Trust: ${hook.trust}${hook.reason ? ` — ${hook.reason}` : ''}`, hook.trust !== 'verified');
      const enabled = toggle(panel, 'Enabled', hook.enabled);
      panel.append(button('Preview hook change', async () => {
        const preview = await context.api('/api/settings/preview', { kind: 'hook', id: hook.id, expectedDigest: hook.digest, enabled: enabled.checked });
        previewApply(panel, preview);
      }));
    }
  } catch (error) { if (generation === renderGeneration) loading.replaceWith(context.el('p', 'settings-status warning', error.message)); }
}

function sensitiveName(name) {
  return /TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|CREDENTIAL|PRIVATE_KEY|AUTH|COOKIE|DATABASE_URL|CONNECTION_STRING|DSN$/.test(name.toUpperCase());
}
function environment() {
  heading('Agent environment', 'Sensitive values use the OS credential vault and are never returned. Explicitly non-sensitive values are saved as plain settings and may be short flags such as 1. Changes apply to new requests.');
  for (const row of snapshot.environment) {
    const profile = snapshot.profiles.find(p => p.id === row.profileId);
    const panel = card(row.name, profile?.name || 'Unknown profile');
    const enabled = toggle(panel, 'Available to this profile', row.enabled);
    const wasSensitive = row.sensitive !== false;
    const sensitive = toggle(panel, 'Sensitive — store the value in the credential vault', wasSensitive);
    sensitive.disabled = sensitiveName(row.name);
    if (sensitive.disabled) status(panel, 'Credential-like names must remain sensitive.');
    const plain = field(panel, 'Non-sensitive plain value', wasSensitive ? '' : row.value || '');
    plain.closest('label').hidden = sensitive.checked;
    const storage = context.el('div'); panel.append(storage);
    if (wasSensitive && profile) secretEditor(storage, profile.id, profile.generation, row.name, row.present, row.name);
    else status(storage, 'Save sensitive mode first, then store a new value in the vault.');
    storage.hidden = !sensitive.checked;
    sensitive.addEventListener('change', () => {
      plain.value = '';
      plain.closest('label').hidden = sensitive.checked;
      storage.hidden = !sensitive.checked;
      if (!sensitive.checked && wasSensitive) plain.placeholder = 'Enter a new plain value; vault values are never copied here';
    });
    actions(panel, button('Save environment entry', () => {
      if (!sensitive.checked && wasSensitive && !plain.value) throw new Error('Enter a new non-sensitive value. The vault value cannot be migrated into plain settings.');
      const settings = settingsOnly();
      const target = settings.environment.find(item => item.id === row.id);
      Object.assign(target, { enabled: enabled.checked, sensitive: sensitive.checked });
      if (sensitive.checked) delete target.value;
      else target.value = plain.value;
      return save(settings);
    }), button('Remove environment entry', async () => {
      if (!window.confirm(`Remove ${row.name} from this profile?`)) return;
      const settings = settingsOnly(); settings.environment = settings.environment.filter(item => item.id !== row.id); await save(settings);
    }, 'danger-button'));
  }
  const panel = card('Add an environment variable');
  const profile = select(panel, 'Profile', '', profileOptions(null, false));
  const name = field(panel, 'Environment variable name'); name.placeholder = 'EXAMPLE_API_KEY';
  const sensitive = toggle(panel, 'Sensitive — store the value in the credential vault', true);
  const plain = field(panel, 'Non-sensitive plain value'); plain.closest('label').hidden = true;
  const guidance = context.el('p', 'settings-status'); panel.append(guidance);
  const updateMode = () => {
    const forced = sensitiveName(name.value);
    sensitive.disabled = forced;
    if (forced) { sensitive.checked = true; plain.value = ''; }
    plain.closest('label').hidden = sensitive.checked;
    guidance.textContent = forced ? 'This credential-like name must use sensitive storage.' : sensitive.checked ? 'Save the entry, then store its value securely. Sensitive values need at least 8 UTF-8 bytes.' : 'This value will be stored in plain settings. Use this only for non-secret flags and configuration.';
  };
  name.addEventListener('input', updateMode);
  sensitive.addEventListener('change', () => { if (sensitive.checked) plain.value = ''; updateMode(); });
  updateMode();
  actions(panel, button('Create environment entry', () => {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name.value)) throw new Error('Use uppercase letters, digits and underscores; start with a letter.');
    if (!profile.value) throw new Error('Select a profile.');
    const entry = { id: '', profileId: profile.value, name: name.value, enabled: true, present: false, sensitive: sensitive.checked };
    if (!sensitive.checked) entry.value = plain.value;
    const settings = settingsOnly(); settings.environment.push(entry); return save(settings);
  }, 'primary-button'));
}

function goodqa() {
  heading('GoodQA integration', 'Explicitly opt in to a saved endpoint. Probing discovers actual available tools and does not activate Hive or submit queued work.');
  const value = snapshot.goodqa;
  const panel = card('Connection');
  const enabled = toggle(panel, 'Enable GoodQA for this console', value.enabled);
  const endpoint = field(panel, 'MCP endpoint', value.endpoint, 'url');
  status(panel, 'Changing the endpoint retires its credential. Save the endpoint, then explicitly store a new credential for that destination.', true);
  const caps = {};
  for (const [key, title] of Object.entries({ desktop: 'Desktop control', browser: 'Browser', remote: 'Remote control', knowledge: 'Knowledge network', hive: 'Hive', tickets: 'Tickets', projects: 'Projects', decisions: 'Decision tracking' })) caps[key] = toggle(panel, title, value.capabilities[key]);
  actions(panel, button('Save integration preferences', () => {
    const settings = settingsOnly(); settings.goodqa = { ...settings.goodqa, allowedTools: endpoint.value.trim() === value.endpoint ? value.allowedTools || [] : [], enabled: enabled.checked, endpoint: endpoint.value.trim(), capabilities: Object.fromEntries(Object.entries(caps).map(([key, input]) => [key, input.checked])) }; return save(settings);
  }, 'primary-button'), button('Probe saved connection', async () => {
    const result = await context.api('/api/settings/goodqa/probe', {});
    panel.querySelector('.probe-result')?.remove();
    const output = context.el('div', 'probe-result'); panel.append(output);
    status(output, `${result.available ? 'Available' : 'Unavailable'} · ${result.reason || result.source || ''}`, !result.available);
    if (result.checkedAt) status(output, `Checked ${new Date(result.checkedAt).toLocaleString()}`);
    status(output, 'Select exact discovered tool names, then save. Category selection alone never grants access. Unlisted tools are not selected automatically.');
    const choices = [];
    for (const tool of result.tools || []) {
      const choice = toggle(output, `${tool.name} · ${tool.capability} · ${tool.available ? 'available' : 'unavailable'}`, (value.allowedTools || []).includes(tool.name));
      choice.disabled = !tool.available;
      choices.push({ name: tool.name, choice, available: tool.available });
    }
    if (result.available) output.append(button('Save allowed tools', () => {
      if (endpoint.value.trim() !== value.endpoint || enabled.checked !== value.enabled || Object.entries(caps).some(([key, input]) => input.checked !== !!value.capabilities[key])) throw new Error('Save connection and category preferences before selecting tools for the saved destination.');
      const settings = settingsOnly();
      settings.goodqa.allowedTools = choices.filter(item => item.available && item.choice.checked).map(item => item.name);
      return save(settings);
    }, 'primary-button'));
  }));
  const tools = card('Saved tool allowlist', 'Only these exact tool names may be offered to providers. No selected names means no GoodQA provider tools.', panel);
  for (const name of value.allowedTools || []) status(tools, name);
  if (!value.allowedTools?.length) status(tools, 'No tools allowed.');
  if (value.allowedTools?.length) tools.append(button('Clear allowed tools', () => {
    const settings = settingsOnly(); settings.goodqa.allowedTools = []; return save(settings);
  }, 'danger-button'));
  secretEditor(panel, 'goodqa', value.generation, 'credential', value.credentialPresent, 'GoodQA credential');
}
