const $ = (selector) => document.querySelector(selector);
const loginPanel = $('#loginPanel');
const appPanel = $('#appPanel');
const loginMessage = $('#loginMessage');
const uploadMessage = $('#uploadMessage');
const documentsMessage = $('#documentsMessage');
const shareDialog = $('#shareDialog');
let currentUser = null;
let currentShareDocument = null;

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  if (response.status === 204) return null;
  const type = response.headers.get('content-type') || '';
  const payload = type.includes('application/json') ? await response.json() : await response.blob();
  if (!response.ok) throw new Error(payload?.error || `Request failed (${response.status}).`);
  return payload;
}

function showMessage(element, text = '', kind = '') {
  element.textContent = text;
  element.className = `message ${kind}`.trim();
}

function formatDate(value) {
  try { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)); }
  catch { return value || ''; }
}
function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
function setSignedIn(user) {
  currentUser = user;
  loginPanel.classList.toggle('hidden', Boolean(user));
  appPanel.classList.toggle('hidden', !user);
  if (user) {
    $('#welcomeTitle').textContent = `Welcome, ${user.full_name || user.email}`;
    $('#userSummary').textContent = `${user.email} · ${user.role.replaceAll('_', ' ')}`;
    $('#uploadPanel').classList.toggle('hidden', user.role === 'viewer');
    $('#auditPanel').classList.toggle('hidden', user.role !== 'administrator');
  }
}

$('#loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  showMessage(loginMessage, 'Signing in…');
  const button = event.currentTarget.querySelector('button[type=submit]');
  button.disabled = true;
  try {
    const form = new FormData(event.currentTarget);
    const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: form.get('email'), password: form.get('password') }) });
    setSignedIn(result.user);
    event.currentTarget.reset();
    showMessage(loginMessage, 'Signed in successfully.', 'success');
    await refreshDocuments();
    if (currentUser.role === 'administrator') await refreshAudit();
  } catch (error) { showMessage(loginMessage, error.message, 'error'); }
  finally { button.disabled = false; }
});

$('#logoutButton').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); }
  catch (error) { showMessage(documentsMessage, error.message, 'error'); }
  setSignedIn(null);
  $('#documentList').innerHTML = '<div class="empty-state">Sign in to see documents.</div>';
  $('#auditList').replaceChildren();
});

$('#uploadForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type=submit]');
  button.disabled = true;
  showMessage(uploadMessage, 'Uploading and validating file…');
  try {
    const form = new FormData(event.currentTarget);
    const result = await api('/api/documents', { method: 'POST', body: form });
    event.currentTarget.reset();
    event.currentTarget.elements.category.value = 'General';
    showMessage(uploadMessage, `Uploaded “${result.document.title}”.`, 'success');
    await refreshDocuments();
  } catch (error) { showMessage(uploadMessage, error.message, 'error'); }
  finally { button.disabled = false; }
});

async function refreshDocuments() {
  if (!currentUser) return;
  showMessage(documentsMessage, 'Loading documents…');
  const form = new FormData($('#searchForm'));
  const params = new URLSearchParams();
  if (String(form.get('q') || '').trim()) params.set('q', String(form.get('q')).trim());
  if (String(form.get('category') || '').trim()) params.set('category', String(form.get('category')).trim());
  try {
    const result = await api(`/api/documents?${params.toString()}`);
    const documents = result.documents || [];
    $('#documentCount').textContent = `${documents.length} ${documents.length === 1 ? 'file' : 'files'}`;
    showMessage(documentsMessage, documents.length ? '' : 'No documents match this search.');
    const list = $('#documentList');
    if (!documents.length) { list.innerHTML = '<div class="empty-state">No accessible documents yet. Upload a file or ask an owner to share one.</div>'; return; }
    list.innerHTML = documents.map((doc) => `
      <article class="doc-card" data-document-id="${escapeHtml(doc.id)}">
        <div>
          <div class="doc-title"><span class="doc-icon" aria-hidden="true">▤</span><span>${escapeHtml(doc.title)}</span></div>
          <div class="doc-meta"><span>${escapeHtml(doc.category)}</span><span>${formatBytes(doc.size_bytes)}</span><span>${formatDate(doc.created_at)}</span><span>Owner: ${escapeHtml(doc.owner_email || 'Unknown')}</span><span>${doc.can_edit ? 'Can edit' : 'Read only'}</span></div>
        </div>
        <div class="doc-actions">
          <button class="small-button" data-action="download" data-id="${escapeHtml(doc.id)}">Download</button>
          ${doc.can_edit ? `<button class="small-button" data-action="edit" data-id="${escapeHtml(doc.id)}">Edit</button>` : ''}
          ${doc.can_manage ? `<button class="small-button" data-action="share" data-id="${escapeHtml(doc.id)}" data-title="${escapeHtml(doc.title)}">Share</button><button class="small-button danger" data-action="delete" data-id="${escapeHtml(doc.id)}">Delete</button>` : ''}
        </div>
      </article>`).join('');
  } catch (error) { showMessage(documentsMessage, error.message, 'error'); }
}

$('#searchForm').addEventListener('submit', (event) => { event.preventDefault(); refreshDocuments(); });
$('#clearSearch').addEventListener('click', () => { $('#searchForm').reset(); refreshDocuments(); });
$('#documentList').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const { action, id } = button.dataset;
  button.disabled = true;
  try {
    if (action === 'download') {
      const response = await fetch(`/api/documents/${encodeURIComponent(id)}/download`, { credentials: 'same-origin' });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || `Download failed (${response.status}).`);
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = 'trustvault-document';
      document.body.append(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(objectUrl);
      await refreshDocuments();
    } else if (action === 'edit') {
      const title = prompt('New document title (leave blank to keep current title):');
      if (title === null) return;
      const category = prompt('New category (leave blank to keep current category):');
      if (category === null) return;
      const body = {};
      if (title.trim()) body.title = title.trim();
      if (category.trim()) body.category = category.trim();
      if (Object.keys(body).length) await api(`/api/documents/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) });
      await refreshDocuments();
    } else if (action === 'share') {
      currentShareDocument = { id, title: button.dataset.title };
      $('#shareForm').elements.documentId.value = id;
      $('#shareForm').reset();
      $('#shareForm').elements.documentId.value = id;
      $('#shareMessage').textContent = '';
      $('#permissionList').replaceChildren();
      $('#shareForm').querySelector('h2').textContent = `Share: ${currentShareDocument.title}`;
      await refreshPermissions();
      shareDialog.showModal();
    } else if (action === 'delete') {
      if (!confirm('Delete this document and its stored file? This cannot be undone.')) return;
      await api(`/api/documents/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await refreshDocuments();
    }
  } catch (error) { showMessage(documentsMessage, error.message, 'error'); }
  finally { button.disabled = false; }
});

async function refreshPermissions() {
  if (!currentShareDocument) return;
  const result = await api(`/api/documents/${encodeURIComponent(currentShareDocument.id)}/permissions`);
  const container = $('#permissionList');
  const entries = result.permissions || [];
  if (!entries.length) { container.innerHTML = '<p class="hint">No explicit grants yet.</p>'; return; }
  container.innerHTML = `<p class="eyebrow">CURRENT ACCESS GRANTS</p>` + entries.map(p => `
    <div class="permission-item"><div><strong>${escapeHtml(p.email || p.user_id)}</strong><small>${p.can_edit ? 'Read and edit' : p.can_read ? 'Read only' : 'No access'}</small></div><button type="button" class="small-button danger" data-revoke="${escapeHtml(p.user_id)}">Revoke</button></div>`).join('');
}

$('#shareForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const canRead = form.get('can_read') === 'on';
  const canEdit = form.get('can_edit') === 'on';
  showMessage($('#shareMessage'), 'Saving permission…');
  try {
    await api(`/api/documents/${encodeURIComponent(currentShareDocument.id)}/permissions`, { method: 'POST', body: JSON.stringify({ email: form.get('email'), can_read: canRead, can_edit: canEdit }) });
    showMessage($('#shareMessage'), 'Permission saved. The server will check it on each document request.', 'success');
    event.currentTarget.elements.email.value = '';
    await refreshPermissions();
  } catch (error) { showMessage($('#shareMessage'), error.message, 'error'); }
});

$('#permissionList').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-revoke]');
  if (!button || !currentShareDocument) return;
  button.disabled = true;
  try {
    await api(`/api/documents/${encodeURIComponent(currentShareDocument.id)}/permissions/${encodeURIComponent(button.dataset.revoke)}`, { method: 'DELETE' });
    showMessage($('#shareMessage'), 'Access revoked. The next request should be denied.', 'success');
    await refreshPermissions();
  } catch (error) { showMessage($('#shareMessage'), error.message, 'error'); }
  finally { button.disabled = false; }
});

$('#closeShare').addEventListener('click', () => shareDialog.close());
$('#refreshAudit').addEventListener('click', refreshAudit);
async function refreshAudit() {
  if (!currentUser || currentUser.role !== 'administrator') return;
  try {
    const result = await api('/api/admin/audit?limit=80');
    const events = result.events || [];
    $('#auditList').innerHTML = events.length ? events.map(e => `<div class="audit-item"><div><strong>${escapeHtml(e.action)}</strong><small>${escapeHtml(e.actor_role)} · ${escapeHtml(e.actor_id || 'anonymous')} · ${formatDate(e.created_at)}</small><small>Document: ${escapeHtml(e.document_id || '—')}</small></div><span class="status ${escapeHtml(e.outcome)}">${escapeHtml(e.outcome)}</span></div>`).join('') : '<div class="empty-state">No audit events yet.</div>';
  } catch (error) { $('#auditList').innerHTML = `<p class="message error">${escapeHtml(error.message)}</p>`; }
}

async function restoreSession() {
  try {
    const result = await api('/api/auth/me');
    setSignedIn(result.user);
    await refreshDocuments();
    if (currentUser.role === 'administrator') await refreshAudit();
  } catch { setSignedIn(null); }
}
restoreSession();
