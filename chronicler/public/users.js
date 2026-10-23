/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/

(() => {
  const $  = id  => document.getElementById(id);
  const qs = sel => document.querySelector(sel);
  let csrf = null, selectedUserId = null;

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;
    await loadUsers();

    $('btnCreate').addEventListener('click', async () => {
      const body = gatherForm(false); if (!body) return;
      const res  = await POST('/api/users/save.php', { action: 'create_user', ...body });
      if (!res.ok) return alert(res.error || 'Create failed');
      await loadUsers();
      alert('User created.');
      clearForm();
    });

    $('btnClear')?.addEventListener('click', clearForm);

    $('btnUpdate').addEventListener('click', async () => {
      if (!selectedUserId) return alert('Select a user from the table first.');
      const body = gatherForm(true); if (!body) return;
      body.user_id = selectedUserId;
      const res = await POST('/api/users/save.php', { action: 'update_user', ...body });
      if (!res.ok) return alert(res.error || 'Update failed');
      await loadUsers();
      alert('User updated.');
    });
  })();

  async function GET(path) {
    const r = await fetch(path, { cache: 'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('GET parse error', path, t); return { ok: false }; }
  }

  async function POST(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(body || {})
    });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('POST parse error', path, t); return { ok: false }; }
  }

  async function loadUsers() {
    const rows = await GET('/api/users/list.php');
    const tb   = qs('#uTable tbody');
    if (!tb) return;
    tb.innerHTML = '';

    (Array.isArray(rows) ? rows : []).forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${u.user_id}</td>
        <td>${escHtml(u.username)}</td>
        <td>${escHtml(u.email)}</td>
        <td>${escHtml(u.role)}</td>
        <td>${u.is_active   ? '✔' : '—'}</td>
        <td>${u.is_verified ? '✔' : '—'}</td>
        <td>
          <button class="btn small sel" data-id="${u.user_id}">Select</button>
          <button class="btn small danger del" data-id="${u.user_id}">Delete</button>
        </td>`;
      tb.appendChild(tr);
    });

    tb.querySelectorAll('.sel').forEach(b =>
      b.addEventListener('click', () => selectUser(parseInt(b.dataset.id, 10)))
    );
    tb.querySelectorAll('.del').forEach(b =>
      b.addEventListener('click', async () => {
        const id = parseInt(b.dataset.id, 10);
        if (!confirm('Delete this user?')) return;
        const res = await POST('/api/users/save.php', { action: 'delete_user', user_id: id });
        if (!res.ok) return alert(res.error || 'Delete failed');
        await loadUsers();
      })
    );
  }

  async function selectUser(uid) {
    selectedUserId = uid;
    const rows = await GET('/api/users/list.php');
    const u = (Array.isArray(rows) ? rows : []).find(x => x.user_id === uid);
    if (!u) return;
    $('uName').value  = u.username;
    $('uEmail').value = u.email;
    $('uPass').value  = '';
    $('uRole').value  = u.role || 'viewer';
    $('pCreate').checked = !!u.can_create;
    $('pRead').checked   = !!u.can_read;
    $('pUpdate').checked = !!u.can_update;
    $('pDelete').checked = !!u.can_delete;
  }

  function clearForm() {
    ['uName', 'uEmail', 'uPass'].forEach(id => $(id).value = '');
    $('uRole').value = 'viewer';
    $('pCreate').checked = false;
    $('pRead').checked   = true;
    $('pUpdate').checked = false;
    $('pDelete').checked = false;
    selectedUserId = null;
  }

  function gatherForm(isUpdate = false) {
    const username = $('uName').value.trim();
    const email    = $('uEmail').value.trim();
    const password = $('uPass').value;
    const role     = $('uRole').value;
    if (!username || !email) { alert('Username and email are required.'); return null; }
    if (!password) { alert('Password is required.'); return null; }
    const body = {
      username, email, role,
      permissions: {
        can_create: $('pCreate').checked,
        can_read:   $('pRead').checked,
        can_update: $('pUpdate').checked,
        can_delete: $('pDelete').checked,
      }
    };
    if (password) body.password = password;
    return body;
  }

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch]));
  }
})();
