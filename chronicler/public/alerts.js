/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $   = (id)  => document.getElementById(id);
  const qsa = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  let csrf     = null;
  let page     = 1;
  let perPage  = 50;   // controlled by the per-page dropdown
  let total    = 0;
  let openAlertId = null;   // currently open modal alert id

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;

    setupBell();
    setupModal();
    setupBulk();

    $('perPage')?.addEventListener('change', () => {
      perPage = parseInt($('perPage').value, 10) || 50;
      page = 1;
      loadAlerts();
    });

    $('btnFilter').onclick = () => { page = 1; loadAlerts(); };
    $('prevPage').onclick  = () => { if (page > 1)                 { page--; loadAlerts(); } };
    $('nextPage').onclick  = () => { if (page * perPage < total)   { page++; loadAlerts(); } };

    const params = new URLSearchParams(location.search);
    const linkId = parseInt(params.get('id'), 10);

    const linkSev = params.get('severity');
    if (linkSev && $('fSeverity')) {
      $('fSeverity').value = linkSev;
    }

    await loadAlerts();

    if (linkId) openModal(linkId).catch(console.error);

    setInterval(loadNotifications, 5000);
  })();

  async function GET(path) {
    const r = await fetch(path, { cache: 'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('GET parse error', path, t); return { ok: false }; }
  }

  async function POST(path, body) {
    const r = await fetch(path, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body:    JSON.stringify(body || {})
    });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('POST parse error', path, t); return { ok: false }; }
  }

  async function loadAlerts() {
    const sev  = $('fSeverity').value;
    const typ  = $('fType').value;
    const act  = $('fActive').value;
    const hrs  = $('fHours').value;
    const q    = $('fSearch').value.trim();
    const url  = `/api/alerts/list.php?page=${page}&per_page=${perPage}`
               + `&severity=${encodeURIComponent(sev)}`
               + `&type=${encodeURIComponent(typ)}`
               + `&active=${encodeURIComponent(act)}`
               + `&hours=${encodeURIComponent(hrs)}`
               + `&q=${encodeURIComponent(q)}`
               + `&sort=unread_first`;   // unacknowledged entries always on top

    const res = await GET(url);
    if (!res.ok) { console.error('loadAlerts failed', res); return; }

    total = res.total || 0;
    const pages = Math.ceil(total / perPage) || 1;
    $('pageInfo').textContent = `Page ${res.page} of ${pages}  (${total} total)`;

    const tb    = document.querySelector('#alertsTable tbody');
    const empty = $('alertsEmpty');
    tb.innerHTML = '';

    const selAll = $('alertsSelectAll');
    if (selAll) selAll.checked = false;
    syncBulkBar();

    if (!Array.isArray(res.alerts) || res.alerts.length === 0) {
      if (empty) empty.style.display = 'block';
      return;
    }
    if (empty) empty.style.display = 'none';

    res.alerts.forEach(a => {
      let name = '';
      try {
        const n = JSON.parse(a.admin_note || '{}');
        name = n.case_name || n.details?.case_name || n.details?.artifact || n.artifact || '';
      } catch (_) {}

      const sevClass = 'sev sev-' + (a.severity || 'mid').toLowerCase();

      const tr = document.createElement('tr');
      tr.dataset.id = a.id;
      tr.title      = 'Click to view details';
      tr.innerHTML  = `
        <td class="col-cb" onclick="event.stopPropagation()">
          <input type="checkbox" class="alert-cb" data-id="${a.id}">
        </td>
        <td>${a.id}</td>
        <td><span class="${sevClass}">${(a.severity || 'mid').toUpperCase()}</span></td>
        <td>${escHtml(a.alert_type || '—')}</td>
        <td>${escHtml(a.source_ip  || '—')}</td>
        <td>${escHtml(name         || '—')}</td>
        <td>${a.count || 1}</td>
        <td>${a.last_seen || '—'}</td>
        <td>${a.is_active ? '<span style="color:#7ecb7e">● Yes</span>'
                          : '<span style="color:#4a5a6e">● No</span>'}</td>
      `;
      tr.addEventListener('click', e => {
        if (e.target.type === 'checkbox') return;
        openModal(a.id);
      });
      tr.querySelector('.alert-cb').addEventListener('change', syncBulkBar);
      tb.appendChild(tr);
    });
  }

  function setupBulk() {
    $('alertsSelectAll').addEventListener('change', e => {
      qsa('#alertsTable tbody .alert-cb').forEach(cb => cb.checked = e.target.checked);
      syncBulkBar();
    });

    $('alertsBulkClear').addEventListener('click', () => {
      qsa('#alertsTable tbody .alert-cb').forEach(cb => cb.checked = false);
      $('alertsSelectAll').checked = false;
      syncBulkBar();
    });

    $('alertsBulkDelete').addEventListener('click', async () => {
      const ids = getSelectedAlertIds();
      if (!ids.length) return;
      if (!confirm(`Delete ${ids.length} alert(s)? This cannot be undone.`)) return;
      const res = await POST('/api/delete_alerts.php', { ids });
      if (!res.ok) return alert(res.error || 'Delete failed');
      $('alertsSelectAll').checked = false;
      await loadAlerts();
    });

    $('alertsBulkAck').addEventListener('click', async () => {
      const ids = getSelectedAlertIds();
      if (!ids.length) return;
      if (!confirm(`Acknowledge ${ids.length} alert(s)?`)) return;
      await Promise.all(ids.map(id => POST('/api/ack_alert.php', { id })));
      $('alertsSelectAll').checked = false;
      await loadAlerts();
      loadNotifications().catch(() => {});
    });
  }

  function getSelectedAlertIds() {
    return qsa('#alertsTable tbody .alert-cb:checked')
      .map(cb => parseInt(cb.dataset.id, 10));
  }

  function syncBulkBar() {
    const checked = qsa('#alertsTable tbody .alert-cb:checked').length;
    const bar = $('alertsBulkBar');
    if (bar) {
      bar.classList.toggle('visible', checked > 0);
      $('alertsBulkCount').textContent = `${checked} alert${checked !== 1 ? 's' : ''} selected`;
    }
  }

  function setupModal() {
    $('alertModalClose').addEventListener('click',  hideModal);
    $('alertModalCancel').addEventListener('click', hideModal);
    document.querySelector('#alertModal .modal-backdrop')
      ?.addEventListener('click', hideModal);
    $('alertAckBtn').addEventListener('click', ackCurrentAlert);
    $('alertDeleteBtn').addEventListener('click', deleteCurrentAlert);
  }

  function hideModal() {
    $('alertModal').classList.add('hidden');
    openAlertId = null;
  }

  async function openModal(id) {
    openAlertId = id;
    $('alertModalTitle').textContent = `Alert #${id}`;
    $('alertModalBody').innerHTML    = '<div class="empty">Loading…</div>';
    $('alertAckBtn').disabled        = true;
    $('alertModal').classList.remove('hidden');

    const d = await GET(`/api/alerts/details.php?id=${encodeURIComponent(id)}`);
    if (!d.ok) {
      $('alertModalBody').innerHTML = `<div class="empty">Failed to load: ${escHtml(d.error || 'unknown error')}</div>`;
      return;
    }

    const a   = d.alert       || {};
    const occ = d.occurrences || [];

    let caseName = '', noteDetails = null;
    try {
      const n  = JSON.parse(a.admin_note || '{}');
      caseName = n.case_name || n.details?.case_name || n.details?.artifact || n.artifact || '';
      noteDetails = n.details || null;
    } catch (_) {}

    // KV grid
    const kvItems = [
      { label: 'Alert ID',   val: a.id },
      { label: 'Type',       val: a.alert_type },
      { label: 'Severity',   val: (a.severity || 'mid').toUpperCase() },
      { label: 'Source IP',  val: a.source_ip  || 'n/a' },
      { label: 'Active',     val: a.is_active  ? 'Yes' : 'No' },
      { label: 'Hit Count',  val: a.count      || 1 },
      { label: 'Name',       val: caseName     || '—' },
      { label: 'Acked At',   val: a.acknowledged_time || '—' },
    ];

    // If details has extra fields, show them
    if (noteDetails && typeof noteDetails === 'object') {
      Object.entries(noteDetails).forEach(([k, v]) => {
        if (k === 'case_name' || k === 'artifact') return; // already shown
        kvItems.push({ label: k, val: Array.isArray(v) ? v.join(', ') : String(v) });
      });
    }

    const kvHTML = kvItems.map(item => `
      <div class="kv-item">
        <div class="kv-label">${escHtml(item.label)}</div>
        <div class="kv-val">${escHtml(String(item.val ?? '—'))}</div>
      </div>
    `).join('');

    // Timeline
    let timelineHTML = '';
    if (occ.length === 0) {
      timelineHTML = '<div class="tl-empty">No occurrences recorded.</div>';
    } else {
      timelineHTML = occ.map(o => `
        <div class="tl-item">
          <div class="tl-ts">${escHtml(o.occurred_at || '')}</div>
          <div class="tl-msg">${escHtml(o.text || '(no raw line available)')}</div>
          ${o.source_ip ? `<div class="tl-ip">from ${escHtml(o.source_ip)}</div>` : ''}
        </div>
      `).join('');
    }

    $('alertModalBody').innerHTML = `
      <div class="kv-grid">${kvHTML}</div>
      <div class="section-title">Occurrence Timeline (${occ.length} event${occ.length !== 1 ? 's' : ''})</div>
      <div class="timeline">${timelineHTML}</div>
    `;

    // Enable Ack only if still active
    $('alertAckBtn').disabled    = !a.is_active;
    $('alertDeleteBtn').disabled = false;
  }

  async function ackCurrentAlert() {
    if (!openAlertId) return;
    if (!confirm('Acknowledge this alert?')) return;
    await POST('/api/ack_alert.php', { id: parseInt(openAlertId, 10) });
    hideModal();
    await loadAlerts();
    loadNotifications().catch(() => {});
  }

  async function deleteCurrentAlert() {
    if (!openAlertId) return;
    if (!confirm('Delete this alert permanently? This cannot be undone.')) return;
    const res = await POST('/api/delete_alerts.php', { ids: [parseInt(openAlertId, 10)] });
    if (!res.ok) return alert(res.error || 'Delete failed');
    hideModal();
    await loadAlerts();
    loadNotifications().catch(() => {});
  }

  async function loadNotifications() {
    const d     = await GET('/api/get_alerts.php');
    const badge = $('notiBadge');
    if (badge) badge.textContent = d.count ?? 0;

    const list = $('notiList');
    if (!list) return;
    list.innerHTML = '';

    const items = Array.isArray(d.items) ? d.items : [];

    if (items.length === 0) {
      list.innerHTML = '<div style="padding:8px 12px;color:#9aa8bd;font-size:12px;">No active alerts</div>';
      return;
    }

    items.forEach(a => {
      const sev     = (a.severity || 'mid').toLowerCase();
      const label   = a.source_ip || 'n/a';
      const count   = a.hit_count > 1 ? ` (${a.hit_count})` : '';
      const typeStr = (a.alert_type || '').toUpperCase();

      const div = document.createElement('div');
      div.className = 'noti-item';
      div.style.cursor = 'pointer';
      div.innerHTML = `
        <div style="flex:1">
          <div class="noti-kind">${typeStr} — ${escHtml(label)}${escHtml(count)}</div>
          <div class="noti-sev ${sev}">${(a.severity || 'MID').toUpperCase()}</div>
        </div>
        <span style="font-size:11px;color:#4a6a8a;align-self:center">▶</span>
      `;
      div.addEventListener('click', () => {
        const dest = `/alerts.html?id=${a.id}`;
        if (window.location.pathname.endsWith('alerts.html')) {
          $('notiMenu')?.classList.add('hidden');
          openModal(a.id).catch(console.error);
        } else {
          window.location.href = dest;
        }
      });
      list.appendChild(div);
    });
  }

  function setupBell() {
    const bell = $('notiBell'), menu = $('notiMenu');
    if (!bell || !menu) return;
    bell.onclick = () => menu.classList.toggle('hidden');
    document.addEventListener('click', e => {
      if (!menu.contains(e.target) && !bell.contains(e.target))
        menu.classList.add('hidden');
    }, { passive: true });
    loadNotifications();
  }

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, ch =>
      ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[ch])
    );
  }

})();
