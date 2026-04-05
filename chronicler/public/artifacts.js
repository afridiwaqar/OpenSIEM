/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $   = id  => document.getElementById(id);
  const qsa = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  let csrf = null;
  let allHits = [];
  let modalArtifact = null;

  // Pagination state
  let hitsPage    = 1;  let hitsPerPage  = 50;
  let artPage     = 1;  let artPerPage   = 50;
  let allArtRows  = [];  // full artifact list kept in memory

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;

    qsa('.tab').forEach(t => t.addEventListener('click', () => {
      qsa('.tab').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      const target = t.getAttribute('data-tab');
      qsa('.pane').forEach(p => p.classList.remove('active'));
      $(target).classList.add('active');
      if (target === 'hitsPane') loadHits();
    }));

    $('btnCreateArtifact').addEventListener('click', createArtifact);

    $('hitsPerPage')?.addEventListener('change', () => {
      hitsPerPage = parseInt($('hitsPerPage').value, 10) || 50;
      hitsPage = 1; renderHitsGrouped();
    });
    $('artPerPage')?.addEventListener('change', () => {
      artPerPage = parseInt($('artPerPage').value, 10) || 50;
      artPage = 1; renderArtifacts();
    });

    // Pagination buttons — hits
    $('hitsPrev')?.addEventListener('click', () => { if (hitsPage > 1) { hitsPage--; renderHitsGrouped(); } });
    $('hitsNext')?.addEventListener('click', () => {
      const groups = buildHitsGroups();
      if (hitsPage * hitsPerPage < groups.size) { hitsPage++; renderHitsGrouped(); }
    });

    // Pagination buttons — manage
    $('artPrev')?.addEventListener('click', () => { if (artPage > 1) { artPage--; renderArtifacts(); } });
    $('artNext')?.addEventListener('click', () => {
      if (artPage * artPerPage < allArtRows.length) { artPage++; renderArtifacts(); }
    });

    setupBulkHits();
    setupBulkArt();
    setupGroupModal();
    setupBell();

    await Promise.all([loadHits(), loadArtifacts()]);
    setInterval(loadHits, 8000);
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

  async function loadHits() {
    try {
      const data = await GET('/api/artifacts/hits.php');
      allHits    = Array.isArray(data) ? data : [];
      hitsPage   = 1;
      renderHitsGrouped();
    } catch(e) { console.error('loadHits', e); }
  }

  function buildHitsGroups() {
    const groups = new Map();
    const SEV_ORDER = { critical:4, high:3, mid:2, low:1 };
    const sorted = [...allHits].sort((a, b) => {
      if (a.is_active !== b.is_active) return a.is_active ? -1 : 1;
      return (b.last_seen || '') > (a.last_seen || '') ? 1 : -1;
    });
    sorted.forEach(h => {
      const key = getArtifactKey(h);
      if (!groups.has(key)) groups.set(key, { hits:[], maxSev:'low', latestSeen:null, anyActive:false });
      const g = groups.get(key);
      g.hits.push(h);
      if ((SEV_ORDER[h.severity] || 0) > (SEV_ORDER[g.maxSev] || 0)) g.maxSev = h.severity;
      if (h.is_active) g.anyActive = true;
      if (h.last_seen && (!g.latestSeen || h.last_seen > g.latestSeen)) g.latestSeen = h.last_seen;
    });
    return groups;
  }

  function renderHitsGrouped() {
    const tb    = document.querySelector('#hitsTable tbody');
    const empty = $('hitsEmpty');
    if (!tb) return;
    tb.innerHTML = '';
    $('hitsSelectAll').checked = false;
    syncHitsBulkBar();

    const groups = buildHitsGroups();

    if (groups.size === 0) {
      if (empty) empty.style.display = 'block';
      if ($('hitsPageInfo')) $('hitsPageInfo').textContent = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    const groupEntries = [...groups.entries()];
    const totalGroups  = groupEntries.length;
    const totalPages   = Math.ceil(totalGroups / hitsPerPage) || 1;
    if (hitsPage > totalPages) hitsPage = totalPages;
    const start = (hitsPage - 1) * hitsPerPage;
    const page  = groupEntries.slice(start, start + hitsPerPage);

    if ($('hitsPageInfo')) $('hitsPageInfo').textContent =
      `Page ${hitsPage} of ${totalPages}  (${totalGroups} groups)`;

    page.forEach(([key, g]) => {
      const allIds   = g.hits.map(h => h.id);
      const sevClass = 'sev sev-' + g.maxSev;
      const statusHtml = g.anyActive
        ? '<span style="color:#7ecb7e">● Active</span>'
        : '<span style="color:#4a5a6e">● All acked</span>';

      const tr = document.createElement('tr');
      tr.dataset.ids = JSON.stringify(allIds);

      if (g.anyActive) tr.style.borderLeft = '3px solid #b01828';
      tr.innerHTML = `
        <td class="col-cb" onclick="event.stopPropagation()">
          <input type="checkbox" class="hits-cb" data-ids='${JSON.stringify(allIds)}'>
        </td>
        <td style="word-break:break-all">${escHtml(key)}</td>
        <td><span class="${sevClass}">${g.maxSev.toUpperCase()}</span></td>
        <td>
          <span class="hit-badge" title="Click to view individual hits">${g.hits.length}</span>
        </td>
        <td>${escHtml(g.latestSeen || '—')}</td>
        <td>${statusHtml}</td>
      `;

      tr.querySelector('.hit-badge').addEventListener('click', e => {
        e.stopPropagation();
        openGroupModal(key, g.hits);
      });
      tr.addEventListener('click', e => {
        if (e.target.type === 'checkbox') return;
        openGroupModal(key, g.hits);
      });
      tr.querySelector('.hits-cb').addEventListener('change', syncHitsBulkBar);
      tb.appendChild(tr);
    });
  }

  function setupBulkHits() {
    $('hitsSelectAll').addEventListener('change', e => {
      qsa('#hitsTable tbody .hits-cb').forEach(cb => cb.checked = e.target.checked);
      syncHitsBulkBar();
    });

    $('hitsBulkClear').addEventListener('click', () => {
      qsa('#hitsTable tbody .hits-cb').forEach(cb => cb.checked = false);
      $('hitsSelectAll').checked = false;
      syncHitsBulkBar();
    });

    $('hitsBulkDelete').addEventListener('click', async () => {
      const ids = getSelectedHitIds();
      if (!ids.length) return;
      if (!confirm(`Delete ${ids.length} alert(s)?`)) return;
      const res = await POST('/api/delete_alerts.php', { ids });
      if (!res.ok) return alert(res.error || 'Delete failed');
      $('hitsSelectAll').checked = false;
      await loadHits();
    });

    $('hitsBulkAck').addEventListener('click', async () => {
      const ids = getSelectedHitIds();
      if (!ids.length) return;
      if (!confirm(`Acknowledge ${ids.length} alert(s)?`)) return;
      await Promise.all(ids.map(id => POST('/api/ack_alert.php', { id })));
      $('hitsSelectAll').checked = false;
      await loadHits();
      loadNotifications().catch(() => {});
    });
  }

  function getSelectedHitIds() {
    const ids = [];
    qsa('#hitsTable tbody .hits-cb:checked').forEach(cb => {
      try { JSON.parse(cb.dataset.ids).forEach(id => ids.push(id)); }
      catch { ids.push(parseInt(cb.dataset.ids, 10)); }
    });
    return [...new Set(ids)];
  }

  function syncHitsBulkBar() {
    const checked = qsa('#hitsTable tbody .hits-cb:checked').length;
    const bar = $('hitsBulkBar');
    if (bar) {
      bar.classList.toggle('visible', checked > 0);
      $('hitsBulkCount').textContent = `${checked} group${checked !== 1 ? 's' : ''} selected`;
    }
  }

  function setupGroupModal() {
    $('groupModalClose').addEventListener('click',  hideGroupModal);
    $('groupModalCancel').addEventListener('click', hideGroupModal);
    document.querySelector('#groupModal .modal-backdrop')
      ?.addEventListener('click', hideGroupModal);

    $('groupSelectAll').addEventListener('change', e => {
      qsa('#groupModal .group-hit-cb').forEach(cb => cb.checked = e.target.checked);
      syncGroupSel();
    });

    $('groupBulkAck').addEventListener('click', async () => {
      const ids = getGroupSelected();
      if (!ids.length) return;
      if (!confirm(`Acknowledge ${ids.length} hit(s)?`)) return;
      await Promise.all(ids.map(id => POST('/api/ack_alert.php', { id })));
      await loadHits();
      const fresh = allHits.filter(h => getArtifactKey(h) === modalArtifact);
      if (fresh.length) renderGroupModal(fresh);
      else hideGroupModal();
      loadNotifications().catch(() => {});
    });

    $('groupBulkDelete').addEventListener('click', async () => {
      const ids = getGroupSelected();
      if (!ids.length) return;
      if (!confirm(`Delete ${ids.length} hit(s)?`)) return;
      const res = await POST('/api/delete_alerts.php', { ids });
      if (!res.ok) return alert(res.error || 'Delete failed');
      await loadHits();
      const fresh = allHits.filter(h => getArtifactKey(h) === modalArtifact);
      if (fresh.length) renderGroupModal(fresh);
      else hideGroupModal();
    });
  }

  function getGroupSelected() {
    return qsa('#groupModal .group-hit-cb:checked')
      .map(cb => parseInt(cb.dataset.id, 10));
  }

  function syncGroupSel() {
    const checked = qsa('#groupModal .group-hit-cb:checked').length;
    $('groupSelCount').textContent = checked ? `${checked} selected` : '';
  }

  function openGroupModal(key, hits) {
    modalArtifact = key;
    $('groupModalTitle').textContent = 'Hits: ' + key;
    renderGroupModal(hits);
    $('groupModal').classList.remove('hidden');
  }

  function renderGroupModal(hits) {
    $('groupSelectAll').checked = false;
    $('groupSelCount').textContent = '';

    const body = $('groupModalBody');
    if (!hits.length) { body.innerHTML = '<div class="empty">No hits.</div>'; return; }

    const rows = hits.map(h => {
      const isActive = h.is_active || h.is_active === 't' || h.is_active === true;
      const ackedAt  = h.acknowledged_time
        ? `<span style="color:#4a6a8a;font-size:11px">Acked: ${escHtml(h.acknowledged_time)}</span>` : '';
      const sevClass = 'sev sev-' + (h.severity || 'mid');

      let msgText = '';
      try {
        const n = JSON.parse(h.admin_note || '{}');
        msgText = n?.details?.message || n?.message || n?.details?.artifact || '';
      } catch { /* ignore */ }

      const msgRow = msgText ? `
        <tr class="hit-msg-row" style="background:#07090f">
          <td></td>
          <td colspan="5" style="padding:4px 10px 8px;font-size:11px;
              font-family:monospace;color:#7ab0d8;word-break:break-all;
              border-top:none">
            ${escHtml(msgText)}
          </td>
        </tr>` : '';

      return `
        <tr class="hit-main-row" data-id="${h.id}" style="cursor:pointer"
            title="Click to load raw log line">
          <td class="col-cb" onclick="event.stopPropagation()">
            <input type="checkbox" class="group-hit-cb" data-id="${h.id}">
          </td>
          <td>${h.id}</td>
          <td><span class="${sevClass}">${(h.severity||'mid').toUpperCase()}</span></td>
          <td>${escHtml(h.source_ip || '—')}</td>
          <td>${escHtml(h.last_seen || '—')}</td>
          <td>${isActive
            ? '<span style="color:#7ecb7e">● Active</span>'
            : `<span style="color:#4a5a6e">● Acked</span> ${ackedAt}`
          }</td>
        </tr>
        ${msgRow}
        <tr class="hit-detail-row" id="detail-${h.id}" style="display:none;background:#07090f">
          <td></td>
          <td colspan="5" style="padding:4px 10px 8px;font-size:11px;
              font-family:monospace;color:#9ab8d8;word-break:break-all">
            <span style="color:#4a6a8a">Loading…</span>
          </td>
        </tr>`;
    }).join('');

    body.innerHTML = `
      <table class="table">
        <thead>
          <tr>
            <th class="col-cb"></th>
            <th>ID</th><th>Severity</th><th>Source IP</th><th>Last Seen</th><th>Status</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;

    body.querySelectorAll('.hit-main-row').forEach(row => {
      row.addEventListener('click', async e => {
        if (e.target.type === 'checkbox') return;
        const id       = row.dataset.id;
        const detailEl = body.querySelector(`#detail-${id}`);
        if (!detailEl) return;

        const visible = detailEl.style.display !== 'none';
        if (visible) { detailEl.style.display = 'none'; return; }

        detailEl.style.display = '';
        const td = detailEl.querySelector('td:last-child');

        if (td.querySelector('[data-loaded]')) return;

        try {
          const d = await GET(`/api/alerts/details.php?id=${encodeURIComponent(id)}`);
          if (!d.ok) { td.innerHTML = '<span style="color:#ff6b6b">Failed to load</span>'; return; }

          const occ = Array.isArray(d.occurrences) ? d.occurrences : [];
          if (!occ.length) {
            td.innerHTML = '<span style="color:#4a6a8a" data-loaded>No raw log lines recorded.</span>';
            return;
          }

          td.innerHTML = occ.map(o => {
            const line = o.text || o.details || '(no raw line)';
            return `<div data-loaded style="padding:2px 0;border-bottom:1px solid #1c2434">
              <span style="color:#4a6a8a;margin-right:6px">${escHtml(o.occurred_at || '')}</span>
              ${escHtml(line)}
            </div>`;
          }).join('');

        } catch(err) {
          td.innerHTML = `<span style="color:#ff6b6b">Error: ${escHtml(String(err))}</span>`;
        }
      });
    });

    body.querySelectorAll('.group-hit-cb').forEach(cb =>
      cb.addEventListener('change', syncGroupSel)
    );
  }

  function hideGroupModal() {
    $('groupModal').classList.add('hidden');
    modalArtifact = null;
  }

  function getArtifactKey(hit) {
    try {
      const n = JSON.parse(hit.admin_note || '{}');
      if (n?.details?.artifact) return n.details.artifact;
      if (n?.artifact)          return n.artifact;
      if (n?.case_name) {
        const m = String(n.case_name).match(/^Artifact detected:\s*(.+)$/i);
        if (m) return m[1].trim();
      }
    } catch { /* fall through */ }
    return hit.source_ip || String(hit.id);
  }

  async function loadArtifacts() {
    try {
      const data = await GET('/api/artifacts/list.php');
      allArtRows = Array.isArray(data) ? data.slice().reverse() : [];
      artPage = 1;
      renderArtifacts();
    } catch(e) { console.error('loadArtifacts', e); }
  }

  function renderArtifacts() {
    const tb    = document.querySelector('#artTable tbody');
    const empty = $('artEmpty');
    if (!tb) return;
    tb.innerHTML = '';
    $('artSelectAll').checked = false;
    syncArtBulkBar();

    if (allArtRows.length === 0) {
      if (empty) empty.style.display = 'block';
      if ($('artPageInfo')) $('artPageInfo').textContent = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    const totalPages = Math.ceil(allArtRows.length / artPerPage) || 1;
    if (artPage > totalPages) artPage = totalPages;
    const start = (artPage - 1) * artPerPage;
    const rows  = allArtRows.slice(start, start + artPerPage);

    if ($('artPageInfo')) $('artPageInfo').textContent =
      `Page ${artPage} of ${totalPages}  (${allArtRows.length} total)`;

    rows.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="col-cb" onclick="event.stopPropagation()">
          <input type="checkbox" class="art-cb" data-art="${encodeURIComponent(r.artifacts)}">
        </td>
        <td style="word-break:break-all">${escHtml(r.artifacts)}</td>
        <td>${r.interval ?? 0}</td>
        <td>${(r.severity || 'mid').toUpperCase()}</td>
        <td style="word-break:break-all">${escHtml(r.source_url || '—')}</td>
        <td>${r.added_at || '—'}</td>
        <td>
          <button class="btn small danger del"
                  data-art="${encodeURIComponent(r.artifacts)}">Delete</button>
        </td>`;
      tr.querySelector('.del').addEventListener('click', async () => {
        if (!confirm('Delete this artifact?')) return;
        const res = await POST('/api/artifacts/save.php', {
          action: 'delete', artifacts: decodeURIComponent(tr.querySelector('.del').dataset.art)
        });
        if (!res.ok) return alert(res.error || 'Delete failed.');
        await loadArtifacts();
      });
      tr.querySelector('.art-cb').addEventListener('change', syncArtBulkBar);
      tb.appendChild(tr);
    });
  }

  function setupBulkArt() {
    $('artSelectAll').addEventListener('change', e => {
      qsa('#artTable tbody .art-cb').forEach(cb => cb.checked = e.target.checked);
      syncArtBulkBar();
    });
    $('artBulkClear').addEventListener('click', () => {
      qsa('#artTable tbody .art-cb').forEach(cb => cb.checked = false);
      $('artSelectAll').checked = false;
      syncArtBulkBar();
    });
    $('artBulkDelete').addEventListener('click', async () => {
      const keys = qsa('#artTable tbody .art-cb:checked')
        .map(cb => decodeURIComponent(cb.dataset.art));
      if (!keys.length) return;
      if (!confirm(`Delete ${keys.length} artifact(s)?`)) return;
      for (const a of keys) {
        await POST('/api/artifacts/save.php', { action: 'delete', artifacts: a });
      }
      $('artSelectAll').checked = false;
      await loadArtifacts();
    });
  }

  function syncArtBulkBar() {
    const checked = qsa('#artTable tbody .art-cb:checked').length;
    const bar = $('artBulkBar');
    if (bar) {
      bar.classList.toggle('visible', checked > 0);
      $('artBulkCount').textContent = `${checked} artifact${checked !== 1 ? 's' : ''} selected`;
    }
  }

  async function createArtifact() {
    const a   = $('artText').value.trim();
    const sev = $('artSev').value;
    const iv  = parseInt($('artInt').value, 10) || 0;
    const src = $('artSrc').value.trim() || null;
    if (!a) return alert('Artifact text is required.');
    const res = await POST('/api/artifacts/save.php', {
      action: 'create', artifacts: a, interval: iv, severity: sev, source_url: src
    });
    if (!res.ok) return alert(res.error || 'Create failed.');
    $('artText').value = '';
    $('artInt').value  = '0';
    $('artSev').value  = 'mid';
    $('artSrc').value  = '';
    await loadArtifacts();
  }

  async function loadNotifications() {
    const data  = await GET('/api/get_alerts.php');
    const badge = $('notiBadge');
    if (badge) badge.textContent = data.count ?? 0;
    const list = $('notiList');
    if (!list) return;
    list.innerHTML = '';
    const items = Array.isArray(data.items) ? data.items : [];
    if (items.length === 0) {
      list.innerHTML = '<div style="padding:10px;color:#9aa8bd;font-size:12px;">No active alerts</div>';
      return;
    }
    items.forEach(a => {
      const sev   = (a.severity || 'mid').toLowerCase();
      const label = a.source_ip || 'n/a';
      const count = a.hit_count > 1 ? ` (${a.hit_count})` : '';
      const div   = document.createElement('div');
      div.className    = 'noti-item';
      div.style.cursor = 'pointer';
      div.innerHTML = `
        <div style="flex:1">
          <div class="noti-kind">${(a.alert_type||'').toUpperCase()} — ${escHtml(label)}${escHtml(count)}</div>
          <div class="noti-sev ${sev}">${(a.severity||'MID').toUpperCase()}</div>
        </div>
        <span style="font-size:11px;color:#4a6a8a;align-self:center">▶</span>`;
      div.addEventListener('click', () => { window.location.href = `/alerts.html?id=${a.id}`; });
      list.appendChild(div);
    });
  }

  function setupBell() {
    const bell = $('notiBell'), menu = $('notiMenu');
    if (!bell || !menu) return;
    bell.addEventListener('click', () => menu.classList.toggle('hidden'));
    document.addEventListener('click', e => {
      if (!menu.contains(e.target) && !bell.contains(e.target))
        menu.classList.add('hidden');
    }, { passive: true });
    loadNotifications();
    setInterval(loadNotifications, 5000);
  }

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch]));
  }
})();
