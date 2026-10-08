// /var/www/chronicler/public/alerts.js
(() => {
  const $   = id => document.getElementById(id);
  const esc = s  => String(s ?? '').replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const qsa = sel => Array.from(document.querySelectorAll(sel));

  // ── API helpers ──────────────────────────────────────────────────────────
  async function GET(url) {
    const r = await fetch(url, { cache:'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); } catch { return { ok:false, error:t }; }
  }
  async function POST(url, body) {
    const r = await fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    const t = await r.text();
    try { return JSON.parse(t); } catch { return { ok:false, error:t }; }
  }

  // ── State ────────────────────────────────────────────────────────────────
  let page = 1, totalPages = 1, currentAlertId = null;
  const SEV_CLASS = { low:'low', mid:'mid', high:'high', critical:'critical' };
  const STATUS_LABEL = {
    open:'Open', investigating:'Investigating',
    resolved:'Resolved', false_positive:'False Positive'
  };

  // ── Severity badge ───────────────────────────────────────────────────────
  function sevBadge(s) {
    return `<span class="sev sev-${esc(s)}">${esc((s||'').toUpperCase())}</span>`;
  }
  function statusBadge(s) {
    return `<span class="status-badge status-${esc(s)}">${esc(STATUS_LABEL[s]||s)}</span>`;
  }

  // ── Load alerts table ────────────────────────────────────────────────────
  async function loadAlerts() {
    const params = new URLSearchParams({
      severity: $('fSeverity')?.value || '',
      type:     $('fType')?.value     || '',
      active:   $('fActive')?.value   || '',
      hours:    $('fHours')?.value    || '0',
      status:   $('fStatus')?.value   || '',
      search:   $('fSearch')?.value   || '',
      page,
      per_page: $('perPage')?.value   || 50,
    });

    const data = await GET(`/api/alerts/get_alerts.php?${params}`);
    const tbody = document.querySelector('#alertsTable tbody');
    if (!tbody) return;

    if (!data.ok || !data.alerts?.length) {
      tbody.innerHTML = '';
      if ($('alertsEmpty')) $('alertsEmpty').style.display = 'block';
      $('pageInfo').textContent = 'No results';
      return;
    }
    if ($('alertsEmpty')) $('alertsEmpty').style.display = 'none';

    totalPages = data.total_pages || 1;
    $('pageInfo').textContent = `Page ${page} of ${totalPages}  (${data.total || 0} alerts)`;

    tbody.innerHTML = data.alerts.map(a => {
      const noteData = (() => { try { return JSON.parse(a.admin_note||'{}'); } catch { return {}; } })();
      const caseName = noteData.case_name || `Alert #${a.id}`;
      return `
        <tr data-id="${a.id}" style="cursor:pointer">
          <td class="col-cb"><input type="checkbox" class="alert-cb" data-id="${a.id}"></td>
          <td style="color:#7a9bbf;font-weight:600">#${esc(a.id)}</td>
          <td>${sevBadge(a.severity)}</td>
          <td style="color:#b8c7dc">${esc(a.alert_type)}</td>
          <td style="font-family:monospace;font-size:12px">${esc(a.source_ip||'—')}</td>
          <td>${statusBadge(a.status||'open')}</td>
          <td style="font-size:12px;color:#7a9bbf">${esc(a.assigned_username||'—')}</td>
          <td>${esc(a.count||1)}</td>
          <td style="font-size:12px;color:#4a6a8a">${esc((a.acknowledged_time||'').slice(0,16)||'—')}</td>
          <td>
            <button class="btn small" onclick="openAlertModal(${a.id});event.stopPropagation()">
              Open
            </button>
          </td>
        </tr>`;
    }).join('');

    // Row click → open modal
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', e => {
        if (e.target.classList.contains('alert-cb')) return;
        openAlertModal(parseInt(row.dataset.id));
      });
    });

    // Checkboxes
    tbody.querySelectorAll('.alert-cb').forEach(cb => {
      cb.addEventListener('change', syncBulkBar);
    });

    $('alertsSelectAll')?.addEventListener('change', e => {
      qsa('#alertsTable tbody .alert-cb').forEach(cb => cb.checked = e.target.checked);
      syncBulkBar();
    });
  }

  function syncBulkBar() {
    const checked = qsa('#alertsTable tbody .alert-cb:checked').length;
    const bar = $('alertsBulkBar');
    if (bar) bar.style.display = checked > 0 ? 'flex' : 'none';
    const cnt = $('alertsBulkCount');
    if (cnt) cnt.textContent = `${checked} alert${checked !== 1 ? 's' : ''} selected`;
  }

  // ── Pagination ───────────────────────────────────────────────────────────
  $('btnFilter')?.addEventListener('click', () => { page = 1; loadAlerts(); });
  $('prevPage')?.addEventListener('click',  () => { if (page > 1) { page--; loadAlerts(); } });
  $('nextPage')?.addEventListener('click',  () => { if (page < totalPages) { page++; loadAlerts(); } });

  // ── Bulk actions ─────────────────────────────────────────────────────────
  $('alertsBulkAck')?.addEventListener('click', async () => {
    const ids = qsa('#alertsTable tbody .alert-cb:checked').map(cb => parseInt(cb.dataset.id));
    await Promise.all(ids.map(id => POST('/api/alerts/escalate.php', { action:'status', alert_id:id, status:'resolved' })));
    loadAlerts();
  });
  $('alertsBulkDelete')?.addEventListener('click', async () => {
    if (!confirm(`Delete ${qsa('#alertsTable tbody .alert-cb:checked').length} alerts?`)) return;
    const ids = qsa('#alertsTable tbody .alert-cb:checked').map(cb => parseInt(cb.dataset.id));
    await Promise.all(ids.map(id => POST('/api/alerts/delete.php', { id })));
    loadAlerts();
  });
  $('alertsBulkClear')?.addEventListener('click', () => {
    qsa('#alertsTable tbody .alert-cb').forEach(cb => cb.checked = false);
    if ($('alertsSelectAll')) $('alertsSelectAll').checked = false;
    syncBulkBar();
  });

  // ── Alert detail / escalation modal ─────────────────────────────────────
  let analysts = [];

  async function loadAnalysts() {
    const d = await GET('/api/alerts/escalate.php?action=analysts');
    analysts = d.analysts || [];
    const sel = $('mdAssignee');
    if (!sel) return;
    sel.innerHTML = '<option value="">— Unassigned —</option>' +
      analysts.map(a => `<option value="${a.id}">${esc(a.username)}</option>`).join('');
  }

  window.openAlertModal = async function(alert_id) {
    currentAlertId = alert_id;
    $('alertModalTitle').textContent = `Alert #${alert_id}`;
    $('alertModal').classList.remove('hidden');
    $('mdDetails').textContent = 'Loading…';
    $('mdNotes').innerHTML = '';

    const d = await GET(`/api/alerts/escalate.php?action=detail&alert_id=${alert_id}`);
    if (!d.ok) { $('mdDetails').textContent = d.error; return; }

    const a = d.alert;
    const noteData = (() => { try { return JSON.parse(a.admin_note||'{}'); } catch { return {}; } })();

    // Summary
    $('mdId').textContent       = `#${a.id}`;
    $('mdSeverity').innerHTML   = sevBadge(a.severity);
    $('mdType').textContent     = a.alert_type;
    $('mdIp').textContent       = a.source_ip || '—';
    $('mdCount').textContent    = a.count || 1;
    $('mdStatus').value         = a.status || 'open';

    // Assignment
    if ($('mdAssignee') && analysts.length) {
      $('mdAssignee').value = a.assigned_to || '';
    }
    $('mdAssignInfo').innerHTML = a.assigned_username
      ? `Assigned to <strong style="color:#c5d8f0">${esc(a.assigned_username)}</strong>` +
        ` at ${esc((a.assigned_at||'').slice(0,16))}`
      : 'Not yet assigned';

    // Details
    $('mdDetails').textContent = JSON.stringify(noteData, null, 2);

    // Notes thread
    renderNotes(d.notes || []);
  };

  function renderNotes(notes) {
    const el = $('mdNotes');
    if (!notes.length) {
      el.innerHTML = '<div style="font-size:12px;color:#2a4a6a;padding:8px 0">No notes yet.</div>';
      return;
    }
    el.innerHTML = notes.map(n => {
      const isSystem = n.author === 'system' || n.note.endsWith('.');
      return `
        <div class="note-entry ${isSystem ? 'note-system' : ''}">
          <div class="note-meta">
            <strong>${esc(n.author)}</strong> &nbsp;·&nbsp; ${esc((n.created_at||'').slice(0,16))}
          </div>
          <div class="note-body">${esc(n.note)}</div>
        </div>`;
    }).join('');
    // Scroll to bottom of notes
    el.scrollTop = el.scrollHeight;
  }

  // Status change
  $('btnSetStatus')?.addEventListener('click', async () => {
    if (!currentAlertId) return;
    const status = $('mdStatus').value;
    const r = await POST('/api/alerts/escalate.php', {
      action:'status', alert_id:currentAlertId, status
    });
    if (!r.ok) { alert(r.error); return; }
    refreshModalNotes();
    loadAlerts();
  });

  // Assign
  $('btnAssign')?.addEventListener('click', async () => {
    if (!currentAlertId) return;
    const analyst_id = parseInt($('mdAssignee').value) || 0;
    const r = await POST('/api/alerts/escalate.php', {
      action:'assign', alert_id:currentAlertId, analyst_id
    });
    if (!r.ok) { alert(r.error); return; }
    // Refresh assignment info
    const d = await GET(`/api/alerts/escalate.php?action=detail&alert_id=${currentAlertId}`);
    if (d.ok) {
      $('mdAssignInfo').innerHTML = d.alert.assigned_username
        ? `Assigned to <strong style="color:#c5d8f0">${esc(d.alert.assigned_username)}</strong>` +
          ` at ${esc((d.alert.assigned_at||'').slice(0,16))}`
        : 'Not yet assigned';
      renderNotes(d.notes || []);
    }
    loadAlerts();
  });

  // Add note
  $('btnAddNote')?.addEventListener('click', addNote);
  $('mdNoteInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.ctrlKey) addNote();
  });

  async function addNote() {
    if (!currentAlertId) return;
    const note = $('mdNoteInput').value.trim();
    if (!note) return;
    const r = await POST('/api/alerts/escalate.php', {
      action:'note', alert_id:currentAlertId, note
    });
    if (!r.ok) { alert(r.error); return; }
    $('mdNoteInput').value = '';
    renderNotes(r.notes || []);
  }

  async function refreshModalNotes() {
    if (!currentAlertId) return;
    const d = await GET(`/api/alerts/escalate.php?action=detail&alert_id=${currentAlertId}`);
    if (d.ok) renderNotes(d.notes || []);
  }

  // Close modal
  function closeModal() {
    $('alertModal').classList.add('hidden');
    currentAlertId = null;
  }
  $('alertModalClose')?.addEventListener('click',  closeModal);
  $('alertModalClose2')?.addEventListener('click', closeModal);
  $('alertModalOverlay')?.addEventListener('click', closeModal);

  // ── MTTA/MTTR metrics modal ──────────────────────────────────────────────
  async function openMetrics() {
    $('metricsModal').classList.remove('hidden');
    $('metricsBody').innerHTML = 'Loading…';
    const d = await GET('/api/alerts/escalate.php?action=metrics');
    if (!d.ok) { $('metricsBody').innerHTML = `Error: ${esc(d.error)}`; return; }
    const rows = d.metrics || [];
    if (!rows.length) { $('metricsBody').innerHTML = '<div class="empty">No data yet.</div>'; return; }
    $('metricsBody').innerHTML = `
      <table class="metric-table">
        <thead>
          <tr>
            <th>Analyst</th>
            <th>Assigned</th>
            <th>Acked</th>
            <th>Resolved</th>
            <th>Avg MTTA (min)</th>
            <th>Avg MTTR (min)</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r => `
            <tr>
              <td style="color:#c5d8f0">${esc(r.username)}</td>
              <td>${esc(r.total_assigned)}</td>
              <td>${esc(r.total_acked)}</td>
              <td>${esc(r.total_resolved)}</td>
              <td>${r.avg_mtta_minutes ?? '—'}</td>
              <td>${r.avg_mttr_minutes ?? '—'}</td>
            </tr>`).join('')}
        </tbody>
      </table>
      <div style="font-size:11px;color:#4a6a8a;margin-top:10px">
        MTTA = Mean Time to Acknowledge &nbsp;·&nbsp; MTTR = Mean Time to Resolve
      </div>`;
  }
  $('metricsModalClose')?.addEventListener('click',  () => $('metricsModal').classList.add('hidden'));
  $('metricsModalClose2')?.addEventListener('click', () => $('metricsModal').classList.add('hidden'));
  $('metricsOverlay')?.addEventListener('click',     () => $('metricsModal').classList.add('hidden'));

  // ── Bell notifications ───────────────────────────────────────────────────
  async function loadNotifications() {
    const d = await GET('/api/notifications.php');
    if (!d.ok) return;
    const count = d.notifications?.length || 0;
    const badge = $('notiBadge');
    if (badge) badge.textContent = count > 99 ? '99+' : count;
    const list = $('notiList');
    if (list) {
      list.innerHTML = count
        ? d.notifications.map(n => `
            <div class="dropdown-item" onclick="openAlertModal(${n.alert_id||0})">
              <div style="font-size:12px;color:#c5d8f0">${esc(n.message)}</div>
              <div style="font-size:11px;color:#4a6a8a">${esc((n.created_at||'').slice(0,16))}</div>
            </div>`).join('')
        : '<div class="dropdown-item" style="color:#4a6a8a">No notifications</div>';
    }
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  (async function init() {
    await Promise.all([loadAlerts(), loadAnalysts(), loadNotifications()]);
    setInterval(loadAlerts,       15000);
    setInterval(loadNotifications, 10000);

    // Add metrics button to page if not present
    const filterBar = document.querySelector('.filters');
    if (filterBar) {
      const mb = document.createElement('button');
      mb.className = 'btn small';
      mb.textContent = '📊 Response Metrics';
      mb.style.marginLeft = '8px';
      mb.addEventListener('click', openMetrics);
      filterBar.appendChild(mb);
    }

    // Bell toggle
    $('notiBell')?.addEventListener('click', () => {
      $('notiMenu')?.classList.toggle('hidden');
    });
  })();

})();
