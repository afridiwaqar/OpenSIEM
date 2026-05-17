/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $  = (id)       => document.getElementById(id);
  const qsa = (sel, r=document) => Array.from(r.querySelectorAll(sel));

  let csrf          = null;
  let editingCaseId = null;

  // Hits pagination
  let allHitsData  = [];
  let hitsPage     = 1;
  let hitsPerPage  = 50;

  (async function init() {
    if (!$('hitsPane')) return;

    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;

    // ── Tab switching ──
    qsa('.tab').forEach(t => t.addEventListener('click', () => {
      qsa('.tab').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      const target = t.getAttribute('data-tab');
      qsa('.pane').forEach(p => p.classList.remove('active'));
      $(target).classList.add('active');
      if (target === 'hitsPane') loadHits().catch(console.error);
    }));

    // ── Reload rules ──
    $('reloadRulesBtn').addEventListener('click', reloadRules);

    $('hitsPerPage')?.addEventListener('change', () => {
      hitsPerPage = parseInt($('hitsPerPage').value, 10) || 50;
      hitsPage = 1; renderHits();
    });
    $('hitsPrev')?.addEventListener('click', () => {
      if (hitsPage > 1) { hitsPage--; renderHits(); }
    });
    $('hitsNext')?.addEventListener('click', () => {
      if (hitsPage * hitsPerPage < allHitsData.length) { hitsPage++; renderHits(); }
    });

    // ── "Add log line" button in Create form ──
    $('addLineBtn').addEventListener('click', () => appendCreateLine(''));

    // ── Save (create or update) ──
    $('btnSaveUC').addEventListener('click', saveUseCase);

    // ── Cancel edit (reset form to Create mode) ──
    $('btnCancelEdit').addEventListener('click', resetCreateForm);

    // ── Edit modal wiring ──
    $('editModalClose').addEventListener('click', hideEditModal);
    $('editCancelBtn').addEventListener('click',  hideEditModal);
    $('editSaveBtn').addEventListener('click',    saveEditModal);
    $('editDeleteUC').addEventListener('click',   deleteFromEditModal);
    $('editAddLineBtn').addEventListener('click', () => appendEditLine(null));
    document.querySelector('#editModal .modal-backdrop')
      ?.addEventListener('click', hideEditModal);

    // ── Hit modal wiring ──
    $('hitModalClose').addEventListener('click', hideHitModal);
    document.querySelector('#hitModal .modal-backdrop')
      ?.addEventListener('click', hideHitModal);

    appendCreateLine('');

    // ── Initial data load ──
    await Promise.all([loadHits(), loadUseCases(), loadNotifications()]);

    setInterval(loadHits,         8000);
    setInterval(loadNotifications, 5000);
  })();

  function appendCreateLine(value, canRepeat=false, enforceOrder=false) {
    const container = $('logLinesList');
    const idx       = container.children.length + 1;

    const row = document.createElement('div');
    row.className = 'log-line';
    row.innerHTML = `
      <span class="line-num">${idx}</span>
      <input type="text" placeholder="Log message to match…" value="${escHtml(value)}">
      <div class="line-flags">
        <label class="line-flag">
          <input type="checkbox" class="chk-repeat" ${canRepeat ? 'checked' : ''}> Repeat
        </label>
        <label class="line-flag">
          <input type="checkbox" class="chk-order" ${enforceOrder ? 'checked' : ''}> Order
        </label>
      </div>
      <button type="button" class="del-line" title="Remove line">✕</button>
    `;

    row.querySelector('.del-line').addEventListener('click', () => {
      row.remove();
      renumberLines($('logLinesList'), '.line-num');
    });

    container.appendChild(row);
    if (value === '') row.querySelector('input[type=text]').focus();
  }

  function renumberLines(container, numSel) {
    qsa('.log-line, .edit-line', container).forEach((row, i) => {
      const n = row.querySelector(numSel);
      if (n) n.textContent = i + 1;
    });
  }

  function getCreateLines() {
    return qsa('#logLinesList .log-line')
      .map(row => ({
        message:    row.querySelector('input[type=text]').value.trim(),
        can_repeat: row.querySelector('.chk-repeat')?.checked ?? false,
        order:      row.querySelector('.chk-order')?.checked  ?? false,
      }))
      .filter(l => l.message);
  }

  function resetCreateForm() {
    editingCaseId = null;
    $('formCardTitle').textContent   = 'Create New Rule';
    $('btnSaveUC').textContent       = 'Save Rule';
    $('btnCancelEdit').style.display = 'none';
    $('ucName').value   = '';
    $('ucEntity').value = 'ip';
    $('logLinesList').innerHTML = '';
    appendCreateLine('');
  }

  async function saveUseCase() {
    const name   = $('ucName').value.trim();
    const entity = $('ucEntity').value;
    const lines  = getCreateLines();

    if (!name)         return alert('Case Name is required.');
    if (!lines.length) return alert('Add at least one log line.');

    // 1. Create the use case
    const res = await POST('/api/correlation/save_rule.php', {
      action: 'create_use_case', case_name: name, entity_field: entity
    });

    if (!res.ok) return alert(res.error || 'Failed to create use case.');

    const caseId = res.case_id ?? res.id ?? res.new_id ?? res.data?.case_id ?? null;
    if (!caseId) {
      return alert(
        'Use case was created but the server did not return its ID.\n' +
        'Response was: ' + JSON.stringify(res) + '\n\n' +
        'Check your save_rule.php — it needs to return {"ok":true,"case_id":<id>}.'
      );
    }

    // 2. Add each rule line with its own flags
    for (const line of lines) {
      const r = await POST('/api/correlation/save_rule.php', {
        action:     'add_rule',
        case_id:    caseId,
        message:    line.message,
        can_repeat: line.can_repeat,
        order:      line.order,
      });
      if (!r.ok) {
        alert('Use case created but a rule failed to save: ' + (r.error || 'unknown'));
        break;
      }
    }

    resetCreateForm();
    await loadUseCases();
  }

  async function loadUseCases() {
    const data = await GET('/api/correlation/list_rules.php');
    const el   = $('useCasesList');
    if (!el) return;

    if (!Array.isArray(data) || data.length === 0) {
      el.innerHTML = '<div class="empty">No use cases defined yet.</div>';
      return;
    }

    el.innerHTML = '';

    data.forEach((uc, ucIdx) => {
      const item = document.createElement('div');
      item.className = 'uc-item';

      const rulesHTML = (uc.rules || []).map((r, i) => `
        <div class="uc-rule-row">
          <span class="uc-rule-num">${i + 1}.</span>
          <span class="uc-rule-msg" title="${escHtml(String(r.message||''))}">${escHtml(String(r.message||''))}</span>
          <span class="pill">${r.can_repeat ? 'repeat' : 'no-repeat'}</span>
          <span class="pill">${r.order     ? 'ordered' : 'unordered'}</span>
        </div>
      `).join('') || '<div class="muted" style="font-size:12px;padding:4px 0">No rules yet.</div>';

      item.innerHTML = `
        <div class="uc-left">
          <div class="uc-title">${ucIdx + 1}. ${escHtml(uc.case_name)}</div>
          <div class="uc-meta">case_id: ${uc.case_id} &nbsp;·&nbsp; entity: ${uc.entity_field}</div>
          <div class="uc-rules">${rulesHTML}</div>
        </div>
        <div style="flex-shrink:0">
          <button class="btn small" data-edit="${uc.case_id}">Edit</button>
        </div>
      `;

      item.querySelector('[data-edit]').addEventListener('click', () =>
        openEditModal(uc)
      );

      el.appendChild(item);
    });
  }

  let _editUc = null;   // snapshot of the UC being edited

  function openEditModal(uc) {
    _editUc = uc;

    $('editModalTitle').textContent = `Edit: ${uc.case_name}`;
    $('editUcName').value   = uc.case_name;
    $('editUcEntity').value = uc.entity_field || 'ip';

    const list = $('editLinesList');
    list.innerHTML = '';
    (uc.rules || []).forEach(r => appendEditLine(r));

    $('editModal').classList.remove('hidden');
  }

  function hideEditModal() {
    $('editModal').classList.add('hidden');
    _editUc = null;
  }

  function appendEditLine(r) {
    const list  = $('editLinesList');
    const idx   = list.children.length + 1;
    const isNew = r === null;
    const canRepeat    = isNew ? false : !!r.can_repeat;
    const enforceOrder = isNew ? false : !!r.order;

    const row = document.createElement('div');
    row.className       = 'edit-line';
    row.dataset.msgId   = isNew ? '' : (r.msg_id || '');
    row.dataset.isNew   = isNew ? '1' : '0';

    row.innerHTML = `
      <span class="line-num">${idx}</span>
      <input type="text" placeholder="Log message to match…"
             value="${escHtml(isNew ? '' : String(r.message||''))}">
      <div class="line-flags">
        <label class="line-flag">
          <input type="checkbox" class="chk-repeat" ${canRepeat    ? 'checked' : ''}> Repeat
        </label>
        <label class="line-flag">
          <input type="checkbox" class="chk-order"  ${enforceOrder ? 'checked' : ''}> Order
        </label>
      </div>
      <button type="button" class="del-line" title="Remove">✕</button>
    `;

    row.querySelector('.del-line').addEventListener('click', async () => {
      if (!isNew && row.dataset.msgId) {
        if (!confirm('Delete this rule from the database?')) return;
        const res = await POST('/api/correlation/save_rule.php', {
          action: 'delete_rule', msg_id: parseInt(row.dataset.msgId, 10)
        });
        if (!res.ok) return alert(res.error || 'Delete failed');
      }
      row.remove();
      renumberLines($('editLinesList'), '.line-num');
    });

    list.appendChild(row);
    if (isNew) row.querySelector('input[type=text]').focus();
  }

  async function saveEditModal() {
    if (!_editUc) return;
    const caseId = _editUc.case_id;
    const name   = $('editUcName').value.trim();
    const entity = $('editUcEntity').value;

    if (!name) return alert('Case Name is required.');

    if (name !== _editUc.case_name || entity !== (_editUc.entity_field || 'ip')) {
      const r = await POST('/api/correlation/save_rule.php', {
        action: 'update_use_case', case_id: caseId, case_name: name, entity_field: entity
      });
      if (!r.ok) return alert(r.error || 'Failed to update use case.');
    }

    const rows = qsa('#editLinesList .edit-line');

    for (const row of rows) {
      const msg          = row.querySelector('input[type=text]').value.trim();
      const can_repeat   = row.querySelector('.chk-repeat')?.checked ?? false;
      const order        = row.querySelector('.chk-order')?.checked  ?? false;
      const isNew        = row.dataset.isNew === '1';
      const msgId        = parseInt(row.dataset.msgId, 10);

      if (!msg) continue;

      if (isNew) {
        const r = await POST('/api/correlation/save_rule.php', {
          action: 'add_rule', case_id: caseId, message: msg, can_repeat, order
        });
        if (!r.ok) alert('A new rule failed to save: ' + (r.error || 'unknown'));
      } else if (msgId) {
        // Update if message or flags changed
        const original = (_editUc.rules || []).find(x => x.msg_id === msgId);
        if (original && (
          original.message    !== msg        ||
          !!original.can_repeat !== can_repeat  ||
          !!original.order      !== order
        )) {
          const r = await POST('/api/correlation/save_rule.php', {
            action: 'update_rule', msg_id: msgId, message: msg, can_repeat, order
          });
          if (!r.ok) alert('A rule failed to update: ' + (r.error || 'unknown'));
        }
      }
    }

    hideEditModal();
    await loadUseCases();
  }

  async function deleteFromEditModal() {
    if (!_editUc) return;
    if (!confirm(`Delete use case "${_editUc.case_name}" and ALL its rules? This cannot be undone.`)) return;
    const res = await POST('/api/correlation/save_rule.php', {
      action: 'delete_use_case', case_id: _editUc.case_id
    });
    if (!res.ok) return alert(res.error || 'Delete failed.');
    hideEditModal();
    await loadUseCases();
  }


  async function loadHits() {
    const table = $('hitsTable');
    if (!table) return;
    const data = await GET('/api/correlation/list_hits.php');
    allHitsData = (Array.isArray(data) ? data : []).sort((a, b) => {
      if (a.is_active !== b.is_active) return a.is_active ? -1 : 1;
      return (b.last_seen || '') > (a.last_seen || '') ? 1 : -1;
    });
    hitsPage = 1;
    renderHits();
  }

  function renderHits() {
    const table = $('hitsTable');
    if (!table) return;
    const tb    = table.tBodies[0] || table.createTBody();
    const empty = $('hitsEmpty');
    tb.innerHTML = '';

    if (allHitsData.length === 0) {
      if (empty) empty.style.display = 'block';
      if ($('hitsPageInfo')) $('hitsPageInfo').textContent = '';
      return;
    }
    if (empty) empty.style.display = 'none';

    const totalPages = Math.ceil(allHitsData.length / hitsPerPage) || 1;
    if (hitsPage > totalPages) hitsPage = totalPages;
    const start  = (hitsPage - 1) * hitsPerPage;
    const pageData = allHitsData.slice(start, start + hitsPerPage);

    if ($('hitsPageInfo')) $('hitsPageInfo').textContent =
      `Page ${hitsPage} of ${totalPages}  (${allHitsData.length} total)`;

    for (const a of pageData) {
      let caseName = '';
      try {
        const note = JSON.parse(a.admin_note || '{}');
        caseName = note.case_name || note.details?.case_name || '';
      } catch (_) {}

      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      if (a.is_active) tr.style.borderLeft = '3px solid #b01828';
      tr.innerHTML = `
        <td>${a.id}</td>
        <td>${(a.severity||'mid').toUpperCase()}</td>
        <td>${a.source_ip||'n/a'}</td>
        <td>${escHtml(caseName) || '—'}</td>
        <td>${a.is_active ? '<span style="color:#7ecb7e">● Yes</span>'
                          : '<span style="color:#4a5a6e">● No</span>'}</td>
        <td>${a.is_active
          ? `<button class="btn small ack" data-id="${a.id}">Ack</button>`
          : '—'
        }</td>
        <td>${a.last_seen||'—'}</td>
      `;
      tr.addEventListener('click', ev => {
        if (ev.target.closest('.ack')) return;
        openHitModal(a.id).catch(console.error);
      });
      tb.appendChild(tr);
    }

    table.querySelectorAll('.ack').forEach(btn => {
      btn.addEventListener('click', async () => {
        await POST('/api/ack_alert.php', { id: parseInt(btn.dataset.id, 10) });
        await loadHits();
        loadNotifications().catch(()=>{});
      });
    });
  }


  function hideHitModal()  { $('hitModal').classList.add('hidden'); }

  async function openHitModal(alertId) {
    const body   = $('hitModalBody');
    const ackBtn = $('hitAckBtn');
    if (!body || !ackBtn) return;

    const d = await GET(`/api/alerts/details.php?id=${encodeURIComponent(alertId)}`);
    if (!d.ok) { alert(d.error || 'Failed to load details'); return; }

    const a   = d.alert || {};
    const occ = Array.isArray(d.occurrences) ? d.occurrences : [];

    let caseName = '';
    try {
      const note = JSON.parse(a.admin_note || '{}');
      caseName = note.case_name || note.details?.case_name || '';
    } catch {}

    const kv = `<div class="kv">
      <span class="pill">ID: ${a.id}</span>
      <span class="pill">Severity: ${(a.severity||'mid').toUpperCase()}</span>
      <span class="pill">Type: ${a.alert_type||'correlation'}</span>
      <span class="pill">Source IP: ${a.source_ip||'n/a'}</span>
      <span class="pill">Active: ${a.is_active ? 'Yes' : 'No'}</span>
      ${a.acknowledged_time ? `<span class="pill">Ack: ${a.acknowledged_time}</span>` : ''}
      ${a.count ? `<span class="pill">Count: ${a.count}</span>` : ''}
    </div>`;

    const timeline = occ.length
      ? occ.map(o => {
          const tx  = (o.text && typeof o.text === 'string') ? o.text : '';
          const safe = escHtml(tx);
          return `<div class="item">
            <div class="ts">${o.occurred_at||''}</div>
            <div class="msg">${safe||'(no raw line)'}</div>
          </div>`;
        }).join('')
      : '<div class="item"><div class="msg">No occurrences recorded.</div></div>';

    body.innerHTML = `
      <div style="margin-bottom:10px; color:#b8c7dc; font-weight:600; font-size:14px;">
        ${escHtml(caseName) || 'Correlation Hit'}
      </div>
      ${kv}
      <div class="timeline">${timeline}</div>
    `;

    ackBtn.disabled = !a.is_active;
    ackBtn.onclick = async () => {
      await POST('/api/ack_alert.php', { id: a.id });
      await loadHits();
      loadNotifications().catch(()=>{});
      hideHitModal();
    };

    $('hitModal').classList.remove('hidden');
  }

  async function loadNotifications() {
    const d     = await GET('/api/get_notifications.php');
    const badge = $('notiBadge');
    if (badge) badge.textContent = d.count ?? 0;

    const list = $('notiList');
    if (!list) return;
    list.innerHTML = '';

    (d.items || []).forEach(a => {
      const div = document.createElement('div');
      const sev = (a.severity||'mid').toLowerCase();
      div.className = 'noti-item';
      div.innerHTML = `
        <div>
          <div class="noti-kind">${(a.alert_type||'').toUpperCase()} — ${a.source_ip||'n/a'}</div>
          <div class="noti-sev ${sev}">${(a.severity||'MID').toUpperCase()}</div>
        </div>
        <button class="btn small noti-ack" data-id="${a.id}">ACK</button>
      `;
      list.appendChild(div);
    });

    list.querySelectorAll('.noti-ack').forEach(btn => btn.onclick = async () => {
      await POST('/api/ack_alert.php', { id: parseInt(btn.dataset.id, 10) });
      await loadNotifications();
    });

    const bell = $('notiBell'), menu = $('notiMenu');
    if (bell && menu) {
      bell.onclick = () => menu.classList.toggle('hidden');
      document.addEventListener('click', e => {
        if (!menu.contains(e.target) && !bell.contains(e.target))
          menu.classList.add('hidden');
      }, { passive:true });
    }
  }

  async function reloadRules() {
    const res = await POST('/api/reload_rules.php', {});
    alert(res.ok ? 'Correlation rules reloaded.' : ('Reload failed: ' + (res.error||'unknown')));
  }

  async function GET(path) {
    const r = await fetch(path, { cache:'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); } catch { console.error('GET parse error', path, t); return {ok:false}; }
  }

  async function POST(path, body) {
    const r = await fetch(path, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-CSRF-Token': csrf},
      body: JSON.stringify(body || {})
    });
    const t = await r.text();
    try { return JSON.parse(t); } catch { console.error('POST parse error', path, t); return {ok:false}; }
  }

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, ch =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])
    );
  }

})();
