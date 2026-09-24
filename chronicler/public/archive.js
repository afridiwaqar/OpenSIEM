// /var/www/chronicler/public/archive.js
(() => {
  const $   = id  => document.getElementById(id);
  const esc = s   => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  const fmt_bytes = b => {
    b = Number(b);
    if (b >= 1e12) return (b/1e12).toFixed(2) + ' TB';
    if (b >= 1e9)  return (b/1e9).toFixed(2)  + ' GB';
    if (b >= 1e6)  return (b/1e6).toFixed(1)  + ' MB';
    return b + ' B';
  };
  const fmt_date = s => s ? s.slice(0,10) : '—';

  // ── API helpers ────────────────────────────────────────────────────────────
  async function GET(path) {
    const r = await fetch(path, { cache: 'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); } catch { return { ok: false, error: t }; }
  }
  async function POST(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
    const t = await r.text();
    try { return JSON.parse(t); } catch { return { ok: false, error: t }; }
  }

  // ── Tab switching ──────────────────────────────────────────────────────────
  let activeTab = 'overview';
  let rhydPollTimer = null;
  document.querySelectorAll('.arch-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.arch-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.arch-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      if (tab !== 'rehydrate' && rhydPollTimer) {
        clearTimeout(rhydPollTimer);
        rhydPollTimer = null;
      }
      activeTab = tab;
      document.getElementById(`panel-${tab}`)?.classList.add('active');
      if (tab === 'overview')    loadOverview();
      if (tab === 'rehydrate')   loadRehydrations();
      if (tab === 'partitions')  loadPartitions();
      if (tab === 'policy')      loadPolicy();
      if (tab === 'storage')     loadStorageBackends();
      if (tab === 'audit')       loadAuditLog();
    });
  });

  // ── Boot ───────────────────────────────────────────────────────────────────
  (async function init() {
    loadOverview();
    setupSearch();
    setupRehydrate();
    setupPartitions();
    setupPolicy();
    setupStorage();
    setupAudit();

    $('btnRunNow')?.addEventListener('click', async () => {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const defaultDate = yesterday.toISOString().slice(0, 10);

      const d = prompt(
        'Archive data for which date?\n\n' +
        'This will export that day\'s logs from PostgreSQL to the archive storage.\n' +
        'The day must be older than your hot_retention_days setting for the\n' +
        'nightly job, but you can manually archive any date here.',
        defaultDate
      );
      if (!d) return;

      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) {
        alert('Invalid date format. Use YYYY-MM-DD.');
        return;
      }

      if (!confirm(`Archive ${d}?\n\nThis will:\n1. Export all logs for ${d} to Parquet\n2. Verify the file integrity\n3. Delete from PostgreSQL if verify passes\n\nThis cannot be undone.`)) return;

      $('btnRunNow').disabled = true;
      $('btnRunNow').textContent = '⏳ Running...';

      const r = await POST('/api/archive/run.php', { action: 'run', date: d });

      $('btnRunNow').disabled = false;
      $('btnRunNow').textContent = '▶ Run Archive Now';

      if (r.ok) {
        const rows  = r.rows_total ?? 0;
        const bytes = r.bytes_total ?? 0;
        alert(`✓ Archive complete for ${d}\n\nRows archived: ${rows.toLocaleString()}\nSize: ${fmt_bytes(bytes)}`);
        loadOverview();
      } else {
        alert(`✗ Archive failed for ${d}\n\nError: ${r.error || 'unknown'}\n\n${r.raw || ''}`);
      }
    });

    $('btnVerifyAll')?.addEventListener('click', async () => {
      if (!confirm('Verify integrity of all archive partitions? This may take a while.')) return;
      const r = await POST('/api/archive/run.php', { action: 'verify', all: true });
      if (!r.ok) { alert(`Verification failed: ${r.error}`); return; }
      const failed = (r.results || []).filter(x => !x.ok).length;
      const ok     = (r.results || []).filter(x => x.ok).length;
      alert(`Verification complete.\n✓ ${ok} passed\n✗ ${failed} failed`);
      loadPartitions();
    });
  })();

  // ══════════════════════════════════════════════════════════════════════════
  // OVERVIEW
  // ══════════════════════════════════════════════════════════════════════════
  async function loadOverview() {
    const d = await GET('/api/archive/status.php');
    if (!d.ok) { $('overviewStats').innerHTML = `<div class="empty">Error: ${esc(d.error)}</div>`; return; }

    const arch = d.archive || {};
    const pol  = d.policy  || {};

    const threshold_bytes = (pol.storage_alert_threshold_gb || 100) * 1024**3;
    const pct = threshold_bytes > 0
      ? Math.min(100, Math.round(arch.total_bytes / threshold_bytes * 100))
      : 0;
    const barClass = pct >= 90 ? 'danger' : pct >= 70 ? 'warn' : '';

    $('overviewStats').innerHTML = `
      <div class="stat-card">
        <div class="label">Archive Size</div>
        <div class="value">${fmt_bytes(arch.total_bytes)}</div>
        <div class="sub">of ${pol.storage_alert_threshold_gb || 100} GB threshold</div>
      </div>
      <div class="stat-card">
        <div class="label">Hot Retention</div>
        <div class="value">${pol.hot_retention_days ?? '—'}</div>
        <div class="sub">days in PostgreSQL</div>
      </div>
      <div class="stat-card">
        <div class="label">Cold Retention</div>
        <div class="value">${pol.cold_retention_days ?? '—'}</div>
        <div class="sub">days in archive</div>
      </div>
      <div class="stat-card">
        <div class="label">Oldest Partition</div>
        <div class="value" style="font-size:16px">${fmt_date(arch.oldest_date) || '—'}</div>
      </div>
      <div class="stat-card">
        <div class="label">Newest Partition</div>
        <div class="value" style="font-size:16px">${fmt_date(arch.newest_date) || '—'}</div>
      </div>
      <div class="stat-card">
        <div class="label">Monthly Growth</div>
        <div class="value" style="font-size:16px">${fmt_bytes(arch.monthly_avg_bytes)}</div>
        <div class="sub">average per month</div>
      </div>
    `;

    $('storageBarWrap').innerHTML = `
      <div style="display:flex;justify-content:space-between;font-size:12px;color:#7a9bbf">
        <span>Storage Usage</span>
        <span>${fmt_bytes(arch.total_bytes)} / ${fmt_bytes(threshold_bytes)} (${pct}%)</span>
      </div>
      <div class="storage-bar-bg">
        <div class="storage-bar-fill ${barClass}" style="width:${pct}%"></div>
      </div>
      ${arch.over_threshold
        ? '<div style="color:#f0c040;font-size:12px">⚠ Storage alert threshold exceeded</div>'
        : ''}
    `;

    const lr = d.last_run;
    $('lastRunInfo').innerHTML = lr
      ? `<div class="rehy-card">
           <div style="font-size:13px;color:#c5d8f0">
             ${esc(lr.occurred_at?.slice(0,19) || '—')} &nbsp;—&nbsp;
             ${esc(lr.action)} &nbsp;
             <span style="color:#7ecb7e">✓ Success</span>
           </div>
           <div style="font-size:12px;color:#4a6a8a;margin-top:4px">
             ${esc(JSON.stringify(lr.detail || {}))}
           </div>
         </div>`
      : '<div class="empty">No archive runs recorded yet.</div>';

    const rh = d.active_rehydrations || [];
    $('overviewRehydrations').innerHTML = rh.length
      ? rh.map(r => renderRehydrationCard(r)).join('')
      : '<div class="empty" style="font-size:13px">No active rehydrations.</div>';
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SEARCH
  // ══════════════════════════════════════════════════════════════════════════
  let srchPage = 1;
  let srchTotal = 0;

  function setupSearch() {
    $('btnSearch')?.addEventListener('click', () => { srchPage = 1; doSearch(); });
    $('srchPrev')?.addEventListener('click', () => { if (srchPage > 1) { srchPage--; doSearch(); } });
    $('srchNext')?.addEventListener('click', () => {
      const per = parseInt($('srchPerPage')?.value || 100);
      if (srchPage * per < srchTotal) { srchPage++; doSearch(); }
    });
    $('btnExportCsv')?.addEventListener('click', doExportCsv);
  }

  async function doSearch() {
    const from = $('srchDateFrom')?.value;
    const to   = $('srchDateTo')?.value;
    if (!from || !to) { alert('Date From and Date To are required.'); return; }

    $('searchProgress').style.display = 'block';
    $('searchResults').innerHTML = '';
    $('searchMeta').style.display = 'none';
    $('searchPagination').style.display = 'none';

    const per = parseInt($('srchPerPage')?.value || 100);
    const params = new URLSearchParams({
      date_from:   from,
      date_to:     to,
      device_ip:   $('srchIp')?.value     || '',
      device_name: $('srchDevice')?.value || '',
      action:      $('srchAction')?.value || '',
      level:       $('srchLevel')?.value  || '',
      user:        $('srchUser')?.value   || '',
      source:      $('srchSource')?.value || '',
      message_q:   $('srchMsg')?.value    || '',
      page:        srchPage,
      per_page:    per,
    });

    const t0  = Date.now();
    const res = await GET(`/api/archive/search.php?${params}`);
    $('searchProgress').style.display = 'none';

    if (!res.ok) {
      $('searchResults').innerHTML = `<div class="empty">Error: ${esc(res.error)}</div>`;
      return;
    }

    srchTotal = res.total || 0;
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

    $('searchMeta').style.display = 'block';
    $('searchMeta').innerHTML =
      `Found <span>${srchTotal.toLocaleString()}</span> results &nbsp;·&nbsp; ` +
      `${res.partitions_scanned} partition files &nbsp;·&nbsp; ${elapsed}s`;

    if (res.warning) {
      $('searchResults').innerHTML =
        `<div class="callout" style="margin-bottom:12px">${esc(res.warning)}</div>`;
    }

    if (!res.results?.length) {
      $('searchResults').innerHTML += '<div class="empty">No results.</div>';
      return;
    }

    $('btnExportCsv').style.display = 'inline-block';

    const rows = res.results.map(r => `
      <tr class="expandable-row" style="cursor:pointer">
        <td>${esc(r.log_date)}</td>
        <td>${esc(r.log_time?.slice(0,8))}</td>
        <td>${esc(r.device_ip)}</td>
        <td>${esc(r.device_name)}</td>
        <td>${esc(r.source_name)}</td>
        <td><span class="sev sev-${esc(r.level)}">${esc((r.level||'').toUpperCase())}</span></td>
        <td>${esc(r.action)}</td>
        <td>${esc(r.user)}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${esc(r.message)}
        </td>
      </tr>
      <tr class="detail-row" style="display:none;background:#07090f">
        <td colspan="9" style="padding:10px 14px;font-family:monospace;font-size:11px;
            color:#7ab0d8;word-break:break-all">
          <strong>Message:</strong> ${esc(r.message)}<br>
          <strong>Raw:</strong> ${esc(r.raw_message)}<br>
          ${r.attributes ? `<strong>Attributes:</strong> ${esc(r.attributes)}` : ''}
        </td>
      </tr>
    `).join('');

    $('searchResults').innerHTML += `
      <table class="table">
        <thead>
          <tr>
            <th>Date</th><th>Time</th><th>IP</th><th>Device</th>
            <th>Source</th><th>Sev</th><th>Action</th><th>User</th><th>Message</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;

    $('searchResults').querySelectorAll('.expandable-row').forEach(row => {
      row.addEventListener('click', () => {
        const det = row.nextElementSibling;
        if (det) det.style.display = det.style.display === 'none' ? '' : 'none';
      });
    });

    const pages = Math.ceil(srchTotal / per) || 1;
    $('srchPageInfo').textContent = `Page ${srchPage} of ${pages}`;
    $('searchPagination').style.display = 'flex';
  }

  async function doExportCsv() {
    const params = new URLSearchParams({
      date_from:   $('srchDateFrom')?.value || '',
      date_to:     $('srchDateTo')?.value   || '',
      device_ip:   $('srchIp')?.value       || '',
      device_name: $('srchDevice')?.value   || '',
      action:      $('srchAction')?.value   || '',
      level:       $('srchLevel')?.value    || '',
      user:        $('srchUser')?.value     || '',
      source:      $('srchSource')?.value   || '',
      message_q:   $('srchMsg')?.value      || '',
      export_csv:  1,
      page: 1, per_page: 10000,
    });
    window.location.href = `/api/archive/search.php?${params}`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // REHYDRATE
  // ══════════════════════════════════════════════════════════════════════════
  function setupRehydrate() {
    $('btnRhydEstimate')?.addEventListener('click', doEstimate);
    $('btnRhydStart')?.addEventListener('click', doRehydrate);
  }

  async function doEstimate() {
    const from   = $('rhydFrom')?.value;
    const to     = $('rhydTo')?.value;
    if (!from || !to) { alert('Select a date range first.'); return; }
    const tables = getSelectedTables();
    const res = await POST('/api/archive/rehydrate.php',
      { action: 'estimate', date_from: from, date_to: to, tables });
    if (!res.ok) { alert(res.error); return; }
    $('rhydEstimate').style.display = 'block';
    $('rhydEstimateText').innerHTML =
      `<strong>${res.total_rows?.toLocaleString() || 0}</strong> rows across
       <strong>${res.partitions || 0}</strong> partitions &nbsp;·&nbsp;
       <strong>${res.total_gb || 0} GB</strong> &nbsp;·&nbsp;
       Estimated time: <strong>${res.est_minutes_min}–${res.est_minutes_max} minutes</strong>`;
  }

  async function doRehydrate() {
    const from = $('rhydFrom')?.value;
    const to   = $('rhydTo')?.value;
    if (!from || !to) { alert('Select a date range first.'); return; }
    if (!confirm(`Rehydrate ${from} → ${to}? This will import data into live storage.`)) return;

    const tables      = getSelectedTables();
    const releaseDays = parseInt($('rhydReleaseDays')?.value || 7);
    const res = await POST('/api/archive/rehydrate.php', {
      action: 'start', date_from: from, date_to: to,
      tables, auto_release_days: releaseDays
    });

    if (!res.ok) { alert(`Rehydration failed: ${res.error}`); return; }
    loadRehydrations();
  }

  function getSelectedTables() {
    const t = [];
    if ($('rhydMessages')?.checked) t.push('messages');
    if ($('rhydAlerts')?.checked)   t.push('alerts');
    return t;
  }

  async function loadRehydrations() {
    const res = await GET('/api/archive/rehydrate.php?action=list');
    const el  = $('rhydList');
    if (!res.ok) { el.innerHTML = `<div class="empty">Error: ${esc(res.error)}</div>`; return; }
    const jobs = res.rehydrations || [];
    el.innerHTML = jobs.length
      ? jobs.map(j => renderRehydrationCard(j, true)).join('')
      : '<div class="empty">No rehydrations yet.</div>';

    // Poll while any job is still in flight, so the progress bar and
    // state (pending → running → active, or → cancelled) update without
    // the user needing to switch tabs and back.
    const inFlight = jobs.some(j => j.state === 'pending' || j.state === 'running');
    if (rhydPollTimer) clearTimeout(rhydPollTimer);
    if (inFlight && activeTab === 'rehydrate') {
      rhydPollTimer = setTimeout(loadRehydrations, 4000);
    }
  }

  function renderRehydrationCard(j, showRelease = false) {
    const state    = j.state || 'unknown';
    const tables   = Array.isArray(j.tables) ? j.tables.join(', ') : (j.tables || '');
    const inFlight = state === 'pending' || state === 'running';

    const total = Number(j.partitions_total || 0);
    const done  = Number(j.partitions_done  || 0);
    const pct   = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;

    const progressHtml = inFlight ? `
        <div class="rehy-progress-wrap" style="margin-top:8px">
          <div class="rehy-progress-bar">
            <div class="rehy-progress-fill" style="width:${total > 0 ? pct : 5}%${total === 0 ? ';opacity:.5' : ''}"></div>
          </div>
          <div style="font-size:11px;color:#7a9bbf;margin-top:3px">
            ${total > 0
              ? `${done} / ${total} partitions (${pct}%) &nbsp;·&nbsp; ${Number(j.rows_imported || 0).toLocaleString()} rows imported so far`
              : 'Starting…'}
          </div>
        </div>` : '';

    const actionBtn = inFlight
      ? `<button class="btn secondary" style="font-size:11px;padding:3px 10px"
           onclick="cancelRehydration(${j.id})">Cancel</button>`
      : (showRelease && state === 'active'
          ? `<button class="btn secondary" style="font-size:11px;padding:3px 10px"
               onclick="releaseRehydration(${j.id})">Release Early</button>`
          : '');

    return `
      <div class="rehy-card">
        <div class="rehy-head">
          <div>
            <strong style="color:#c5d8f0">${esc(j.date_from)} → ${esc(j.date_to)}</strong>
            &nbsp;
            <span class="rehy-status ${esc(state)}">${esc(state)}</span>
          </div>
          ${actionBtn}
        </div>
        ${progressHtml}
        <div style="font-size:12px;color:#4a6a8a;margin-top:4px">
          Tables: ${esc(tables)} &nbsp;·&nbsp;
          Rows: ${Number(j.rows_imported || 0).toLocaleString()} &nbsp;·&nbsp;
          By: ${esc(j.started_by)} &nbsp;·&nbsp;
          Started: ${esc(j.created_at?.slice(0,16))}
          ${j.auto_release_at
            ? ` &nbsp;·&nbsp; Auto-release: ${esc(j.auto_release_at?.slice(0,16))}`
            : ''}
          ${j.error_msg ? `<br><span style="color:#ff6b6b">${esc(j.error_msg)}</span>` : ''}
        </div>
      </div>`;
  }

  window.releaseRehydration = async function(id) {
    if (!confirm('Release this rehydration? Data will be removed from live storage.')) return;
    const res = await POST('/api/archive/rehydrate.php', { action: 'release', id });
    if (!res.ok) { alert(`Release failed: ${res.error}`); return; }
    loadRehydrations();
  };

  window.cancelRehydration = async function(id) {
    if (!confirm('Cancel this rehydration? It will stop after finishing its current batch.')) return;
    const res = await POST('/api/archive/rehydrate.php', { action: 'cancel', id });
    if (!res.ok) { alert(`Cancel failed: ${res.error}`); return; }
    loadRehydrations();
  };

  // ══════════════════════════════════════════════════════════════════════════
  // PARTITIONS
  // ══════════════════════════════════════════════════════════════════════════
  let partPage = 1;
  let partTotal = 0;

  function setupPartitions() {
    $('btnPartFilter')?.addEventListener('click', () => { partPage = 1; loadPartitions(); });
    $('partPrev')?.addEventListener('click', () => { if (partPage > 1) { partPage--; loadPartitions(); } });
    $('partNext')?.addEventListener('click', () => {
      if (partPage * 50 < partTotal) { partPage++; loadPartitions(); }
    });
  }

  async function loadPartitions() {
    const params = new URLSearchParams({
      action:     'list',
      state:      $('partState')?.value || '',
      date_from:  $('partFrom')?.value  || '',
      date_to:    $('partTo')?.value    || '',
      page:       partPage,
    });
    const res = await GET(`/api/archive/run.php?${params}`);
    partTotal = res.total || 0;
    const pages = Math.ceil(partTotal / 50) || 1;
    $('partPageInfo').textContent = `Page ${partPage} of ${pages}  (${partTotal} partitions)`;

    const rows = (res.partitions || []).map(p => `
      <tr>
        <td>${esc(p.partition_date)}</td>
        <td>${esc(p.table_name)}</td>
        <td>
          <span class="sev sev-${stateColour(p.state)}">${esc(p.state)}</span>
          ${p.frozen ? '<span class="frozen-badge">FROZEN</span>' : ''}
          ${p.partial ? '<span class="partial-badge">PARTIAL</span>' : ''}
        </td>
        <td>${Number(p.row_count||0).toLocaleString()}</td>
        <td>${fmt_bytes(p.file_size_bytes)}</td>
        <td>${esc(p.compression)}</td>
        <td>${p.encrypted ? '🔒' : '—'}</td>
        <td>${esc(p.verified_at?.slice(0,16) || '—')}</td>
        <td>
          <button class="btn secondary" style="font-size:10px;padding:2px 8px"
            onclick="verifyPartition(${p.id})">Verify</button>
          ${!p.frozen
            ? `<button class="btn secondary" style="font-size:10px;padding:2px 8px;margin-left:4px"
                 onclick="freezePartition(${p.id})">Freeze</button>`
            : `<button class="btn secondary" style="font-size:10px;padding:2px 8px;margin-left:4px"
                 onclick="unfreezePartition(${p.id})">Unfreeze</button>`
          }
          ${['failed','verify_failed'].includes(p.state)
            ? `<button class="btn danger" style="font-size:10px;padding:2px 8px;margin-left:4px"
                 onclick="deleteFailedPartition(${p.id})">Delete</button>`
            : ''}
        </td>
      </tr>
    `).join('');

    $('partitionTable').innerHTML = `
      <table class="part-table">
        <thead>
          <tr>
            <th>Date</th><th>Table</th><th>State</th><th>Rows</th>
            <th>Size</th><th>Compression</th><th>Enc</th><th>Verified</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="9" class="empty">No partitions.</td></tr>'}</tbody>
      </table>`;
  }

  function stateColour(state) {
    return { verified:'low', deleted_from_hot:'low', failed:'high',
             verify_failed:'high', exporting:'mid', pending:'mid' }[state] || 'mid';
  }

  window.verifyPartition = async function(id) {
    const res = await POST('/api/archive/run.php', { action: 'verify', manifest_id: id });
    if (!res.ok) { alert(res.error); return; }
    const r = res.results?.[0];
    if (r?.ok) alert('✓ Integrity verified — hash matches.');
    else       alert(`✗ Verification failed: ${r?.error || 'unknown error'}`);
    loadPartitions();
  };

  window.freezePartition = async function(id) {
    const reason = prompt('Reason for freeze (e.g. "Legal hold — case #1234"):');
    if (reason === null) return;
    const res = await POST('/api/archive/freeze.php', { action: 'freeze', manifest_id: id, reason });
    if (!res.ok) alert(res.error);
    else loadPartitions();
  };

  window.unfreezePartition = async function(id) {
    if (!confirm('Unfreeze this partition? It will be subject to retention policy again.')) return;
    const res = await POST('/api/archive/freeze.php', { action: 'unfreeze', manifest_id: id });
    if (!res.ok) alert(res.error);
    else loadPartitions();
  };

  window.deleteFailedPartition = async function(id) {
    if (!confirm('Delete this failed partition record? The Parquet file (if any) will remain on disk.')) return;
    const res = await POST('/api/archive/run.php', { action: 'delete_failed', manifest_id: id });
    if (!res.ok) alert(res.error);
    else loadPartitions();
  };

  // ══════════════════════════════════════════════════════════════════════════
  // POLICY
  // ══════════════════════════════════════════════════════════════════════════
  let currentPolicy = {};

  function setupPolicy() {
    $('btnSavePolicy')?.addEventListener('click', savePolicy);
  }

  async function loadPolicy() {
    const res = await GET('/api/archive/policy.php');
    if (!res.ok) { $('policyForm').innerHTML = `<div class="empty">Error: ${esc(res.error)}</div>`; return; }
    currentPolicy = res.policy || {};
    renderPolicyForm(currentPolicy);
  }

  function renderPolicyForm(p) {
    $('policyForm').innerHTML = `
      <div class="policy-section">
        <h3>General</h3>
        <div class="policy-row">
          <label>Archive enabled
            <select id="polEnabled">
              <option value="1" ${p.enabled == true || p.enabled == 't' ? 'selected' : ''}>Yes</option>
              <option value="0" ${!p.enabled || p.enabled == 'f' ? 'selected' : ''}>No</option>
            </select>
          </label>
          <label>Run time (24h)
            <input type="time" id="polRunTime" value="${String(p.run_time || '02:00').slice(0,5)}">
          </label>
        </div>
      </div>

      <div class="policy-section">
        <h3>Retention</h3>
        <div class="policy-row three">
          <label>Hot retention (days in PostgreSQL)
            <input type="number" id="polHotDays" value="${p.hot_retention_days ?? 90}" min="1">
          </label>
          <label>Cold retention (days in archive before deletion)
            <input type="number" id="polColdDays" value="${p.cold_retention_days ?? 1095}" min="1">
          </label>
          <label>Alert retention (days)
            <input type="number" id="polAlertDays" value="${p.alerts_retention_days ?? 365}" min="1">
          </label>
        </div>
      </div>

      <div class="policy-section">
        <h3>What to Archive</h3>
        <div class="policy-row three">
          <label>Archive messages
            <select id="polArchiveMsg">
              <option value="1" ${p.archive_messages != false ? 'selected' : ''}>Yes</option>
              <option value="0" ${p.archive_messages == false ? 'selected' : ''}>No</option>
            </select>
          </label>
          <label>Archive alerts
            <select id="polArchiveAlerts">
              <option value="1" ${p.archive_alerts != false ? 'selected' : ''}>Yes</option>
              <option value="0" ${p.archive_alerts == false ? 'selected' : ''}>No</option>
            </select>
          </label>
          <label>Archive alert occurrences
            <select id="polArchiveOcc">
              <option value="0" ${!p.archive_alert_occurrences ? 'selected' : ''}>No</option>
              <option value="1" ${p.archive_alert_occurrences ? 'selected' : ''}>Yes</option>
            </select>
          </label>
        </div>
      </div>

      <div class="policy-section">
        <h3>Export Settings</h3>
        <div class="policy-row three">
          <label>Compression
            <select id="polCompression">
              <option value="zstd"   ${p.compression === 'zstd'   ? 'selected' : ''}>Zstd (best)</option>
              <option value="snappy" ${p.compression === 'snappy' ? 'selected' : ''}>Snappy (faster)</option>
              <option value="none"   ${p.compression === 'none'   ? 'selected' : ''}>None</option>
            </select>
          </label>
          <label>Encrypt at rest
            <select id="polEncrypt">
              <option value="0" ${!p.encrypt_at_rest || p.encrypt_at_rest == 'f' ? 'selected' : ''}>No</option>
              <option value="1" ${p.encrypt_at_rest == true || p.encrypt_at_rest == 't' ? 'selected' : ''}>Yes</option>
            </select>
          </label>
          <label>Storage alert threshold (GB)
            <input type="number" id="polAlertGb" value="${p.storage_alert_threshold_gb ?? 100}" min="1">
          </label>
        </div>
      </div>

      <div class="policy-section">
        <h3>Failure Handling</h3>
        <div class="policy-row three">
          <label>Partial export behaviour
            <select id="polPartial">
              <option value="keep"             ${(p.partial_export_behaviour||'keep') === 'keep' ? 'selected' : ''}>
                Keep — retry whole day (safe)
              </option>
              <option value="delete_exported"  ${p.partial_export_behaviour === 'delete_exported' ? 'selected' : ''}>
                Delete exported rows only
              </option>
            </select>
          </label>
          <label>Verify after export
            <select id="polVerify">
              <option value="1" ${p.verify_after_export != false ? 'selected' : ''}>Yes (recommended)</option>
              <option value="0" ${p.verify_after_export == false ? 'selected' : ''}>No</option>
            </select>
          </label>
          <label>Delete from hot after verify
            <select id="polDelete">
              <option value="1" ${p.delete_after_verify != false ? 'selected' : ''}>Yes</option>
              <option value="0" ${p.delete_after_verify == false ? 'selected' : ''}>No — keep in both</option>
            </select>
          </label>
        </div>
      </div>
    `;
  }

  async function savePolicy() {
    const body = {
      enabled:                  $('polEnabled')?.value    === '1',
      hot_retention_days:       parseInt($('polHotDays')?.value    || 90),
      cold_retention_days:      parseInt($('polColdDays')?.value   || 1095),
      alerts_retention_days:    parseInt($('polAlertDays')?.value  || 365),
      archive_messages:         $('polArchiveMsg')?.value     === '1',
      archive_alerts:           $('polArchiveAlerts')?.value  === '1',
      archive_alert_occurrences:$('polArchiveOcc')?.value     === '1',
      compression:              $('polCompression')?.value    || 'zstd',
      encrypt_at_rest:          $('polEncrypt')?.value        === '1',
      storage_alert_threshold_gb: parseInt($('polAlertGb')?.value || 100),
      partial_export_behaviour: $('polPartial')?.value        || 'keep',
      verify_after_export:      $('polVerify')?.value         === '1',
      delete_after_verify:      $('polDelete')?.value         === '1',
      run_time:                 $('polRunTime')?.value        || '02:00',
    };
    const res = await POST('/api/archive/policy.php', body);
    if (res.ok) { alert('Policy saved.'); currentPolicy = res.policy; }
    else        alert(`Failed: ${res.error}`);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // STORAGE BACKEND
  // ══════════════════════════════════════════════════════════════════════════
  let activeBeType = 'local';

  function setupStorage() {
    document.querySelectorAll('.bt-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.bt-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeBeType = btn.dataset.be;
        showBeFields(activeBeType);
      });
    });
    $('btnTestConn')?.addEventListener('click', testBackendConnection);
    $('btnSaveBackend')?.addEventListener('click', saveBackend);
  }

  function showBeFields(type) {
    ['local','sftp','s3'].forEach(t => {
      const el = $(`beFields${t.charAt(0).toUpperCase()}${t.slice(1)}`);
      if (el) el.style.display = t === type ? 'block' : 'none';
    });
  }

  function getBePayload() {
    const type = activeBeType;
    let config = {}, creds = {};
    if (type === 'local') {
      config = { path: $('beLocalPath')?.value || '' };
    } else if (type === 'sftp') {
      config = { host: $('beSftpHost')?.value, port: $('beSftpPort')?.value,
                 remote_path: $('beSftpPath')?.value };
      creds  = { username: $('beSftpUser')?.value,
                 key_path: $('beSftpKey')?.value,
                 password: $('beSftpPass')?.value };
    } else if (type === 's3') {
      config = { endpoint_url: $('beS3Endpoint')?.value || null,
                 bucket: $('beS3Bucket')?.value,
                 region: $('beS3Region')?.value,
                 prefix: $('beS3Prefix')?.value,
                 path_style: $('beS3PathStyle')?.checked };
      creds  = { access_key_id: $('beS3Key')?.value,
                 secret_access_key: $('beS3Secret')?.value };
    }
    return { backend_type: type, config, credentials: creds,
             name: $('beName')?.value || type };
  }

  async function testBackendConnection() {
    $('testResults').style.display = 'block';
    $('testResults').innerHTML = '<div style="color:#7a9bbf;font-size:13px">⏳ Testing connection...</div>';
    const payload = getBePayload();
    const editId  = $('btnSaveBackend')?.dataset?.editId;
    if (editId) payload.id = parseInt(editId);
    const res = await POST('/api/archive/storage.php', { action: 'test', ...payload });
    renderTestResults(res);
  }

  function renderTestResults(res) {
    const steps = res.steps || [];
    const stepHtml = steps.map(s => `
      <li>
        <span class="${s.ok ? 'step-ok' : 'step-fail'}">${s.ok ? '✓' : '✗'}</span>
        <span>${esc(s.step.replace(/_/g,' '))}</span>
        ${s.ms !== undefined ? `<span style="color:#4a6a8a;font-size:11px">${s.ms}ms</span>` : ''}
        ${s.available_gb !== undefined
          ? `<span style="color:#4a6a8a;font-size:11px">— ${s.available_gb} GB available</span>`
          : ''}
        ${s.msg ? `<span style="color:#ff6b6b;font-size:11px">${esc(s.msg)}</span>` : ''}
      </li>
    `).join('');

    $('testResults').innerHTML = `
      <ul class="step-list">${stepHtml}</ul>
      ${res.ok
        ? `<div style="color:#7ecb7e;margin-top:8px;font-size:13px">✓ Connection test passed</div>`
        : `<div style="color:#ff6b6b;margin-top:8px;font-size:13px">✗ ${esc(res.error || 'Test failed')}</div>`
      }
      ${res.detail ? `<div style="color:#f0c040;font-size:12px;margin-top:4px">${esc(res.detail)}</div>` : ''}
      ${res.hint   ? `<div style="color:#4a6a8a;font-size:11px;margin-top:4px">Hint: ${esc(res.hint)}</div>` : ''}
      ${res.available_gb != null
        ? `<div style="color:#4a6a8a;font-size:12px;margin-top:4px">Available: ${res.available_gb} GB</div>`
        : ''}
    `;
  }

  async function saveBackend() {
    const payload = getBePayload();
    const editId  = $('btnSaveBackend')?.dataset?.editId;
    if (editId) payload.id = parseInt(editId);

    const res = await POST('/api/archive/storage.php', { action: 'save', ...payload });
    if (!res.ok) { alert(`Save failed: ${res.error}`); return; }

    if ($('btnSaveBackend')) delete $('btnSaveBackend').dataset.editId;
    const hint = $('editHint');
    if (hint) hint.remove();
    $('backendForm').style.border = '';
    $('beName').value = '';

    if (!editId && confirm('Backend saved. Set as active backend?')) {
      await POST('/api/archive/storage.php', { action: 'activate', id: res.id });
    } else if (editId) {
      alert('Backend updated.');
    }
    loadStorageBackends();
  }

  async function loadStorageBackends() {
    const res = await GET('/api/archive/storage.php?action=list');
    const el  = $('backendList');
    if (!res.ok) { el.innerHTML = `<div class="empty">Error: ${esc(res.error)}</div>`; return; }
    const backends = res.backends || [];
    el.innerHTML = backends.length
      ? backends.map(b => `
        <div class="backend-card">
          <div class="bc-head">
            <div>
              <strong style="color:#c5d8f0">${esc(b.name)}</strong>
              &nbsp;
              <span class="sev sev-${b.backend_type === 'local' ? 'low' : 'mid'}">
                ${esc(b.backend_type.toUpperCase())}
              </span>
              ${b.is_active ? '<span class="frozen-badge" style="background:#0e3d6e;color:#7ecb7e">ACTIVE</span>' : ''}
            </div>
            <div style="display:flex;gap:6px">
              <button class="btn secondary" style="font-size:11px;padding:3px 10px"
                onclick="editBackend(${b.id})">Edit</button>
              ${!b.is_active
                ? `<button class="btn secondary" style="font-size:11px;padding:3px 10px"
                     onclick="activateBackend(${b.id})">Set Active</button>`
                : ''}
              ${!b.is_active
                ? `<button class="btn danger" style="font-size:11px;padding:3px 10px"
                     onclick="deleteBackend(${b.id})">Delete</button>`
                : ''}
            </div>
          </div>
          <div style="font-size:12px;color:#4a6a8a;margin-top:6px">
            Last tested: ${esc(b.last_tested_at?.slice(0,16) || 'never')}
            ${b.last_test_ok === 'true' || b.last_test_ok === true
              ? '<span style="color:#7ecb7e;margin-left:8px">✓ Passed</span>'
              : b.last_test_ok === 'false' || b.last_test_ok === false
                ? `<span style="color:#ff6b6b;margin-left:8px">✗ ${esc(b.last_test_msg)}</span>`
                : ''}
          </div>
        </div>`
      ).join('')
      : '<div class="empty">No storage backends configured.</div>';
  }

  window.editBackend = async function(id) {
    const res = await GET(`/api/archive/storage.php?action=get&id=${id}`);
    if (!res.ok) { alert(`Could not load backend: ${res.error}`); return; }
    const b = res.backend;

    $('btnSaveBackend').dataset.editId = id;
    $('beName').value = b.name || '';

    activeBeType = b.backend_type;
    document.querySelectorAll('.bt-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.be === activeBeType);
    });
    showBeFields(activeBeType);

    const cfg = b.config || {};
    if (activeBeType === 'local') {
      $('beLocalPath').value = cfg.path || '';
    } else if (activeBeType === 'sftp') {
      $('beSftpHost').value = cfg.host        || '';
      $('beSftpPort').value = cfg.port        || 22;
      $('beSftpPath').value = cfg.remote_path || '';
      $('beSftpUser').value = '';
      $('beSftpKey').value  = cfg.key_path    || '';
      $('beSftpPass').value = '';
    } else if (activeBeType === 's3') {
      $('beS3Endpoint').value    = cfg.endpoint_url || '';
      $('beS3Bucket').value      = cfg.bucket       || '';
      $('beS3Region').value      = cfg.region       || 'us-east-1';
      $('beS3Prefix').value      = cfg.prefix       || '';
      $('beS3PathStyle').checked = !!cfg.path_style;
      $('beS3Key').value         = '';
      $('beS3Secret').value      = '';
    }

    $('backendForm').scrollIntoView({ behavior: 'smooth' });
    $('backendForm').style.border = '1px solid #1a56a0';
    const existing = $('editHint');
    if (existing) existing.remove();
    const hint = document.createElement('div');
    hint.id = 'editHint';
    hint.style.cssText = 'font-size:12px;color:#7a9bbf;margin-bottom:10px';
    hint.textContent = `Editing: ${b.name} — leave credential fields blank to keep existing credentials.`;
    $('backendForm').insertBefore(hint, $('backendForm').firstChild);
  };

  window.activateBackend = async function(id) {
    if (!confirm('Set this as the active backend? All future archive writes will use it.')) return;
    const res = await POST('/api/archive/storage.php', { action: 'activate', id });
    if (!res.ok) alert(res.error);
    else loadStorageBackends();
  };

  window.deleteBackend = async function(id) {
    if (!confirm('Delete this backend configuration?')) return;
    const res = await POST('/api/archive/storage.php', { action: 'delete', id });
    if (!res.ok) alert(res.error);
    else loadStorageBackends();
  };


  // ══════════════════════════════════════════════════════════════════════════
  // AUDIT LOG
  // ══════════════════════════════════════════════════════════════════════════
  let auditPage = 1;
  let auditTotal = 0;

  function setupAudit() {
    $('btnAuditFilter')?.addEventListener('click', () => { auditPage = 1; loadAuditLog(); });
    $('auditPrev')?.addEventListener('click', () => { if (auditPage > 1) { auditPage--; loadAuditLog(); } });
    $('auditNext')?.addEventListener('click', () => {
      if (auditPage * 50 < auditTotal) { auditPage++; loadAuditLog(); }
    });
    $('btnAuditCsv')?.addEventListener('click', () => {
      window.location.href = `/api/archive/audit.php?export_csv=1` +
        `&filter_action=${encodeURIComponent($('auditAction')?.value||'')}` +
        `&date_from=${encodeURIComponent($('auditFrom')?.value||'')}` +
        `&date_to=${encodeURIComponent($('auditTo')?.value||'')}`;
    });
  }

  async function loadAuditLog() {
    const params = new URLSearchParams({
      filter_action: $('auditAction')?.value || '',
      date_from:     $('auditFrom')?.value   || '',
      date_to:       $('auditTo')?.value     || '',
      page:          auditPage,
    });
    const res = await GET(`/api/archive/audit.php?${params}`);
    if (!res.ok) { $('auditTable').innerHTML = `<div class="empty">Error: ${esc(res.error)}</div>`; return; }

    auditTotal = res.total || 0;
    const pages = Math.ceil(auditTotal / 50) || 1;
    $('auditPageInfo').textContent = `Page ${auditPage} of ${pages}  (${auditTotal} events)`;

    const actionSel = $('auditAction');
    if (actionSel && res.distinct_actions?.length) {
      const current = actionSel.value;
      actionSel.innerHTML = '<option value="">All actions</option>' +
        res.distinct_actions.map(a =>
          `<option value="${esc(a)}" ${a === current ? 'selected' : ''}>${esc(a)}</option>`
        ).join('');
    }

    const rows = (res.rows || []).map(r => `
      <tr>
        <td>${esc(r.occurred_at?.slice(0,19))}</td>
        <td>${esc(r.action)}</td>
        <td>${esc(r.performed_by)}</td>
        <td>${esc(r.partition_date || '—')}</td>
        <td>${esc(r.table_name || '—')}</td>
        <td>${r.success ? '<span style="color:#7ecb7e">✓</span>'
                        : '<span style="color:#ff6b6b">✗</span>'}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">
          ${esc(r.error_msg || r.detail || '—')}
        </td>
      </tr>
    `).join('');

    $('auditTable').innerHTML = `
      <table class="part-table">
        <thead>
          <tr>
            <th>Time</th><th>Action</th><th>By</th>
            <th>Date</th><th>Table</th><th>OK</th><th>Detail</th>
          </tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="7" class="empty">No audit events.</td></tr>'}</tbody>
      </table>`;
  }

})();