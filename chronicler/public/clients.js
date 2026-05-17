/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/

(() => {
  const $ = id => document.getElementById(id);
  let csrf = null;

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;
    setupBell();
    await Promise.all([loadClients(), loadTalkers()]);
    setInterval(loadClients, 5000);
    setInterval(loadTalkers, 7000);
  })();

  async function GET(path) {
    const r = await fetch(path, { cache: 'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('GET parse error', path, t); return { ok: false }; }
  }

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch]));
  }

  function pct(s) { return parseFloat((s || '0').replace('%', '')) || 0; }

  function barClass(val) {
    return val > 85 ? 'bar-crit' : val > 65 ? 'bar-warn' : 'bar-ok';
  }

  function bar(val) {
    return `<div class="bar-track">
      <div class="bar-fill ${barClass(val)}" style="width:${Math.min(val,100)}%"></div>
    </div>`;
  }

  async function loadClients() {
    const ds   = await GET('/api/get_client_stats.php');
    const wrap = $('clientCards');
    if (!wrap) return;
    wrap.innerHTML = '';

    const clients = Array.isArray(ds) ? ds : [];
    if (clients.length === 0) {
      wrap.innerHTML = '<div class="empty">No clients reporting. Ensure the agent is running and writing to /etc/opensiem/stats/ClientStats.xml</div>';
      return;
    }

    clients.forEach(c => {
      const cpuVal  = pct(c.cpu_total);
      const ramVal  = pct(c.ram_pct);
      const diskVal = pct(c.disk_pct);

      const ramDetail  = c.ram_used  && c.ram_total  ? `${c.ram_used} / ${c.ram_total}`  : '';
      const diskDetail = c.disk_used && c.disk_total ? `${c.disk_used} / ${c.disk_total}` : '';

      const svcHtml = (c.services || []).map(s => {
        const ok = /running/i.test(s.status);
        return `<span class="svc-pill ${ok ? 'ok' : 'down'}">${escHtml(s.name)}</span>`;
      }).join('');

      const card = document.createElement('div');
      card.className = 'cc';
      card.innerHTML = `
        <div class="cc-head">
          <span class="cc-id">${escHtml(c.id)}</span>
          ${c.given_name ? `<span class="cc-name">${escHtml(c.given_name)}</span>` : ''}
        </div>
        <div class="metric"><span>CPU</span><span class="metric-val">${escHtml(c.cpu_total||'--')}</span></div>
        ${bar(cpuVal)}
        <div class="metric">
          <span>RAM${ramDetail ? ' · '+escHtml(ramDetail) : ''}</span>
          <span class="metric-val">${escHtml(c.ram_pct||'--')}</span>
        </div>
        ${bar(ramVal)}
        <div class="metric">
          <span>Disk${diskDetail ? ' · '+escHtml(diskDetail) : ''}</span>
          <span class="metric-val">${escHtml(c.disk_pct||'--')}</span>
        </div>
        ${bar(diskVal)}
        ${svcHtml ? `<div class="svc-row">${svcHtml}</div>` : ''}
      `;
      wrap.appendChild(card);
    });
  }

  async function loadTalkers() {
    const rows = await GET('/api/clients/top_talkers.php');
    const tb   = document.querySelector('#topTalkers tbody');
    if (!tb) return;
    tb.innerHTML = '';

    const data = Array.isArray(rows) ? rows : [];
    if (data.length === 0) {
      tb.innerHTML = '<tr><td colspan="3" class="empty" style="padding:8px">No data.</td></tr>';
      return;
    }
    data.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escHtml(r.address  || '—')}</td>
        <td>${escHtml(String(r.messages || 0))}</td>
        <td>${escHtml(r.bytes    || '—')}</td>`;
      tb.appendChild(tr);
    });
  }

  async function loadNotifications() {
    const data  = await GET('/api/get_alerts.php');
    const badge = $('notiBadge');
    const list  = $('notiList');
    if (badge) badge.textContent = data.count ?? 0;
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
})();
