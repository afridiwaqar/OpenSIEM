// /var/www/chronicler/public/clients.js
(() => {
  const $ = id => document.getElementById(id);
  let csrf = null;

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;
    setupBell();
    setupHealthControls();
    await Promise.all([loadClients(), loadTalkers(), loadWatcherHealth()]);
    setInterval(loadClients, 5000);
    setInterval(loadTalkers, 7000);
    setInterval(loadWatcherHealth, 10000);
  })();

  // ── Helpers ──────────────────────────────────────────────────────────────
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

  async function POST(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { return { ok: false, error: t }; }
  }

  function setupHealthControls() {
    $('btnCheckNow')?.addEventListener('click', async () => {
      const btn = $('btnCheckNow');
      btn.disabled = true;
      btn.textContent = '⏳ Checking...';

      const res = await POST('/api/watcher_health.php', { action: 'check_now' });

      btn.disabled = false;
      btn.textContent = '⟳ Check Now';

      if (!res.ok) { alert(`Check failed: ${res.error}`); return; }

      const offline = res.marked_offline || [];
      if (offline.length === 0) {
        alert(`Checked ${res.checked} watcher(s). All within their threshold.`);
      } else {
        const names = offline.map(w => `${w.client_name} (silent ${w.minutes_silent} min, threshold ${w.threshold} min)`).join('\n');
        alert(`Checked ${res.checked} watcher(s).\n\n${offline.length} marked offline:\n${names}\n\nAlert(s) raised — check the Alerts page.`);
      }

      await Promise.all([loadClients(), loadWatcherHealth()]);
    });

    $('btnHealthSettings')?.addEventListener('click', openHealthSettings);
    $('healthModalClose')?.addEventListener('click', closeHealthSettings);
    $('hsCancel')?.addEventListener('click', closeHealthSettings);
    $('hsSave')?.addEventListener('click', saveHealthSettings);
  }

  async function openHealthSettings() {
    $('healthModal')?.classList.remove('hidden');
    const data = await GET('/api/watcher_health.php?action=list');
    if (!data.ok) return;

    const s = data.settings || {};
    $('hsDefaultMinutes').value  = s.default_offline_threshold_minutes ?? 5;
    $('hsCheckInterval').value   = s.check_interval_seconds ?? 60;
    $('hsEnabled').checked       = !!s.enabled;

    const list = $('hsPerClientList');
    const watchers = data.watchers || [];
    if (watchers.length === 0) {
      list.innerHTML = '<div class="empty" style="font-size:12px">No watchers tracked yet.</div>';
      return;
    }

    list.innerHTML = watchers.map(w => `
      <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #1c2434">
        <span style="flex:1;font-size:12px;color:#b8c7dc">
          ${escHtml(w.client_name || w.source_ip)}
          <span style="color:#4a6a8a">(${escHtml(w.source_ip)})</span>
        </span>
        <input type="number" class="threshold-input" min="1"
               placeholder="${$('hsDefaultMinutes').value}"
               value="${w.offline_threshold_minutes ?? ''}"
               data-ip="${escHtml(w.source_ip)}">
        <span style="font-size:10px;color:#4a6a8a">min</span>
      </div>
    `).join('');
  }

  function closeHealthSettings() {
    $('healthModal')?.classList.add('hidden');
  }

  async function saveHealthSettings() {
    const default_minutes = parseInt($('hsDefaultMinutes').value || 5);
    const check_interval  = parseInt($('hsCheckInterval').value || 60);
    const enabled          = $('hsEnabled').checked;

    await POST('/api/watcher_health.php', {
      action: 'set_global_settings',
      default_offline_threshold_minutes: default_minutes,
      check_interval_seconds: check_interval,
      enabled,
    });

    const overrides = document.querySelectorAll('#hsPerClientList .threshold-input');
    for (const input of overrides) {
      const ip  = input.dataset.ip;
      const val = input.value.trim();
      await POST('/api/watcher_health.php', {
        action: 'set_threshold',
        source_ip: ip,
        threshold_minutes: val === '' ? null : parseInt(val),
      });
    }

    closeHealthSettings();
    alert('Settings saved.');
    loadWatcherHealth();
  }

  // ── Watcher health (online / offline tracking) ─────────────────────────────
  let _healthByIp = {};   // source_ip -> { is_online, last_heartbeat_at, threshold }

  async function loadWatcherHealth() {
    const data = await GET('/api/watcher_health.php?action=list');
    if (!data.ok) return;

    _healthByIp = {};
    (data.watchers || []).forEach(w => {
      _healthByIp[w.source_ip] = w;
    });

    const sum = $('healthSummary');
    if (sum) {
      const s = data.summary || {};
      sum.innerHTML = `
        <span><b>${s.total ?? 0}</b> watchers tracked</span>
        <span style="color:#7ecb7e"><b>${s.online ?? 0}</b> online</span>
        <span class="off-count"><b>${s.offline ?? 0}</b> offline</span>
      `;
    }

    // Re-render cards so badges reflect current health without waiting
    // for the next loadClients() cycle
    applyHealthBadges();
  }

  function applyHealthBadges() {
    document.querySelectorAll('.cc[data-ip]').forEach(card => {
      const ip = card.dataset.ip;
      const h  = _healthByIp[ip];
      const badgeEl = card.querySelector('.health-badge');
      if (!badgeEl) return;
      if (!h) {
        badgeEl.textContent = '—';
        badgeEl.className = 'health-badge';
        return;
      }
      if (h.is_online) {
        badgeEl.textContent = 'Online';
        badgeEl.className = 'health-badge online';
        badgeEl.title = `Last heartbeat: ${h.last_heartbeat_at || '—'}`;
      } else {
        badgeEl.textContent = 'Offline';
        badgeEl.className = 'health-badge offline';
        badgeEl.title = `Offline since: ${h.marked_offline_at || '—'}`;
      }
    });
  }

  // ── Client health cards ──────────────────────────────────────────────────
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

      // The client id from get_client_stats.php is typically "ip:port" —
      // extract just the IP to match against watcher_health.source_ip
      const ip = String(c.id || '').split(':')[0];
      const h  = _healthByIp[ip];
      const badgeClass = h ? (h.is_online ? 'online' : 'offline') : '';
      const badgeText  = h ? (h.is_online ? 'Online' : 'Offline') : '—';

      const card = document.createElement('div');
      card.className = 'cc';
      card.dataset.ip = ip;
      card.innerHTML = `
        <div class="cc-head">
          <span class="cc-id">${escHtml(c.id)}</span>
          <span class="health-badge ${badgeClass}">${badgeText}</span>
        </div>
        ${c.given_name ? `<div class="cc-name" style="margin-bottom:8px">${escHtml(c.given_name)}</div>` : ''}
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

    applyHealthBadges();
  }

  // ── Top talkers ──────────────────────────────────────────────────────────
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

  // ── Bell (grouped, navigate on click) ───────────────────────────────────
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
