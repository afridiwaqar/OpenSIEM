/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $  = id  => document.getElementById(id);
  const qs = sel => document.querySelector(sel);
  let csrf = null, conf = null;

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;
    setupBell();
    setupTabs();
    setupSevChips();

    conf = await GET('/api/settings/get.php');
    if (!conf.ok) { alert(conf.error || 'Failed to load config'); return; }
    populate();

    $('saveDB').addEventListener('click',     () => saveSection('database'));
    $('saveEmail').addEventListener('click',  () => saveSection('email'));
    $('saveAlerts').addEventListener('click', () => saveSection('alerts'));
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

  function setupTabs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
      });
    });
  }

  function setupSevChips() {
    document.querySelectorAll('.sev-chip').forEach(chip => {
      const cb = chip.querySelector('input[type=checkbox]');
      const sync = () => chip.classList.toggle('checked', cb.checked);
      cb.addEventListener('change', sync);
      sync();
    });
  }

  function setSevGroup(groupId, csv) {
    const active = (csv || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    document.querySelectorAll(`#${groupId} .sev-chip`).forEach(chip => {
      const cb  = chip.querySelector('input');
      cb.checked = active.includes(cb.value);
      chip.classList.toggle('checked', cb.checked);
    });
  }

  function getSevGroup(groupId) {
    const vals = [];
    document.querySelectorAll(`#${groupId} .sev-chip input:checked`).forEach(cb => vals.push(cb.value));
    return vals.join(',');
  }

  function populate() {
    const db = conf.database || {};
    const em = conf.email    || {};
    const al = conf.alerts   || {};

    // Database
    $('dbHost').value = db.host     || '';
    $('dbPort').value = db.port     || '5432';
    $('dbName').value = db.database || '';
    $('dbUser').value = db.user     || '';
    $('dbPass').value = '';          // never pre-fill passwords

    // Email
    const enabled = (em.enabled || 'yes').toLowerCase();
    $('emailEnabled').checked = enabled !== 'no' && enabled !== 'false' && enabled !== '0';
    $('smtpServer').value  = em.smtp_server  || '';
    $('smtpPort').value    = em.smtp_port    || '587';
    $('senderEmail').value = em.sender_email || '';
    $('senderPass').value  = '';    // never pre-fill
    $('adminEmails').value = em.admin_emails || '';
    const tls = (em.use_tls || 'yes').toLowerCase();
    $('useTls').checked = tls !== 'no' && tls !== 'false' && tls !== '0';

    // Alerts
    setSevGroup('emailSevGroup', al.email_severities || 'high,critical');
    setSevGroup('uiSevGroup',    al.ui_severities    || 'low,mid,high,critical');
    $('cooldown').value = al.cooldown_period || '300';
  }

  async function saveSection(section) {
    const statusEl = $('status' + { database:'DB', email:'Email', alerts:'Alerts' }[section]);
    statusEl.textContent = 'Saving…';
    statusEl.className   = 'save-status';
    statusEl.style.display = 'inline';

    let values = {};

    if (section === 'database') {
      values = {
        host:     $('dbHost').value.trim(),
        port:     $('dbPort').value.trim() || null,
        database: $('dbName').value.trim(),
        user:     $('dbUser').value.trim(),
        password: $('dbPass').value.trim() || null,
      };
    } else if (section === 'email') {
      values = {
        enabled:         $('emailEnabled').checked ? 'yes' : 'no',
        smtp_server:     $('smtpServer').value.trim(),
        smtp_port:       $('smtpPort').value.trim() || null,
        sender_email:    $('senderEmail').value.trim(),
        sender_password: $('senderPass').value.trim() || null,
        admin_emails:    $('adminEmails').value.trim(),
        use_tls:         $('useTls').checked ? 'yes' : 'no',
      };
    } else if (section === 'alerts') {
      values = {
        email_severities: getSevGroup('emailSevGroup'),
        ui_severities:    getSevGroup('uiSevGroup'),
        cooldown_period:  $('cooldown').value.trim() || '300',
      };
    }

    const res = await POST('/api/settings/save.php', { section, values });

    if (!res.ok) {
      statusEl.textContent = '✖ ' + (res.error || 'Save failed');
      statusEl.classList.add('err');
    } else {
      statusEl.textContent = '✔ Saved';
      statusEl.classList.remove('err');
      conf = await GET('/api/settings/get.php');
    }

    // Auto-hide after 4 seconds
    setTimeout(() => { statusEl.style.display = 'none'; }, 4000);
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

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch]));
  }
})();
