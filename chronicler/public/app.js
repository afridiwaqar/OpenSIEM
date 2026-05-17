/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/

//console.log('[app.js] loaded');
if (window.__chroniclerInit) {
} else {
  window.__chroniclerInit = true;

  const $ = (id) => document.getElementById(id);

  (async () => {
    try {
      const res = await fetch('/api/auth/me.php', {cache:'no-store'});
      const me = await res.json();
      if (!me.ok) { location.href = '/login.html'; return; }
      window.__csrf = me.csrf; // store CSRF for POST calls
      bootstrap(); // start app only after auth
    } catch {
      location.href = '/login.html';
    }
  })();

  async function api(path, opts={}) {
    const res = await fetch(`/api/${path}`, {cache:'no-store', ...opts});
    const text = await res.text();
    try { return JSON.parse(text); } catch { console.error('API parse error for', path, text); throw new Error('bad_json'); }
  }

  function bootstrap() {
    const LOG_CAP = 500;         // max DOM lines for live logs
    const LINE_MAX = 2000;       // max chars per log line
    const MAX_POINTS = 60;       // max datapoints per chart (keep last N points)
    // ---------- Alerts ribbon ----------
    async function loadAlertRibbon() {
      try {
        const data   = await api('get_alerts.php');
        const ribbon = $('alertRibbon');
        if (!ribbon) return;
        ribbon.innerHTML = '';

        const items = Array.isArray(data.items) ? data.items : [];

        if (items.length === 0) {
          ribbon.innerHTML = '<span style="color:#4a5a6e;font-size:12px;">No active alerts</span>';
          return;
        }

        items.forEach(a => {
          const sev   = (a.severity || 'mid').toLowerCase();
          const label = a.source_ip || 'unknown';
          const count = a.hit_count > 1 ? ` (${a.hit_count})` : '';

          // <a> tag navigates to alerts page and auto-opens the detail modal
          const pill = document.createElement('a');
          pill.className   = `alert ${sev}`;
          pill.href        = `/alerts.html?id=${a.id}`;
          pill.title       = `${(a.alert_type||'').toUpperCase()} — click to view details`;
          pill.textContent = label + count;
          pill.style.textDecoration = 'none';
          ribbon.appendChild(pill);
        });
      } catch(e) { console.error('alert ribbon', e); }
    }

    // ---------- Widget strip ----------

    async function loadWidgets() {
      try {
        const w = await api('dashboard/widgets.php');
        console.log('[widgets response]', w);
        console.log('[wSevCritical el]', document.getElementById('wSevCritical'));
        console.log('[sev-card el]', document.querySelector('.sev-card'));
        const sevCard = document.querySelector('.sev-card');
        if (sevCard) {
          const cs = window.getComputedStyle(sevCard);
          console.log('[sev-card computed]', {
            display:    cs.display,
            visibility: cs.visibility,
            opacity:    cs.opacity,
            height:     cs.height,
            width:      cs.width,
            overflow:   cs.overflow,
            gridColumn: cs.gridColumn,
            position:   cs.position,
          });
          console.log('[sev-card rect]', sevCard.getBoundingClientRect());
        }

        // ── Threat level ──────────────────────────────────────────────
        const card  = $('threatCard');
        const lvl   = $('threatLevel');
        const sub   = $('threatSub');
        const level = w.threat_level || 'green';
        const tc    = w.threat_counts || {};

        const levelLabel = { green:'GREEN', yellow:'ELEVATED', orange:'HIGH', red:'CRITICAL' };
        const levelSub   = {
          green:  'No active threats',
          yellow: `${tc.mid||0} mid alerts active`,
          orange: `${tc.high||0} high alerts active`,
          red:    `${tc.critical||0} critical alerts active`,
        };

        if (card) {
          card.className = `threat-card threat-${level}`;
        }
        if (lvl) lvl.textContent = levelLabel[level] || level.toUpperCase();
        if (sub) sub.textContent = levelSub[level]   || '';

        // ── Today vs Yesterday — Alerts ──────────────────────────────
        const ta = w.today_alerts ?? 0;
        const ya = w.yest_alerts  ?? 0;
        const alertDiff = ta - ya;
        const alertPct  = ya > 0 ? Math.round(Math.abs(alertDiff) / ya * 100) : null;

        if ($('wAlertToday')) $('wAlertToday').textContent = ta;
        if ($('wAlertYest'))  $('wAlertYest').textContent  = `Yesterday: ${ya}`;
        if ($('wAlertDelta')) {
          const el = $('wAlertDelta');
          if (alertDiff === 0) {
            el.textContent = '→ same';
            el.className   = 'stat-delta neutral';
          } else {
            const arrow = alertDiff > 0 ? '▲' : '▼';
            el.textContent = `${arrow} ${alertPct !== null ? alertPct + '%' : Math.abs(alertDiff)}`;
            el.className   = 'stat-delta ' + (alertDiff > 0 ? 'up' : 'down');
          }
        }

        // ── Today vs Yesterday — Messages ────────────────────────────
        const tm = w.today_msgs ?? 0;
        const ym = w.yest_msgs  ?? 0;
        const msgDiff = tm - ym;
        const msgPct  = ym > 0 ? Math.round(Math.abs(msgDiff) / ym * 100) : null;

        if ($('wMsgToday')) $('wMsgToday').textContent = tm.toLocaleString?.() ?? tm;
        if ($('wMsgYest'))  $('wMsgYest').textContent  = `Yesterday: ${ym.toLocaleString?.() ?? ym}`;
        if ($('wMsgDelta')) {
          const el = $('wMsgDelta');
          if (msgDiff === 0) {
            el.textContent = '→ same';
            el.className   = 'stat-delta neutral';
          } else {
            const arrow = msgDiff > 0 ? '▲' : '▼';
            el.textContent = `${arrow} ${msgPct !== null ? msgPct + '%' : Math.abs(msgDiff)}`;
            el.className   = 'stat-delta ' + (msgDiff > 0 ? 'msg-up' : 'msg-down');
          }
        }

        // ── Backlog ──────────────────────────────────────────────────
        if ($('wBacklog')) $('wBacklog').textContent = w.backlog ?? '—';

        // ── Rules health ─────────────────────────────────────────────
        if ($('wRules')) {
          $('wRules').textContent = `${w.rules_fired ?? '—'} / ${w.rules_total ?? '—'}`;
        }

        // ── Top IPs (1h) ─────────────────────────────────────────────
        const ipsEl = $('wTopIPs');
        if (ipsEl) {
          const ips = w.top_ips_1h || [];
          if (ips.length === 0) {
            ipsEl.innerHTML = '<div class="mini-empty">No alerts in last hour</div>';
          } else {
            ipsEl.innerHTML = ips.map(r => `
              <div class="mini-row">
                <span class="mini-ip">${r.ip}</span>
                <span class="mini-count">${r.c}</span>
              </div>`).join('');
          }
        }

        // ── Severity tri-widget — today's alert counts ────────────────
        const sev = w.sev_today || w.threat_counts || {};
        if ($('wSevCritical')) $('wSevCritical').textContent = sev.critical ?? 0;
        if ($('wSevHigh'))     $('wSevHigh').textContent     = sev.high     ?? 0;
        if ($('wSevMid'))      $('wSevMid').textContent      = sev.mid      ?? 0;

      } catch(e) { console.error('loadWidgets', e); }
    }
    async function loadEPS() {
      try {
        const d = await api('get_eps.php'); // { eps, mbps, source }
        let text = `EPS: ${d.eps ?? '--'}`;
        if (d.mbps !== null && d.mbps !== undefined) text += ` • ${d.mbps} Mb/s`;
        $('epsCard').textContent = text;
      } catch(e) { /* ignore */ }
    }

    let lastSince = null;
    async function loadLiveLogs() {
      try {
        const d = await api(`get_live_logs.php${lastSince ? `?since=${encodeURIComponent(lastSince)}` : ''}`);
        const box = $('liveLogs');
        (d.logs || []).forEach(line => {
          const el = document.createElement('div');
          el.className = `log ${line.level || 'info'}`;
          const txt = String(line.text || '');
          el.textContent = txt.length > LINE_MAX ? (txt.slice(0, LINE_MAX) + '…') : txt;
          box.appendChild(el);
        });
        if (d.logs && d.logs.length) {
          lastSince = d.logs[d.logs.length - 1].ts;
          box.scrollTop = box.scrollHeight;
        }
        while (box.children.length > LOG_CAP) box.removeChild(box.firstChild);
      } catch(e) { /* ignore */ }
    }

    // ---------- Client stats ----------
    async function loadClientStats() {
      try {
        const ds   = await api('get_client_stats.php');
        const wrap = $('clientCards');
        if (!wrap) return;
        wrap.innerHTML = '';

        const clients = Array.isArray(ds) ? ds : [];
        if (clients.length === 0) {
          wrap.innerHTML = '<div style="color:#4a6a8a;font-size:12px;padding:4px 0">No clients reporting.</div>';
          return;
        }

        const pct = s => parseFloat((s || '0').replace('%', '')) || 0;

        const bar = (val) => {
          const color = val > 85 ? '#ff6b6b' : val > 65 ? '#ffd66e' : '#7ecb7e';
          return `<div style="background:#1c2434;border-radius:3px;height:5px;margin:2px 0 7px;overflow:hidden">
            <div style="width:${Math.min(val,100)}%;height:100%;background:${color};border-radius:3px;transition:width .4s"></div>
          </div>`;
        };

        clients.forEach(c => {
          const cpuVal  = pct(c.cpu_total);
          const ramVal  = pct(c.ram_pct);
          const diskVal = pct(c.disk_pct);

          const ramDetail  = c.ram_used  && c.ram_total  ? ` ${c.ram_used}/${c.ram_total}`  : '';
          const diskDetail = c.disk_used && c.disk_total ? ` ${c.disk_used}/${c.disk_total}` : '';

          const svcHtml = (c.services || []).map(s => {
            const ok = /running/i.test(s.status);
            return `<span style="font-size:11px;margin-right:6px;color:${ok?'#7ecb7e':'#ff6b6b'}">${ok?'●':'○'} ${s.name}</span>`;
          }).join('');

          const div = document.createElement('div');
          div.className = 'client-card';
          div.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:7px">
              <strong style="color:#c8dff5;font-size:13px">${c.id}</strong>
              ${c.given_name ? `<span style="color:#6a8aaa;font-size:11px">${c.given_name}</span>` : ''}
            </div>
            <div style="display:flex;justify-content:space-between;font-size:11px;color:#9aa8bd">
              <span>CPU</span><span>${c.cpu_total || '--'}</span>
            </div>
            ${bar(cpuVal)}
            <div style="display:flex;justify-content:space-between;font-size:11px;color:#9aa8bd">
              <span>RAM${ramDetail}</span><span>${c.ram_pct || '--'}</span>
            </div>
            ${bar(ramVal)}
            <div style="display:flex;justify-content:space-between;font-size:11px;color:#9aa8bd">
              <span>Disk${diskDetail}</span><span>${c.disk_pct || '--'}</span>
            </div>
            ${bar(diskVal)}
            ${svcHtml ? `<div style="margin-top:4px;padding-top:5px;border-top:1px solid #1c2434">${svcHtml}</div>` : ''}
          `;
          wrap.appendChild(div);
        });
      } catch(e) { console.error('client stats', e); }
    }

    $('searchBtn')?.addEventListener('click', async () => {
      const q = $('logQuery').value.trim();
      if (!q) return;
      const res = await api('search_logs.php', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ q })
      });
      const box = $('liveLogs');
      box.innerHTML = '';
      (res.results || []).forEach(r => {
        const el = document.createElement('div');
        el.className = `log ${r.level || 'info'}`;
        el.textContent = r.text;
        box.appendChild(el);
      });
      box.scrollTop = box.scrollHeight;
    });

    // ---------- Reload Rules ----------
    $('reloadRulesBtn')?.addEventListener('click', async () => {
      try {
        const res = await api('reload_rules.php', { method:'POST', headers:{'X-CSRF-Token': window.__csrf} });
        alert(res.ok ? 'Correlation rules reloaded.' : ('Reload failed: ' + (res.error || 'unknown error')));
      } catch (e) {
        alert('Reload failed.');
      }
    });

    // ---------- Notifications (bell) ----------
    const notiBell  = $('notiBell');
    const notiBadge = $('notiBadge');
    const notiMenu  = $('notiMenu');
    const notiList  = $('notiList');

    async function loadNotifications() {
      try {
        const data = await api('get_alerts.php');
        if (notiBadge) notiBadge.textContent = data.count ?? 0;
        if (!notiList) return;

        notiList.innerHTML = '';
        const items = Array.isArray(data.items) ? data.items : [];

        if (items.length === 0) {
          notiList.innerHTML = '<div style="padding:10px;color:#9aa8bd;font-size:12px;">No active alerts</div>';
          return;
        }

        items.forEach(a => {
          const sev   = (a.severity || 'mid').toLowerCase();
          const label = a.source_ip || 'n/a';
          const count = a.hit_count > 1 ? ` (${a.hit_count})` : '';

          const row = document.createElement('div');
          row.className    = 'noti-item';
          row.style.cursor = 'pointer';
          row.innerHTML = `
            <div style="flex:1">
              <div class="noti-kind">${(a.alert_type||'').toUpperCase()} — ${label}${count}</div>
              <div class="noti-sev ${sev}">${(a.severity||'MID').toUpperCase()}</div>
            </div>
            <span style="font-size:11px;color:#4a6a8a;align-self:center">▶</span>
          `;
          row.addEventListener('click', () => {
            notiMenu?.classList.add('hidden');
            window.location.href = `/alerts.html?id=${a.id}`;
          });
          notiList.appendChild(row);
        });
      } catch(e) { console.error('notifications', e); }
    }

    notiBell?.addEventListener('click', () => {
      notiMenu.classList.toggle('hidden');
    });
    document.addEventListener('click', (e) => {
      if (!notiMenu.contains(e.target) && !notiBell.contains(e.target)) {
        notiMenu.classList.add('hidden');
      }
    });

    let chartAlertsSeverity, chartMsgsPerHour, chartCorrelationCases, chartTopIPs, chartArtifactsSeverity;

    function makeBar(ctx, labels, data, label, color) {
      return new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets: [{ label, data, backgroundColor: color }] },
        options: { responsive:true, maintainAspectRatio:false, scales:{ y:{ beginAtZero:true } } }
      });
    }
    function makeLine(ctx, labels, data, label, color) {
      return new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: [{ label, data, borderColor: color, tension: .25 }] },
        options: { responsive:true, maintainAspectRatio:false, scales:{ y:{ beginAtZero:true } } }
      });
    }
    function makeDoughnut(ctx, labels, data, colors) {
      return new Chart(ctx, {
        type: 'doughnut',
        data: { labels, datasets: [{ data, backgroundColor: colors }] },
        options: { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'bottom' } } }
      });
    }

    async function loadDashboardStats() {
      try {
        const s = await api('dashboard/stats.php');

        {
          const sevOrder = ['low','mid','high','critical'];
          const labels = sevOrder.map(x => x.toUpperCase());
          const data   = sevOrder.map(x => Number(s.alertsBySeverity24h?.[x] || 0));
          const colors = ['#9ef59e','#ffd66e','#ff9a9a','#ff5b5b'];
          const ctx = document.getElementById('chartAlertsSeverity');
          if (ctx) {
            const existing = Chart.getChart(ctx); //Check for orphaned instance
            if (existing) existing.destroy();
            chartAlertsSeverity = makeDoughnut(ctx, labels, data, colors);
          }
        }

        // Line: Messages per hour (24h)
        {
          let labels = (s.messagesPerHour24h||[]).map(r => r.h);
          let data   = (s.messagesPerHour24h||[]).map(r => Number(r.c||0));
          if (labels.length > MAX_POINTS) { labels = labels.slice(-MAX_POINTS); data = data.slice(-MAX_POINTS); }
          const ctx = document.getElementById('chartMsgsPerHour');
          if (ctx) {
            if (!chartMsgsPerHour) chartMsgsPerHour = makeLine(ctx, labels, data, 'msgs', '#6ea8fe');
            else { chartMsgsPerHour.data.labels = labels; chartMsgsPerHour.data.datasets[0].data = data; chartMsgsPerHour.update('none'); }
          }
        }

        // Bar: Correlation hits by use case (7d)
        {
          let labels = (s.correlationByCase7d||[]).map(r => r.case_name);
          let data   = (s.correlationByCase7d||[]).map(r => Number(r.c||0));
          if (labels.length > MAX_POINTS) { labels = labels.slice(-MAX_POINTS); data = data.slice(-MAX_POINTS); }
          const ctx = document.getElementById('chartCorrelationCases');
          if (ctx) {
            if (!chartCorrelationCases) chartCorrelationCases = makeBar(ctx, labels, data, 'hits', '#a18cff');
            else { chartCorrelationCases.data.labels = labels; chartCorrelationCases.data.datasets[0].data = data; chartCorrelationCases.update('none'); }
          }
        }

        // Bar: Top attacked systems (7d)
        {
          let labels = (s.topIPs7d||[]).map(r => r.ip);
          let data   = (s.topIPs7d||[]).map(r => Number(r.c||0));
          if (labels.length > MAX_POINTS) { labels = labels.slice(-MAX_POINTS); data = data.slice(-MAX_POINTS); }
          const ctx = document.getElementById('chartTopIPs');
          if (ctx) {
            if (!chartTopIPs) chartTopIPs = makeBar(ctx, labels, data, 'alerts', '#f7b267');
            else { chartTopIPs.data.labels = labels; chartTopIPs.data.datasets[0].data = data; chartTopIPs.update('none'); }
          }
        }

        // Bar: Artifact alerts by severity (7d)
        {
          const sevOrder = ['low','mid','high','critical'];
          const labels = sevOrder.map(x => x.toUpperCase());
          const data   = sevOrder.map(x => Number(s.artifactBySeverity7d?.[x] || 0));
          const ctx = document.getElementById('chartArtifactsSeverity');
          if (ctx) {
            if (!chartArtifactsSeverity) chartArtifactsSeverity = makeBar(ctx, labels, data, 'alerts', '#60d394');
            else { chartArtifactsSeverity.data.labels = labels; chartArtifactsSeverity.data.datasets[0].data = data; chartArtifactsSeverity.update('none'); }
          }
        }
      } catch(e) {
        console.error('dashboard stats', e);
      }
    }

    // ---------- Intervals ----------
    loadAlertRibbon(); loadEPS(); loadLiveLogs(); loadClientStats(); loadNotifications(); loadDashboardStats(); loadWidgets();
    // Throttle frequent polling to reduce memory/CPU pressure
    setInterval(loadAlertRibbon,   5000);
    setInterval(loadEPS,           5000);
    setInterval(loadLiveLogs,      3000);
    setInterval(loadClientStats,   10000);
    setInterval(loadNotifications, 5000);
    setInterval(loadDashboardStats,30000);
    setInterval(loadWidgets,       15000);
  }
}
