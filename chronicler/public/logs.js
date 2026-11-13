/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $ = (id) => document.getElementById(id);
  const LOG_CAP = 1000, LINE_MAX = 4096, PAGE = 100;
  let csrf = null;

  // ── filter vocabulary (must match api/logs/_lib.php) ───────────────────────
  const FIELDS = {
    ip:       { label: 'IP',                   ops: ['is', 'is_not', 'starts_with'] },
    hostname: { label: 'Host',                 ops: ['is', 'is_not', 'contains', 'not_contains'] },
    source:   { label: 'Source',               ops: ['is', 'is_not', 'contains', 'not_contains'] },
    process:  { label: 'Process',              ops: ['is', 'is_not', 'contains', 'not_contains'] },
    message:  { label: 'Message',              ops: ['contains', 'not_contains', 'regex', 'regex_i'] },
    severity: { label: 'Severity (estimated)', ops: ['is', 'is_not'] },
  };
  const OPLABEL = { is: 'is', is_not: 'is not', starts_with: 'starts with', contains: 'contains',
                    not_contains: 'does not contain', regex: 'matches regex', regex_i: 'matches regex (any case)' };
  const SEVS = ['critical', 'high', 'mid', 'info'];

  // ── state ──────────────────────────────────────────────────────────────────
  let regexMode = false;
  let lastRows = [];            // rows currently shown in the results table (PDF export)
  let lastNext = null;          // cursor for "Load older"
  let lastParams = null;        // params of the last search (CSV export, paging)
  let lastServerTime = '';
  let tab = 'live';
  let booting = true;           // true until init finishes: setSystem must not start the tail/strip yet
  let systems = [];             // from /api/logs/systems.php

  // live tail
  let liveMax = null, livePaused = false, liveEpoch = 0, liveTimer = null, hl = '';

  // ── http ───────────────────────────────────────────────────────────────────
  async function GET(path) {
    const r = await fetch(path, { cache: 'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('GET parse error', path, t.slice(0, 200)); return { ok: false, error: 'Bad response from server' }; }
  }
  async function POST(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(body || {})
    });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('POST parse error', path, t.slice(0, 200)); return { ok: false, error: 'Bad response from server' }; }
  }
  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, ch =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // System dropdown + header strip
  // ═══════════════════════════════════════════════════════════════════════════
  async function loadSystems() {
    const d = await GET('/api/logs/systems.php');
    if (!d.ok) return;
    systems = d.systems || [];
    const sel = $('sysSelect'), cur = sel.value;
    sel.innerHTML = '<option value="">All systems</option>';
    systems.forEach(s => {
      const label = (s.name || s.host || '—') + '  ·  ' + s.ip + '  ' + (s.online ? '●' : '○ offline')
                  + (s.open_alerts ? '  ⚠ ' + s.open_alerts : '');
      const o = el('option', null, label);
      o.value = s.ip;
      sel.appendChild(o);
    });
    if (cur) {                       // keep the selection; never restart the live view from a refresh
      if (![...sel.options].some(o => o.value === cur)) { const o = el('option', null, cur + '  ·  (not in watcher list)'); o.value = cur; sel.appendChild(o); }
      sel.value = cur;
    }
  }

  function setSystem(ip, rerun = true) {
    const sel = $('sysSelect');
    if (ip && ![...sel.options].some(o => o.value === ip)) {
      const o = el('option', null, ip + '  ·  (not in watcher list)'); o.value = ip; sel.appendChild(o);
    }
    sel.value = ip || '';
    if (booting) return;
    liveStart();
    refreshStrip();
    if (rerun && tab === 'results') runSearch();
  }

  function timeAgo(s) {
    if (!s) return '—';
    const t = new Date(String(s).replace(' ', 'T'));
    if (isNaN(t)) return String(s);
    const sec = Math.max(0, Math.round((Date.now() - t.getTime()) / 1000));
    if (sec < 90) return sec + 's ago';
    if (sec < 5400) return Math.round(sec / 60) + ' min ago';
    if (sec < 172800) return Math.round(sec / 3600) + ' h ago';
    return Math.round(sec / 86400) + ' d ago';
  }

  function bar(pctText) {
    const n = Math.max(0, Math.min(100, parseFloat(pctText) || 0));
    const color = n >= 90 ? '#ff6b6b' : n >= 75 ? '#ffd66e' : '#4a8abf';
    return `<span class="mini-bar"><i style="width:${n}%;background:${color}"></i></span>`;
  }

  async function refreshStrip() {
    const strip = $('sysStrip'), ip = $('sysSelect').value;
    if (!ip) { strip.style.display = 'none'; return; }
    const [d, stats] = await Promise.all([
      GET('/api/logs/systems.php?ip=' + encodeURIComponent(ip)),
      GET('/api/get_client_stats.php').catch(() => [])
    ]);
    if ($('sysSelect').value !== ip || !d.ok) return;     // user already moved on
    const s = d.system;
    const known = systems.find(x => x.ip === ip) || {};
    const title = s.name || s.host || known.name || known.host || ip;

    // best-effort match of CPU/RAM/disk stats by hostname or given name
    const want = [s.host, s.name, known.host, known.name].filter(Boolean).map(x => x.toLowerCase());
    const st = (Array.isArray(stats) ? stats : []).find(c =>
      want.includes(String(c.id || '').toLowerCase()) || want.includes(String(c.given_name || '').toLowerCase()));

    const badge = s.online === true ? '<span class="badge-on">ONLINE</span>'
                : s.online === false ? '<span class="badge-off">OFFLINE</span>'
                : '<span class="badge-unk">NOT TRACKED</span>';
    const chips = (s.alerts || []).filter(a => a.active).map(a =>
      `<a class="chip ${escHtml(a.severity)}" href="/alerts.html?id=${a.id}" title="${escHtml(a.case_name)}">#${a.id} ${escHtml(a.severity)} — ${escHtml((a.case_name || '').slice(0, 38))}</a>`).join('');

    strip.innerHTML = `
      <div><span class="sys-name">${escHtml(title)}</span> <span class="sys-ip">${escHtml(ip)}</span> ${badge}</div>
      <div class="kv">last seen<b>${escHtml(timeAgo(s.last_seen))}</b></div>
      <div class="kv">events (5 min)<b>${s.events_5m}</b></div>
      <div class="kv">open alerts<b>${s.open_alerts}</b></div>
      ${st ? `<div class="kv">CPU<b>${escHtml(st.cpu_total || '--')}</b>${bar(st.cpu_total)}</div>
              <div class="kv">RAM<b>${escHtml(st.ram_pct || '--')}</b>${bar(st.ram_pct)}</div>
              <div class="kv">Disk<b>${escHtml(st.disk_pct || '--')}</b>${bar(st.disk_pct)}</div>` : ''}
      ${chips ? `<div>${chips}</div>` : ''}`;
    strip.style.display = 'flex';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Filter rows
  // ═══════════════════════════════════════════════════════════════════════════
  function fillOps(opSel, field, keep) {
    opSel.innerHTML = '';
    FIELDS[field].ops.forEach(o => { const x = el('option', null, OPLABEL[o]); x.value = o; opSel.appendChild(x); });
    if (keep && FIELDS[field].ops.includes(keep)) opSel.value = keep;
  }

  function makeValueControl(field, value) {
    let c;
    if (field === 'severity') {
      c = el('select', 'f-val');
      SEVS.forEach(s => { const o = el('option', null, s); o.value = s; c.appendChild(o); });
      c.value = SEVS.includes(value) ? value : 'high';
    } else {
      c = el('input', 'f-val'); c.type = 'text'; c.maxLength = 200; c.value = value || '';
      c.placeholder = field === 'ip' ? 'e.g. 172.16.100.30' : 'value';
      c.addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(); });
    }
    return c;
  }

  function addFilterRow(field = 'message', op = null, value = '') {
    const rows = $('filterRows');
    const row = el('div', 'f-row');
    row.appendChild(el('span', 'f-join', rows.children.length ? ($('logicSel').value === 'OR' ? 'or' : 'and') : 'where'));

    const fSel = el('select', 'f-field');
    Object.keys(FIELDS).forEach(k => { const o = el('option', null, FIELDS[k].label); o.value = k; fSel.appendChild(o); });
    fSel.value = field;
    const opSel = el('select', 'f-op'); fillOps(opSel, field, op);
    let val = makeValueControl(field, value);
    const del = el('button', 'f-del', '✕'); del.title = 'Remove this filter';

    fSel.addEventListener('change', () => {
      fillOps(opSel, fSel.value);
      const nv = makeValueControl(fSel.value, ''); row.replaceChild(nv, val); val = nv;
    });
    del.addEventListener('click', () => { row.remove(); relabelJoins(); });

    row.append(fSel, opSel, val, del);
    rows.appendChild(row);
    return row;
  }
  function relabelJoins() {
    [...$('filterRows').children].forEach((r, i) => {
      r.querySelector('.f-join').textContent = i === 0 ? 'where' : ($('logicSel').value === 'OR' ? 'or' : 'and');
    });
  }
  function getFilters() {
    return [...$('filterRows').children].map(r => ({
      f: r.querySelector('.f-field').value, op: r.querySelector('.f-op').value,
      v: (r.querySelector('.f-val').value || '').trim()
    })).filter(x => x.v !== '');
  }
  function setFilters(list) {
    $('filterRows').innerHTML = '';
    (list || []).forEach(f => { if (FIELDS[f.f]) addFilterRow(f.f, f.op, f.v); });
  }
  function pivotFilter(field, value) {
    if (!value) return;
    const dupe = getFilters().some(f => f.f === field && f.op === 'is' && f.v === value);
    if (!dupe) addFilterRow(field, 'is', value);
    runSearch();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // State <-> URL <-> controls
  // ═══════════════════════════════════════════════════════════════════════════
  function parseQuick() {
    const raw = $('logQuery').value.trim();
    if (!raw) return null;
    const m = raw.match(/^\/(.+)\/([gimsuy]*)$/);
    if (m) return { f: 'message', op: m[2].includes('i') ? 'regex_i' : 'regex', v: m[1] };
    return { f: 'message', op: regexMode ? 'regex' : 'contains', v: raw };
  }

  function readState() {
    const range = $('rangeSel').value;
    return {
      system: $('sysSelect').value, range,
      from: range === 'custom' ? $('fromDt').value : '', to: range === 'custom' ? $('toDt').value : '',
      logic: $('logicSel').value, q: $('logQuery').value.trim(), rx: regexMode ? 1 : 0,
      filters: getFilters()
    };
  }

  function applyState(s) {
    if (!s) return;
    regexMode = !!(s.rx || s.qmode === 'regex' || s.qmode === 'regex_i');
    $('regexToggle').classList.toggle('active', regexMode);
    $('regexHint').style.display = regexMode ? 'inline' : 'none';
    $('logQuery').value = s.q || '';
    if (s.qmode === 'regex_i' && s.q && !/^\/.+\/[a-z]*$/.test(s.q)) $('logQuery').value = '/' + s.q + '/i';
    $('rangeSel').value = s.range && [...$('rangeSel').options].some(o => o.value === s.range) ? s.range : '24h';
    onRangeChange();
    if (s.from) $('fromDt').value = s.from;
    if (s.to) $('toDt').value = s.to;
    $('logicSel').value = s.logic === 'OR' ? 'OR' : 'AND';
    setFilters(s.filters);
    if (typeof s.system === 'string' && s.system !== $('sysSelect').value) setSystem(s.system, false);
  }

  function pushUrl(view) {
    const s = readState(), p = new URLSearchParams();
    if (s.system) p.set('system', s.system);
    p.set('range', s.range);
    if (s.range === 'custom') { p.set('from', s.from); p.set('to', s.to); }
    if (s.logic === 'OR') p.set('logic', 'OR');
    if (s.q) p.set('q', s.q);
    if (s.rx) p.set('rx', '1');
    if (s.filters.length) p.set('f', JSON.stringify(s.filters));
    p.set('view', view || tab);
    history.replaceState(null, '', '?' + p.toString());
  }

  function stateFromUrl() {
    const p = new URLSearchParams(location.search);
    if (![...p.keys()].length) return null;
    let filters = [];
    try { filters = JSON.parse(p.get('f') || '[]'); } catch { filters = []; }
    return { system: p.get('system') || '', range: p.get('range') || '24h', from: p.get('from') || '',
             to: p.get('to') || '', logic: p.get('logic') || 'AND', q: p.get('q') || '',
             rx: p.get('rx') === '1' ? 1 : 0, filters, view: p.get('view') || '' };
  }

  function onRangeChange() {
    const custom = $('rangeSel').value === 'custom';
    $('customRange').style.display = custom ? 'inline-flex' : 'none';
    if (custom && !$('fromDt').value) {
      const base = lastServerTime ? new Date(lastServerTime.replace(' ', 'T')) : new Date();
      const pad = n => String(n).padStart(2, '0');
      const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
      $('toDt').value = fmt(base);
      $('fromDt').value = fmt(new Date(base.getTime() - 24 * 3600 * 1000));
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Search
  // ═══════════════════════════════════════════════════════════════════════════
  function buildParams(before, forCsv) {
    const s = readState(), p = new URLSearchParams();
    if (s.range === 'custom') { p.set('from', s.from); p.set('to', s.to); } else p.set('range', s.range);
    if (s.system) p.set('system', s.system);
    p.set('logic', s.logic);
    if (s.filters.length) p.set('filters', JSON.stringify(s.filters));
    const q = parseQuick();
    if (q) p.set('must', JSON.stringify([q]));
    if (forCsv) { p.set('format', 'csv'); return p; }
    p.set('limit', String(PAGE));
    if (before) p.set('before', String(before)); else p.set('count', '1');
    return p;
  }

  function showTab(name) {
    tab = name;
    $('tabLive').classList.toggle('active', name === 'live');
    $('tabResults').classList.toggle('active', name === 'results');
    $('paneLive').style.display = name === 'live' ? '' : 'none';
    $('paneResults').style.display = name === 'results' ? '' : 'none';
    const hasRes = lastRows.length > 0;
    $('btnExportPdf').style.display = name === 'results' && hasRes ? '' : 'none';
    $('btnExportCsv').style.display = name === 'results' && hasRes ? '' : 'none';
  }

  async function runSearch(before) {
    const tb = document.querySelector('#resTable tbody');
    if (!before) {
      showTab('results');
      tb.innerHTML = '<tr><td colspan="6" class="muted" style="padding:8px">Searching…</td></tr>';
      $('resBanner').innerHTML = ''; $('moreBtn').style.display = 'none';
    }
    const params = buildParams(before, false);
    const d = await GET('/api/logs/search.php?' + params.toString());
    if (!before) tb.innerHTML = '';

    if (!d.ok) {
      $('resBanner').innerHTML = `<div class="banner err">${escHtml(d.error || 'Search failed')}</div>`;
      if (!before) { lastRows = []; $('resCount').textContent = ''; showTab('results'); }
      return;
    }
    if (d.range && d.range.server_time) { lastServerTime = d.range.server_time; $('serverTime').textContent = 'server time ' + d.range.server_time; }
    if (d.range && d.range.beyond_hot) {
      $('resBanner').innerHTML = `<div class="banner">This range reaches back further than the last ${d.range.hot_days} days kept in the live database. Older logs are in the <a href="/archive.html">Archive</a>.</div>`;
    }
    lastParams = params;
    if (!before) { lastRows = []; pushUrl('results'); }
    lastRows = lastRows.concat(d.rows || []);
    lastNext = d.has_more ? d.next_before : null;

    if (!lastRows.length) {
      tb.innerHTML = '<tr><td colspan="6" class="muted" style="padding:8px">No results.</td></tr>';
    } else {
      renderRows(d.rows || [], tb);
    }
    if (!before && d.count) $('resCount').textContent = `(${d.count.n.toLocaleString()}${d.count.capped ? '+' : ''})`;
    $('moreBtn').style.display = lastNext ? '' : 'none';
    showTab('results');
  }

  function highlightText(text, term) {
    const frag = document.createDocumentFragment();
    if (!term) { frag.appendChild(document.createTextNode(text)); return frag; }
    const low = text.toLowerCase(), t = term.toLowerCase();
    let i = 0, j;
    while ((j = low.indexOf(t, i)) !== -1) {
      if (j > i) frag.appendChild(document.createTextNode(text.slice(i, j)));
      frag.appendChild(el('mark', null, text.slice(j, j + t.length)));
      i = j + t.length;
    }
    if (i < text.length) frag.appendChild(document.createTextNode(text.slice(i)));
    return frag;
  }

  function renderRows(rows, tb) {
    const q = parseQuick();
    const term = q && q.op === 'contains' ? q.v : '';
    rows.forEach(r => {
      const tr = document.createElement('tr');
      const td = (cls, child) => { const c = document.createElement('td'); if (cls) c.style.cssText = cls; if (child) c.append(child); tr.appendChild(c); return c; };
      const tcell = td('white-space:nowrap;color:#4a6a8a', document.createTextNode(r.ts));
      if (r.re) {   // restored from the archive (rehydrated), not a live line
        const mk = el('span', null, ' ↺'); mk.style.color = '#ffd66e'; mk.title = 'Restored from the archive (rehydrated)';
        tcell.appendChild(mk);
      }

      const ip = el('span', 'pivot', r.ip); ip.style.color = '#6ea8fe'; ip.style.fontFamily = 'monospace';
      ip.title = 'Show only this system'; ip.addEventListener('click', () => setSystem(r.ip, true));
      td('white-space:nowrap', ip);

      const h = el('span', r.host ? 'pivot' : '', r.host || '—');
      if (r.host) { h.title = 'Filter by this host'; h.addEventListener('click', () => pivotFilter('hostname', r.host)); }
      td('white-space:nowrap;color:#8aa4c4', h);

      const p = el('span', r.process ? 'pivot' : '', r.process ? r.process + (r.pid ? `[${r.pid}]` : '') : '—');
      if (r.process) { p.title = 'Filter by this process'; p.addEventListener('click', () => pivotFilter('process', r.process)); }
      td('white-space:nowrap;color:#7ab0d8', p);

      const sv = el('span', 'pivot level-' + r.sev, r.sev.toUpperCase());
      sv.title = 'Filter by this severity'; sv.addEventListener('click', () => pivotFilter('severity', r.sev));
      td('white-space:nowrap', sv);

      const m = td('word-break:break-all', highlightText(r.message || '', term));
      m.className = 'level-' + r.sev;
      tb.appendChild(tr);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Live tail
  // ═══════════════════════════════════════════════════════════════════════════
  function renderLine(r) {
    const d = el('div', 'll log ' + r.sev);
    d.dataset.ip = r.ip; d.dataset.sev = r.sev;
    d.appendChild(el('span', 'll-t', (r.ts || '').slice(11, 19)));
    const a = el('a', 'tail-ip ll-ip', r.ip); a.href = '#'; a.title = 'Show only this system';
    a.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); setSystem(r.ip, false); });
    d.appendChild(a);
    if (r.host) d.appendChild(el('span', 'll-h', r.host));
    if (r.process) d.appendChild(el('span', 'll-p', r.process + (r.pid ? `[${r.pid}]` : '') + ':'));
    const txt = String(r.message || '');
    const m = el('span', 'll-m'); m.dataset.raw = txt.length > LINE_MAX ? txt.slice(0, LINE_MAX) + '…' : txt;
    fillMessage(m);
    d.appendChild(m);
    return d;
  }
  function fillMessage(m) {
    m.textContent = '';
    m.appendChild(highlightText(m.dataset.raw, hl));
  }

  async function liveTick(epoch, force) {
    if ((livePaused && !force) || epoch !== liveEpoch) return;
    const box = $('liveLogs'), ip = $('sysSelect').value;
    const url = '/api/logs/live.php?' + (liveMax == null ? 'limit=200' : 'since=' + liveMax + '&limit=500')
              + (ip ? '&ip=' + encodeURIComponent(ip) : '');
    const d = await GET(url);
    if (epoch !== liveEpoch) return;
    if (!d.ok) { $('liveStatus').textContent = d.error || 'Live view error'; return; }
    $('liveStatus').textContent = livePaused ? 'paused' : 'live';
    const near = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    const first = liveMax == null;
    (d.rows || []).forEach(r => box.appendChild(renderLine(r)));
    liveMax = d.max_id;
    if (first && !box.children.length) {
      box.appendChild(el('div', 'muted', ip ? 'No log lines from this system yet — waiting for new ones…' : 'Waiting for log lines…'));
      box.firstChild.dataset.placeholder = '1';
    } else if (box.firstChild && box.firstChild.dataset && box.firstChild.dataset.placeholder && (d.rows || []).length) {
      box.removeChild(box.firstChild);
    }
    while (box.children.length > LOG_CAP) box.removeChild(box.firstChild);
    if (near || first) box.scrollTop = box.scrollHeight;
  }

  function liveLoop(epoch) {
    liveTimer = setTimeout(async () => {
      try { await liveTick(epoch); } catch (e) { console.error(e); }
      if (epoch === liveEpoch) liveLoop(epoch);
    }, 2000);
  }
  function liveStart() {
    liveEpoch++; clearTimeout(liveTimer);
    $('liveLogs').innerHTML = ''; liveMax = null;
    const epoch = liveEpoch;
    liveTick(epoch, true).then(() => { if (epoch === liveEpoch) liveLoop(epoch); });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Saved searches
  // ═══════════════════════════════════════════════════════════════════════════
  let saved = [];
  async function loadSaved() {
    const d = await GET('/api/logs/saved.php');
    const sel = $('savedSel');
    sel.innerHTML = '<option value="">— saved searches —</option>';
    if (!d.ok) { $('savedMsg').textContent = d.error || ''; return; }
    saved = d.searches || [];
    saved.forEach(s => {
      const o = el('option', null, s.name + (s.mine ? (s.shared ? '  (shared)' : '') : `  (by ${s.owner})`));
      o.value = String(s.id); sel.appendChild(o);
    });
    $('delSavedBtn').style.display = 'none';
  }
  function savedSelected() { return saved.find(s => String(s.id) === $('savedSel').value); }

  function savedToState(def) {
    return { system: def.system || '', range: def.range || '24h', from: def.from, to: def.to, logic: def.logic,
             q: def.q, qmode: def.qmode, filters: def.filters };
  }
  async function saveCurrent() {
    const name = $('saveName').value.trim();
    if (!name) { $('savedMsg').textContent = 'Give the search a name.'; return; }
    const s = readState();
    const qmode = (parseQuick() || {}).op || 'contains';
    const def = { system: s.system, range: s.range, from: s.from, to: s.to, logic: s.logic,
                  q: s.q, qmode, filters: s.filters };
    const r = await POST('/api/logs/saved.php', { action: 'save', name, shared: $('saveShared').checked, definition: def });
    $('savedMsg').textContent = r.ok ? 'Saved.' : (r.error || 'Could not save');
    if (r.ok) { $('saveForm').style.display = 'none'; $('saveName').value = ''; await loadSaved(); }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Exports
  // ═══════════════════════════════════════════════════════════════════════════
  function exportCsv() {
    if (!lastParams) return;
    window.location.href = '/api/logs/search.php?' + buildParams(null, true).toString();
  }

  async function exportPdf() {
    if (!lastRows.length) return;
    let logoDataUrl = null;
    try {
      const resp = await fetch('/img/opensiem.png');
      if (!resp.ok) throw new Error('no logo');
      const blob = await resp.blob();
      logoDataUrl = await new Promise((res, rej) => {
        const reader = new FileReader(); reader.onload = () => res(reader.result); reader.onerror = rej; reader.readAsDataURL(blob);
      });
    } catch (e) { /* falls back to the text header */ }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
    const PAGE_W = doc.internal.pageSize.getWidth(), PAGE_H = doc.internal.pageSize.getHeight(), MARGIN = 14;
    const now = new Date(), nowStr = now.toLocaleString(), dateStr = now.toISOString().slice(0, 10);
    const C = { navy: [15, 21, 33], accent: [74, 138, 191], muted: [100, 120, 150], white: [255, 255, 255],
                offwhite: [240, 244, 250], text: [30, 40, 55],
                sev: { critical: [220, 60, 60], high: [230, 120, 50], mid: [200, 170, 50], info: [100, 140, 190] } };

    doc.setFillColor(...C.navy); doc.rect(0, 0, PAGE_W, 22, 'F');
    if (logoDataUrl) {
      doc.addImage(logoDataUrl, 'PNG', MARGIN, 4, 0, 13);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(8); doc.setTextColor(134, 198, 251);
      doc.text('Atom v1  •  Log Search Report', MARGIN + 38, 14);
    } else {
      doc.setFont('helvetica', 'bold'); doc.setFontSize(15); doc.setTextColor(...C.white); doc.text('OpenSIEM', MARGIN, 14);
      doc.setFontSize(9); doc.setFont('helvetica', 'normal'); doc.setTextColor(134, 198, 251);
      doc.text('Atom v1  •  Log Search Report', MARGIN + 36, 14);
    }
    doc.setFontSize(8); doc.setTextColor(180, 200, 220); doc.text(nowStr, PAGE_W - MARGIN, 14, { align: 'right' });
    doc.setDrawColor(...C.accent); doc.setLineWidth(0.5); doc.line(0, 22, PAGE_W, 22);

    // what was searched
    const s = readState(), q = parseQuick();
    const parts = [];
    parts.push('System: ' + (s.system || 'all systems'));
    parts.push('Time: ' + (s.range === 'custom' ? `${s.from} to ${s.to}` : 'last ' + s.range));
    if (q) parts.push(`Message ${OPLABEL[q.op]}: ${q.v}`);
    s.filters.forEach(f => parts.push(`${FIELDS[f.f].label} ${OPLABEL[f.op]} ${f.v}`));
    let y = 30;
    doc.setFont('helvetica', 'bold'); doc.setFontSize(10); doc.setTextColor(...C.text); doc.text('Search', MARGIN, y);
    doc.setFont('helvetica', 'normal'); doc.setTextColor(...C.navy);
    const joiner = s.filters.length > 1 ? (s.logic === 'OR' ? '  |  ANY of: ' : '  |  ALL of: ') : '  |  ';
    const line = parts.slice(0, 2).join('   •   ') + (parts.length > 2 ? joiner + parts.slice(2).join('; ') : '');
    doc.text(doc.splitTextToSize(line, PAGE_W - MARGIN * 2 - 22), MARGIN + 22, y);
    y += 8;
    doc.setFont('helvetica', 'bold'); doc.setTextColor(...C.text); doc.text('Rows', MARGIN, y);
    doc.setFont('helvetica', 'normal'); doc.setTextColor(...C.navy);
    doc.text(`${lastRows.length} log line${lastRows.length !== 1 ? 's' : ''}${lastNext ? ' (more available — use CSV for up to 5,000)' : ''}`, MARGIN + 22, y);

    const sevCounts = {};
    lastRows.forEach(r => { sevCounts[r.sev] = (sevCounts[r.sev] || 0) + 1; });
    let bx = MARGIN + 130;
    ['critical', 'high', 'mid', 'info'].forEach(sev => {
      if (!sevCounts[sev]) return;
      const label = sev.toUpperCase() + ' ' + sevCounts[sev], tw = doc.getTextWidth(label) + 6;
      doc.setFillColor(...C.sev[sev]); doc.roundedRect(bx, y - 5, tw, 6, 1.5, 1.5, 'F');
      doc.setFont('helvetica', 'bold'); doc.setFontSize(7); doc.setTextColor(...C.white); doc.text(label, bx + 3, y - 0.5);
      bx += tw + 3;
    });
    y += 5;
    doc.setDrawColor(210, 220, 235); doc.setLineWidth(0.3); doc.line(MARGIN, y, PAGE_W - MARGIN, y); y += 4;

    const MSG_MAX = 280;
    doc.autoTable({
      startY: y,
      head: [['Time', 'IP', 'Host', 'Process', 'Severity', 'Message']],
      body: lastRows.map(r => [r.ts, r.ip, r.host || '', r.process ? r.process + (r.pid ? `[${r.pid}]` : '') : '',
                               r.sev.toUpperCase(), (r.message || '').length > MSG_MAX ? r.message.slice(0, MSG_MAX) + '…' : (r.message || '')]),
      margin: { left: MARGIN, right: MARGIN },
      styles: { fontSize: 7.5, cellPadding: 2, textColor: C.text, lineColor: [210, 220, 235], lineWidth: 0.2, font: 'helvetica', overflow: 'linebreak' },
      headStyles: { fillColor: C.navy, textColor: C.white, fontStyle: 'bold', fontSize: 8 },
      alternateRowStyles: { fillColor: C.offwhite },
      columnStyles: { 0: { cellWidth: 32 }, 1: { cellWidth: 28 }, 2: { cellWidth: 26 }, 3: { cellWidth: 28 }, 4: { cellWidth: 18, halign: 'center', fontStyle: 'bold' }, 5: { cellWidth: 'auto' } },
      didParseCell(data) {
        if (data.section === 'body' && data.column.index === 4) data.cell.styles.textColor = C.sev[String(data.cell.raw).toLowerCase()] || C.sev.info;
      },
      didDrawPage() {
        const pn = doc.internal.getCurrentPageInfo().pageNumber, pc = doc.internal.getNumberOfPages();
        doc.setFont('helvetica', 'normal'); doc.setFontSize(7); doc.setTextColor(...C.muted);
        doc.text(`OpenSIEM Atom v1  •  Generated ${nowStr}  •  Page ${pn} of ${pc}`, PAGE_W / 2, PAGE_H - 6, { align: 'center' });
        doc.setDrawColor(...C.accent); doc.setLineWidth(0.3); doc.line(MARGIN, PAGE_H - 9, PAGE_W - MARGIN, PAGE_H - 9);
      }
    });
    doc.save(`opensiem-logs-${dateStr}-${(s.system || 'all').replace(/[^a-z0-9_.-]/gi, '_')}.pdf`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Notification bell (unchanged from the previous logs.js)
  // ═══════════════════════════════════════════════════════════════════════════
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

      const div = document.createElement('div');
      div.className    = 'noti-item';
      div.style.cursor = 'pointer';
      div.innerHTML = `
        <div style="flex:1">
          <div class="noti-kind">${(a.alert_type||'').toUpperCase()} — ${escHtml(label)}${escHtml(count)}</div>
          <div class="noti-sev ${sev}">${(a.severity||'MID').toUpperCase()}</div>
        </div>
        <span style="font-size:11px;color:#4a6a8a;align-self:center">▶</span>
      `;
      div.addEventListener('click', () => {
        window.location.href = `/alerts.html?id=${a.id}`;
      });
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

  // ═══════════════════════════════════════════════════════════════════════════
  // init
  // ═══════════════════════════════════════════════════════════════════════════
  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;
    setupBell();

    $('regexToggle').addEventListener('click', () => {
      regexMode = !regexMode;
      $('regexToggle').classList.toggle('active', regexMode);
      $('regexHint').style.display = regexMode ? 'inline' : 'none';
      $('logQuery').placeholder = regexMode ? 'Regex pattern — e.g. 192\\.168\\.\\d+ or fail(ed)?' : 'Search message text… keyword, or /regex/i';
    });
    $('logQuery').addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(); });
    $('searchBtn').addEventListener('click', () => runSearch());
    $('addFilterBtn').addEventListener('click', () => addFilterRow());
    $('clearBtn').addEventListener('click', () => {
      $('logQuery').value = ''; setFilters([]); $('rangeSel').value = '24h'; onRangeChange();
      $('logicSel').value = 'AND'; lastRows = []; lastNext = null;
      document.querySelector('#resTable tbody').innerHTML = ''; $('resCount').textContent = ''; $('resBanner').innerHTML = '';
      $('moreBtn').style.display = 'none'; $('savedSel').value = '';
      showTab('live'); pushUrl('live');
    });
    $('rangeSel').addEventListener('change', onRangeChange);
    $('logicSel').addEventListener('change', relabelJoins);
    $('moreBtn').addEventListener('click', () => { if (lastNext) runSearch(lastNext); });
    $('tabLive').addEventListener('click', () => { showTab('live'); pushUrl('live'); });
    $('tabResults').addEventListener('click', () => showTab('results'));
    $('sysSelect').addEventListener('change', () => setSystem($('sysSelect').value, true));
    $('btnExportCsv').addEventListener('click', exportCsv);
    $('btnExportPdf').addEventListener('click', exportPdf);

    // live controls
    $('pauseBtn').addEventListener('click', () => {
      livePaused = !livePaused;
      $('pauseBtn').textContent = livePaused ? '▶ Resume' : '⏸ Pause';
      $('pauseBtn').classList.toggle('active', livePaused);
      $('liveStatus').textContent = livePaused ? 'paused' : 'live';
      if (!livePaused) liveTick(liveEpoch);
    });
    $('minSev').addEventListener('change', () => {
      $('liveLogs').className = 'console' + ($('minSev').value ? ' minsev-' + $('minSev').value : '');
    });
    let hlT = null;
    $('hlInput').addEventListener('input', () => {
      clearTimeout(hlT);
      hlT = setTimeout(() => { hl = $('hlInput').value.trim(); document.querySelectorAll('#liveLogs .ll-m').forEach(fillMessage); }, 200);
    });
    $('liveClear').addEventListener('click', () => { $('liveLogs').innerHTML = ''; });

    // saved searches
    $('saveBtn').addEventListener('click', () => { $('saveForm').style.display = 'inline-flex'; $('saveName').focus(); });
    $('saveCancel').addEventListener('click', () => { $('saveForm').style.display = 'none'; });
    $('saveOk').addEventListener('click', saveCurrent);
    $('savedSel').addEventListener('change', () => {
      const s = savedSelected();
      $('delSavedBtn').style.display = s && s.mine ? '' : 'none';
      if (s) { applyState(savedToState(s.definition)); runSearch(); }
    });
    $('delSavedBtn').addEventListener('click', async () => {
      const s = savedSelected();
      if (!s || !confirm(`Delete the saved search "${s.name}"?`)) return;
      const r = await POST('/api/logs/saved.php', { action: 'delete', id: s.id });
      $('savedMsg').textContent = r.ok ? 'Deleted.' : (r.error || 'Could not delete');
      await loadSaved();
    });

    await loadSystems();
    loadSaved();
    setInterval(loadSystems, 60000);
    setInterval(() => { if ($('sysSelect').value) refreshStrip(); }, 15000);

    // open straight into a system or a saved view when the URL asks for it (dashboard click-through)
    const st = stateFromUrl();
    if (st) {
      applyState(st);
      const wantsResults = st.view === 'results' || st.q || (st.filters && st.filters.length);
      if (wantsResults) { runSearch(); } else { showTab('live'); }
    } else {
      showTab('live');
    }
    booting = false;
    liveStart();
    refreshStrip();
  })();
})();
