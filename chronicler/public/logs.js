/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $ = (id) => document.getElementById(id);
  const LOG_CAP = 1000, LINE_MAX = 4096;
  let csrf = null, lastSince = null;
  let regexMode   = false;
  let lastResults = [];     // most recent search results — used for PDF export
  let lastQuery   = '';

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;

    setupBell();

    // Regex toggle button
    $('regexToggle').addEventListener('click', () => {
      regexMode = !regexMode;
      $('regexToggle').classList.toggle('active', regexMode);
      $('regexHint').style.display = regexMode ? 'inline' : 'none';
      $('logQuery').placeholder = regexMode
        ? 'Regex pattern — e.g. 192\\.168\\.\\d+ or fail(ed)?'
        : 'Search logs… keyword, IP, or /regex/i';
    });

    // Allow Enter key in search box
    $('logQuery').addEventListener('keydown', e => {
      if (e.key === 'Enter') onSearch();
    });

    $('searchBtn').addEventListener('click', onSearch);
    $('btnExportPdf')?.addEventListener('click', exportPdf);

    loadTail();
    setInterval(loadTail, 1500);
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

  async function loadTail() {
    const url = `/api/get_live_logs.php${lastSince ? `?since=${encodeURIComponent(lastSince)}` : ''}`;
    const d   = await GET(url);
    const box = $('liveLogs');

    (d.logs || []).forEach(line => {
      const el  = document.createElement('div');
      el.className = `log ${line.level || 'info'}`;
      const txt = String(line.text || '');
      el.textContent = txt.length > LINE_MAX ? txt.slice(0, LINE_MAX) + '…' : txt;
      box.appendChild(el);
    });

    if (d.logs && d.logs.length) {
      lastSince     = d.logs[d.logs.length - 1].ts;
      box.scrollTop = box.scrollHeight;
    }

    while (box.children.length > LOG_CAP) box.removeChild(box.firstChild);
  }

  async function onSearch() {
    const raw = $('logQuery').value.trim();
    if (!raw) return;

    let pattern = raw;
    let isRegex = regexMode;
    let flags   = '';

    const slashMatch = raw.match(/^\/(.+)\/([gimsuy]*)$/);
    if (slashMatch) {
      pattern = slashMatch[1];
      flags   = slashMatch[2];
      isRegex = true;
    }

    const tb = document.querySelector('#resTable tbody');
    tb.innerHTML = '<tr><td colspan="3" style="color:#9aa8bd;font-size:12px;padding:8px">Searching…</td></tr>';

    let res;
    try {
      res = await POST('/api/search_logs.php', {
        q:     pattern,
        regex: isRegex,
        flags: flags
      });
    } catch (e) {
      tb.innerHTML = `<tr class="err-row"><td colspan="3">Network error: ${escHtml(String(e))}</td></tr>`;
      return;
    }

    tb.innerHTML = '';

    if (res.error || res.ok === false) {
      const tr = document.createElement('tr');
      tr.className = 'err-row';
      tr.innerHTML = `<td colspan="3">${escHtml(res.error || 'Search failed')}</td>`;
      tb.appendChild(tr);
      return;
    }

    const results = Array.isArray(res.results) ? res.results
                  : Array.isArray(res)          ? res
                  : [];

    if (results.length === 0) {
      tb.innerHTML = '<tr><td colspan="3" style="color:#9aa8bd;font-size:12px;padding:8px">No results.</td></tr>';
      const cnt = $('resCount');    if (cnt)    cnt.textContent = '';
      const btn = $('btnExportPdf'); if (btn)  btn.style.display = 'none';
      lastResults = [];
      lastQuery   = '';
      return;
    }

    lastResults = results;
    lastQuery   = $('logQuery').value.trim();

    const cnt = $('resCount');    if (cnt)   cnt.textContent = `(${results.length})`;
    const btn = $('btnExportPdf'); if (btn)  btn.style.display = 'inline-block';

    results.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="white-space:nowrap;color:#4a6a8a;vertical-align:top">${r.id}</td>
        <td style="white-space:nowrap;vertical-align:top"><span class="level-${r.level||'info'}">${(r.level||'info').toUpperCase()}</span></td>
        <td style="word-break:break-all">${escHtml(r.text || '')}</td>
      `;
      tb.appendChild(tr);
    });
  }

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, ch =>
      ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[ch])
    );
  }

  async function exportPdf() {
    if (!lastResults.length) return;

    let logoDataUrl = null;
    try {
      const blob = await resp.blob();
      logoDataUrl = await new Promise((res, rej) => {
        const reader = new FileReader();
        reader.onload  = () => res(reader.result);
        reader.onerror = rej;
        reader.readAsDataURL(blob);
      });
    } catch(e) {
      console.warn('Could not load opensiem.png for PDF — falling back to text', e);
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });

    const PAGE_W  = doc.internal.pageSize.getWidth();
    const PAGE_H  = doc.internal.pageSize.getHeight();
    const MARGIN  = 14;
    const now     = new Date();
    const nowStr  = now.toLocaleString();
    const dateStr = now.toISOString().slice(0, 10);

    const C = {
      navy:    [15,  21,  33],   // #0f1521
      blue:    [26,  58,  92],   // #1a3a5c
      accent:  [74, 138, 191],   // #4a8abf
      muted:   [100, 120, 150],
      white:   [255, 255, 255],
      offwhite:[240, 244, 250],
      text:    [30,  40,  55],
      sev: {
        critical: [220, 60,  60],
        high:     [230, 120, 50],
        mid:      [200, 170, 50],
        low:      [80,  160, 80],
        info:     [100, 140, 190],
      }
    };

    doc.setFillColor(...C.navy);
    doc.rect(0, 0, PAGE_W, 22, 'F');

    if (logoDataUrl) {
      doc.addImage(logoDataUrl, 'PNG', MARGIN, 4, 0, 13);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(...C.accent.map(v => Math.min(255, v + 60)));
      doc.text('Atom v1  •  Log Search Report', MARGIN + 38, 14);
    } else {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(15);
      doc.setTextColor(...C.white);
      doc.text('OpenSIEM', MARGIN, 14);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...C.accent.map(v => Math.min(255, v + 60)));
      doc.text('Atom v1  •  Log Search Report', MARGIN + 36, 14);
    }

    doc.setFontSize(8);
    doc.setTextColor(180, 200, 220);
    doc.text(nowStr, PAGE_W - MARGIN, 14, { align: 'right' });

    doc.setDrawColor(...C.accent);
    doc.setLineWidth(0.5);
    doc.line(0, 22, PAGE_W, 22);

    let y = 30;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...C.text);
    doc.text('Search Query', MARGIN, y);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(...C.navy);
    const qDisplay = lastQuery.length > 120 ? lastQuery.slice(0, 120) + '…' : lastQuery;
    doc.text(qDisplay, MARGIN + 32, y);

    y += 7;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...C.text);
    doc.text('Results', MARGIN, y);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(...C.navy);
    doc.text(`${lastResults.length} log line${lastResults.length !== 1 ? 's' : ''}`, MARGIN + 32, y);

    // Severity summary badges
    const sevCounts = {};
    lastResults.forEach(r => { sevCounts[r.level||'info'] = (sevCounts[r.level||'info']||0) + 1; });
    let bx = MARGIN + 80;
    const SEV_ORDER = ['critical','high','mid','low','info'];
    SEV_ORDER.forEach(sev => {
      if (!sevCounts[sev]) return;
      const label  = sev.toUpperCase();
      const count  = String(sevCounts[sev]);
      const bColor = C.sev[sev] || C.sev.info;

      // Pill background
      const tw = doc.getTextWidth(label + ' ' + count) + 6;
      doc.setFillColor(...bColor);
      doc.roundedRect(bx, y - 5, tw, 6, 1.5, 1.5, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(...C.white);
      doc.text(label + ' ' + count, bx + 3, y - 0.5);
      bx += tw + 3;
    });

    y += 4;
    // Separator
    doc.setDrawColor(210, 220, 235);
    doc.setLineWidth(0.3);
    doc.line(MARGIN, y, PAGE_W - MARGIN, y);
    y += 6;

    const MSG_MAX = 280;
    const tableRows = lastResults.map(r => {
      const msg = (r.text || '').length > MSG_MAX
        ? r.text.slice(0, MSG_MAX) + '…'
        : (r.text || '');
      return [
        String(r.id || ''),
        (r.level || 'info').toUpperCase(),
        msg
      ];
    });

    doc.autoTable({
      startY: y,
      head:   [['ID', 'Severity', 'Message']],
      body:   tableRows,
      margin: { left: MARGIN, right: MARGIN },
      styles: {
        fontSize:    8,
        cellPadding: 2.5,
        textColor:   C.text,
        lineColor:   [210, 220, 235],
        lineWidth:   0.2,
        font:        'helvetica',
        overflow:    'linebreak',
      },
      headStyles: {
        fillColor:  C.navy,
        textColor:  C.white,
        fontStyle:  'bold',
        fontSize:   8.5,
      },
      alternateRowStyles: {
        fillColor: C.offwhite,
      },
      columnStyles: {
        0: { cellWidth: 16,  halign: 'right', textColor: C.muted },
        1: { cellWidth: 22,  halign: 'center', fontStyle: 'bold' },
        2: { cellWidth: 'auto' },
      },
      // Colour severity cells
      didParseCell(data) {
        if (data.section === 'body' && data.column.index === 1) {
          const sev = data.cell.raw.toLowerCase().replace('critical','critical')
                                                  .replace('high','high')
                                                  .replace('mid','mid')
                                                  .replace('low','low')
                                                  .replace('info','info');
          const color = C.sev[sev] || C.sev.info;
          data.cell.styles.textColor = color;
        }
      },
      // Footer with page numbers
      didDrawPage(data) {
        const pn = doc.internal.getCurrentPageInfo().pageNumber;
        const pc = doc.internal.getNumberOfPages();
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(...C.muted);
        doc.text(
          `OpenSIEM Atom v1  •  Generated ${nowStr}  •  Page ${pn} of ${pc}`,
          PAGE_W / 2, PAGE_H - 6, { align: 'center' }
        );
        // Footer line
        doc.setDrawColor(...C.accent);
        doc.setLineWidth(0.3);
        doc.line(MARGIN, PAGE_H - 9, PAGE_W - MARGIN, PAGE_H - 9);
      }
    });

    const filename = `opensiem-logs-${dateStr}-${lastQuery.slice(0,30).replace(/[^a-z0-9_-]/gi,'_') || 'search'}.pdf`;
    doc.save(filename);
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
})();
