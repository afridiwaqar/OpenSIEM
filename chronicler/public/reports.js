/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
(() => {
  const $   = id  => document.getElementById(id);
  const qsa = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  let csrf = null, lastData = null;

  const charts = {};

  const SEV_COLORS = {
    critical: '#ff6b6b',
    high:     '#ff9a3c',
    mid:      '#ffd66e',
    low:      '#7eb3cb',
    info:     '#6ea8fe',
  };
  const CHART_COLORS = ['#6ea8fe','#a18cff','#60d394','#f7b267','#ff9a9a','#7ecb7e','#ffd66e','#ff6b6b'];

  (async function init() {
    const me = await GET('/api/auth/me.php');
    if (!me.ok) { location.href = '/login.html'; return; }
    csrf = me.csrf;

    setupBell();
    $('btnRefresh').addEventListener('click',    () => loadReport());
    $('periodSelect').addEventListener('change', () => loadReport());
    $('btnExportPdf').addEventListener('click',  exportPdf);

    await loadReport();
  })();

  async function GET(path) {
    const r = await fetch(path, { cache: 'no-store' });
    const t = await r.text();
    try { return JSON.parse(t); }
    catch { console.error('GET parse error', path, t); return { ok: false }; }
  }

  async function loadReport() {
    const hours = $('periodSelect').value;
    $('loadingBadge').style.display = 'inline';
    $('btnExportPdf').disabled = true;

    const s = await GET(`/api/reports/stats.php?hours=${hours}`);
    if (!s.ok) { $('loadingBadge').style.display = 'none'; return; }

    lastData = s;

    renderKPIs(s);
    renderCharts(s);
    renderUnacked(s);
    renderIOCs(s);

    $('loadingBadge').style.display  = 'none';
    $('btnExportPdf').disabled       = false;
    $('lastUpdated').textContent     = 'Updated: ' + new Date().toLocaleTimeString();
  }

  function renderKPIs(s) {
    const k      = s.kpi || {};
    const total  = k.total_alerts  || 0;
    const acked  = k.acked_alerts  || 0;
    const active = k.active_alerts || 0;
    const pct    = total ? Math.round(acked / total * 100) : 0;
    const mtta   = s.mtta_minutes || 0;
    const mttaStr = mtta === 0 ? '—'
                  : mtta < 60  ? mtta + ' min'
                  : (mtta / 60).toFixed(1) + ' hr';

    $('kCritical').textContent   = k.critical_count   ?? '—';
    $('kHigh').textContent       = k.high_count        ?? '—';
    $('kTotal').textContent      = total;
    $('kAcked').textContent      = acked;
    $('kAckedPct').textContent   = `${pct}% of total`;
    $('kMtta').textContent       = mttaStr;
    $('kMessages').textContent   = (s.msg_kpi?.total_messages ?? '—').toLocaleString?.() ?? s.msg_kpi?.total_messages ?? '—';
    $('kCorrelation').textContent = k.correlation_count ?? '—';
    $('kArtifact').textContent   = k.artifact_count    ?? '—';
  }

  function destroyChart(key) {
    if (charts[key]) { charts[key].destroy(); delete charts[key]; }
  }

  function makeChart(key, ctx, type, data, options = {}) {
    destroyChart(key);
    charts[key] = new Chart(ctx, { type, data, options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#9aa8bd', font: { size: 11 } } } },
      scales: type !== 'doughnut' && type !== 'pie' ? {
        x: { ticks: { color: '#6a8aaa', font: { size: 10 } }, grid: { color: '#1c2434' } },
        y: { beginAtZero: true, ticks: { color: '#6a8aaa', font: { size: 10 } }, grid: { color: '#1c2434' } }
      } : undefined,
      ...options
    }});
  }

  function renderCharts(s) {
    // 1. Alert volume over time (line)
    makeChart('alertVolume', $('chartAlertVolume'), 'line', {
      labels:   (s.alert_volume || []).map(r => r.ts),
      datasets: [{ label: 'Alerts', data: (s.alert_volume || []).map(r => r.c),
                   borderColor: '#6ea8fe', backgroundColor: 'rgba(110,168,254,.1)',
                   fill: true, tension: .3, pointRadius: 2 }]
    });

    // 2. Alerts by severity (doughnut)
    const sevOrder = ['critical','high','mid','low'];
    makeChart('alertSev', $('chartAlertSev'), 'doughnut', {
      labels:   sevOrder.map(s => s.toUpperCase()),
      datasets: [{ data: sevOrder.map(k => s.alerts_by_sev?.[k] || 0),
                   backgroundColor: sevOrder.map(k => SEV_COLORS[k]) }]
    }, { plugins: { legend: { position: 'bottom', labels: { color: '#9aa8bd', font: { size: 11 } } } } });

    // 3. Alert type (doughnut)
    const types  = (s.alerts_by_type || []);
    makeChart('alertType', $('chartAlertType'), 'doughnut', {
      labels:   types.map(r => r.alert_type.toUpperCase()),
      datasets: [{ data: types.map(r => r.c), backgroundColor: CHART_COLORS }]
    }, { plugins: { legend: { position: 'bottom', labels: { color: '#9aa8bd', font: { size: 11 } } } } });

    // 4. Message volume (bar)
    makeChart('msgVolume', $('chartMsgVolume'), 'bar', {
      labels:   (s.msg_volume || []).map(r => r.ts),
      datasets: [{ label: 'Messages', data: (s.msg_volume || []).map(r => r.c),
                   backgroundColor: 'rgba(161,140,255,.7)' }]
    });

    // 5. Top IPs (horizontal bar)
    const ips = (s.top_ips || []);
    makeChart('topIPs', $('chartTopIPs'), 'bar', {
      labels:   ips.map(r => r.ip),
      datasets: [{ label: 'Alerts', data: ips.map(r => r.c),
                   backgroundColor: 'rgba(247,178,103,.8)' }]
    }, { indexAxis: 'y' });

    // 6. Correlation rules (horizontal bar)
    const corr = (s.correlation || []);
    makeChart('correlation', $('chartCorrelation'), 'bar', {
      labels:   corr.map(r => r.case_name),
      datasets: [{ label: 'Hits', data: corr.map(r => r.c),
                   backgroundColor: 'rgba(96,211,148,.8)' }]
    }, { indexAxis: 'y' });

    // 7. Artifact by severity (bar)
    makeChart('artifactSev', $('chartArtifactSev'), 'bar', {
      labels:   sevOrder.map(s => s.toUpperCase()),
      datasets: [{ label: 'IOC Hits', data: sevOrder.map(k => s.artifact_by_sev?.[k] || 0),
                   backgroundColor: sevOrder.map(k => SEV_COLORS[k] + 'cc') }]
    });
  }

  function renderUnacked(s) {
    const rows  = s.unacked_critical || [];
    const tb    = document.querySelector('#unackedTable tbody');
    const empty = $('unackedEmpty');
    tb.innerHTML = '';

    if (rows.length === 0) {
      if (empty) empty.style.display = 'block';
      $('unackedTable').style.display = 'none';
      return;
    }
    $('unackedTable').style.display = '';
    if (empty) empty.style.display = 'none';

    rows.forEach(a => {
      let name = '';
      try { const n = JSON.parse(a.admin_note || '{}'); name = n.case_name || n.artifact || ''; } catch {}

      const sev = a.severity || 'high';
      const tr  = document.createElement('tr');
      tr.innerHTML = `
        <td style="color:#4a6a8a">${a.id}</td>
        <td>${escHtml(a.alert_type || '—')}</td>
        <td><span class="sev sev-${sev}">${sev.toUpperCase()}</span></td>
        <td>${escHtml(a.source_ip || '—')}</td>
        <td>${a.count || 1}</td>
        <td style="font-size:11px;color:#6a8aaa">${fmt(a.first_seen)}</td>
        <td style="font-size:11px;color:#6a8aaa">${fmt(a.last_seen)}</td>
      `;
      tb.appendChild(tr);
    });
  }

  function renderIOCs(s) {
    const rows  = s.top_iocs || [];
    const tb    = document.querySelector('#iocTable tbody');
    const empty = $('iocEmpty');
    tb.innerHTML = '';

    if (rows.length === 0) {
      if (empty) empty.style.display = 'block';
      $('iocTable').style.display = 'none';
      return;
    }
    $('iocTable').style.display = '';
    if (empty) empty.style.display = 'none';

    rows.forEach(r => {
      const sev = r.severity || 'mid';
      const tr  = document.createElement('tr');
      tr.innerHTML = `
        <td style="word-break:break-all;font-family:monospace;font-size:12px">${escHtml(r.artifact)}</td>
        <td><span class="sev sev-${sev}">${sev.toUpperCase()}</span></td>
        <td style="font-weight:700;color:#c8dff5">${r.c}</td>
      `;
      tb.appendChild(tr);
    });
  }

  function fmt(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
  }

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch]));
  }

  async function exportPdf() {
    if (!lastData) return;

    let logoDataUrl = null;
    try {
      const resp = await fetch('/img/opensiem.png', { cache: 'force-cache' });
      const blob = await resp.blob();
      logoDataUrl = await new Promise((res, rej) => {
        const reader = new FileReader();
        reader.onload  = () => res(reader.result);
        reader.onerror = rej;
        reader.readAsDataURL(blob);
      });
    } catch (e) {
      console.warn('Could not load opensiem.png for PDF — falling back to text', e);
    }
    const { jsPDF } = window.jspdf;
    const doc   = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const PW    = doc.internal.pageSize.getWidth();
    const PH    = doc.internal.pageSize.getHeight();
    const M     = 14;   // margin
    const now   = new Date();
    const nowStr = now.toLocaleString();
    const dateStr = now.toISOString().slice(0, 10);
    const periodLabel = $('periodSelect').options[$('periodSelect').selectedIndex].text;

    const C = {
      navy:   [15,  21,  33],
      blue:   [26,  58,  92],
      accent: [74, 138, 191],
      muted:  [100, 120, 150],
      white:  [255, 255, 255],
      offwhite:[240,244,250],
      text:   [30,  40,  55],
      red:    [220, 60,  60],
      orange: [230,120,  50],
      yellow: [200,170,  50],
      green:  [80, 160,  80],
      lblue:  [80, 140, 200],
      sev: { critical:[220,60,60], high:[230,120,50], mid:[200,170,50], low:[80,160,80] }
    };

    function hdrFooter(pageNum, totalPages) {
      doc.setFillColor(...C.navy);
      doc.rect(0, 0, PW, 18, 'F');

      if (logoDataUrl) {
        doc.addImage(logoDataUrl, 'PNG', M, 3, 0, 12);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(160, 200, 230);
        doc.text('Atom v1  •  Security Report', M + 38, 12);
      } else {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.setTextColor(...C.white);
        doc.text('OpenSIEM', M, 12);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(160, 200, 230);
        doc.text('Atom v1  •  Security Report', M + 28, 12);
      }

      doc.setFontSize(8);
      doc.setTextColor(130, 160, 190);
      doc.text(periodLabel + '  •  Generated ' + nowStr, PW - M, 12, { align: 'right' });

      doc.setDrawColor(...C.accent);
      doc.setLineWidth(0.4);
      doc.line(0, 18, PW, 18);

      doc.setDrawColor(...C.accent);
      doc.setLineWidth(0.25);
      doc.line(M, PH - 10, PW - M, PH - 10);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(...C.muted);
      doc.text(
        `OpenSIEM Atom v1  •  Confidential  •  Page ${pageNum} of ${totalPages}`,
        PW / 2, PH - 6, { align: 'center' }
      );
    }

    let y = 24; // start below header
    const k = lastData.kpi || {};

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(...C.navy);
    doc.text('Security Operations Report', M, y + 6);
    y += 12;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(...C.muted);
    doc.text(periodLabel, M, y);
    y += 10;

    // Separator
    doc.setDrawColor(210, 220, 235);
    doc.setLineWidth(0.3);
    doc.line(M, y, PW - M, y);
    y += 8;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(...C.muted);
    doc.text('EXECUTIVE SUMMARY', M, y);
    y += 6;

    const total  = k.total_alerts  || 0;
    const acked  = k.acked_alerts  || 0;
    const pct    = total ? Math.round(acked / total * 100) : 0;
    const mtta   = lastData.mtta_minutes || 0;
    const mttaStr = mtta === 0 ? 'N/A'
                  : mtta < 60  ? mtta + ' min'
                  : (mtta / 60).toFixed(1) + ' hr';

    const kpis = [
      { label: 'Total Alerts',      value: total,                   color: C.navy   },
      { label: 'Acknowledged',      value: `${acked} (${pct}%)`,    color: C.green  },
      { label: 'Critical Alerts',   value: k.critical_count || 0,   color: C.red    },
      { label: 'High Alerts',       value: k.high_count     || 0,   color: C.orange },
      { label: 'Avg Ack Time (MTTA)',value: mttaStr,                 color: C.lblue  },
      { label: 'Log Messages',      value: (lastData.msg_kpi?.total_messages || 0).toLocaleString(), color: C.navy },
      { label: 'Correlation Hits',  value: k.correlation_count || 0, color: C.navy  },
      { label: 'IOC Hits',          value: k.artifact_count    || 0, color: C.navy  },
    ];

    const colW = (PW - M * 2 - 6) / 2;
    kpis.forEach((kpi, i) => {
      const col = i % 2;
      const row = Math.floor(i / 2);
      const bx  = M + col * (colW + 6);
      const by  = y + row * 18;

      doc.setFillColor(240, 244, 250);
      doc.roundedRect(bx, by, colW, 14, 2, 2, 'F');
      doc.setDrawColor(210, 220, 235);
      doc.setLineWidth(0.2);
      doc.roundedRect(bx, by, colW, 14, 2, 2, 'S');

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...C.muted);
      doc.text(kpi.label.toUpperCase(), bx + 4, by + 5);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(13);
      doc.setTextColor(...kpi.color);
      doc.text(String(kpi.value), bx + 4, by + 11.5);
    });

    y += Math.ceil(kpis.length / 2) * 18 + 8;

    // Separator
    doc.setDrawColor(210, 220, 235);
    doc.setLineWidth(0.3);
    doc.line(M, y, PW - M, y);
    y += 8;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(...C.muted);
    doc.text('OPEN CRITICAL & HIGH ALERTS', M, y);
    y += 5;

    const unacked = lastData.unacked_critical || [];
    if (unacked.length === 0) {
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(10);
      doc.setTextColor(...C.green);
      doc.text('✔  No unacknowledged critical or high alerts.', M, y + 5);
      y += 14;
    } else {
      doc.autoTable({
        startY: y,
        head:   [['ID', 'Type', 'Severity', 'Source IP', 'Hits', 'First Seen', 'Last Seen']],
        body:   unacked.map(a => [
          a.id, a.alert_type || '—', (a.severity||'high').toUpperCase(),
          a.source_ip || '—', a.count || 1,
          fmt(a.first_seen), fmt(a.last_seen)
        ]),
        margin:      { left: M, right: M },
        styles:      { fontSize: 8, cellPadding: 2, textColor: C.text, lineColor: [210,220,235], lineWidth: 0.2 },
        headStyles:  { fillColor: C.navy, textColor: C.white, fontSize: 8, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: C.offwhite },
        columnStyles: {
          0: { cellWidth: 12, halign: 'right', textColor: C.muted },
          2: { cellWidth: 20, halign: 'center', fontStyle: 'bold' },
          4: { cellWidth: 10, halign: 'center' },
        },
        didParseCell(data) {
          if (data.section === 'body' && data.column.index === 2) {
            const v = data.cell.raw.toLowerCase();
            data.cell.styles.textColor = v.includes('critical') ? C.sev.critical
                                       : v.includes('high')     ? C.sev.high
                                       : C.sev.mid;
          }
        },
        didDrawPage(data) { y = data.cursor.y + 6; }
      });
      y = doc.lastAutoTable.finalY + 8;
    }

    doc.addPage();
    y = 24;

    // Alert volume table
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(...C.muted);
    doc.text('ALERT ACTIVITY', M, y);
    y += 5;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(...C.navy);
    doc.text('Alert Volume Over Time', M, y);
    y += 4;

    const volRows = (lastData.alert_volume || []).map(r => [r.ts, r.c]);
    if (volRows.length) {
      doc.autoTable({
        startY: y,
        head: [['Time Bucket', 'Alert Count']],
        body: volRows,
        margin: { left: M, right: M },
        styles: { fontSize: 8, cellPadding: 2, textColor: C.text, lineColor: [210,220,235], lineWidth: 0.2 },
        headStyles: { fillColor: C.blue, textColor: C.white, fontSize: 8 },
        alternateRowStyles: { fillColor: C.offwhite },
        columnStyles: { 1: { halign: 'right', fontStyle: 'bold' } },
        tableWidth: (PW - M * 2) / 2,  // only half width
        didDrawPage(data) {}
      });
      y = doc.lastAutoTable.finalY + 8;
    } else {
      doc.setFont('helvetica', 'italic'); doc.setFontSize(9); doc.setTextColor(...C.muted);
      doc.text('No alert volume data for this period.', M, y + 4); y += 12;
    }

    // Severity breakdown table
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(...C.navy);
    doc.text('Alerts by Severity', M, y);
    y += 4;

    const sevData = lastData.alerts_by_sev || {};
    const sevRows = ['critical','high','mid','low'].map(k => [k.toUpperCase(), sevData[k] || 0]);
    doc.autoTable({
      startY: y,
      head:   [['Severity', 'Count']],
      body:   sevRows,
      margin: { left: M, right: M },
      styles: { fontSize: 8, cellPadding: 2, textColor: C.text, lineColor: [210,220,235], lineWidth: 0.2 },
      headStyles: { fillColor: C.blue, textColor: C.white, fontSize: 8 },
      alternateRowStyles: { fillColor: C.offwhite },
      columnStyles: { 1: { halign: 'right', fontStyle: 'bold' } },
      tableWidth: (PW - M * 2) / 2,
      didParseCell(data) {
        if (data.section === 'body' && data.column.index === 0) {
          const v = data.cell.raw.toLowerCase();
          data.cell.styles.textColor = C.sev[v] || C.text;
          data.cell.styles.fontStyle = 'bold';
        }
      },
      didDrawPage(data) {}
    });
    y = doc.lastAutoTable.finalY + 10;

    doc.addPage();
    y = 24;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(...C.muted);
    doc.text('THREAT INTELLIGENCE', M, y);
    y += 5;

    // Top IPs
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(...C.navy);
    doc.text('Top Attacked Systems', M, y);
    y += 4;

    const ipRows = (lastData.top_ips || []).map(r => [r.ip, r.c]);
    if (ipRows.length) {
      doc.autoTable({
        startY: y, head: [['Source IP', 'Alert Count']], body: ipRows,
        margin: { left: M, right: M },
        styles: { fontSize: 8, cellPadding: 2, textColor: C.text, lineColor: [210,220,235], lineWidth: 0.2 },
        headStyles: { fillColor: C.navy, textColor: C.white, fontSize: 8 },
        alternateRowStyles: { fillColor: C.offwhite },
        columnStyles: { 0: { fontStyle: 'bold', font: 'courier' }, 1: { halign: 'right', fontStyle: 'bold' } },
        tableWidth: (PW - M * 2) / 2,
        didDrawPage(data) {}
      });
      y = doc.lastAutoTable.finalY + 10;
    }

    // Correlation rules
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(...C.navy);
    doc.text('Top Correlation Rule Triggers', M, y);
    y += 4;

    const corrRows = (lastData.correlation || []).map(r => [r.case_name, r.c]);
    if (corrRows.length) {
      doc.autoTable({
        startY: y, head: [['Rule / Use Case', 'Hits']], body: corrRows,
        margin: { left: M, right: M },
        styles: { fontSize: 8, cellPadding: 2, textColor: C.text, lineColor: [210,220,235], lineWidth: 0.2 },
        headStyles: { fillColor: C.navy, textColor: C.white, fontSize: 8 },
        alternateRowStyles: { fillColor: C.offwhite },
        columnStyles: { 1: { halign: 'right', fontStyle: 'bold', cellWidth: 20 } },
        didDrawPage(data) {}
      });
      y = doc.lastAutoTable.finalY + 10;
    }

    // Top IOCs
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(...C.navy);
    doc.text('Top Triggered IOC Artifacts', M, y);
    y += 4;

    const iocRows = (lastData.top_iocs || []).map(r => [r.artifact, r.severity.toUpperCase(), r.c]);
    if (iocRows.length) {
      doc.autoTable({
        startY: y, head: [['Artifact / IOC', 'Severity', 'Hits']], body: iocRows,
        margin: { left: M, right: M },
        styles: { fontSize: 7.5, cellPadding: 2, textColor: C.text, lineColor: [210,220,235], lineWidth: 0.2 },
        headStyles: { fillColor: C.navy, textColor: C.white, fontSize: 8 },
        alternateRowStyles: { fillColor: C.offwhite },
        columnStyles: {
          0: { fontStyle: 'bold' },
          1: { cellWidth: 22, halign: 'center', fontStyle: 'bold' },
          2: { cellWidth: 14, halign: 'right',  fontStyle: 'bold' }
        },
        didParseCell(data) {
          if (data.section === 'body' && data.column.index === 1) {
            const v = data.cell.raw.toLowerCase();
            data.cell.styles.textColor = C.sev[v] || C.text;
          }
        },
        didDrawPage(data) {}
      });
    }

    const totalPages = doc.internal.getNumberOfPages();
    for (let p = 1; p <= totalPages; p++) {
      doc.setPage(p);
      hdrFooter(p, totalPages);
    }

    const filename = `opensiem-report-${dateStr}-${$('periodSelect').value}h.pdf`;
    doc.save(filename);
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
      div.className = 'noti-item'; div.style.cursor = 'pointer';
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
