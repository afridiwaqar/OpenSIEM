<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
?>
<?php /* Chronicler Dashboard */ ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OpenSIEM • Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <!-- Styles -->
  <link rel="stylesheet" href="/dashboard.css" />
  <style>
    /* ── Widget strip ── */
    .widget-strip {
      display:grid;
      grid-template-columns: repeat(3, 1fr);
      grid-template-rows: auto auto;
      gap:10px; padding:10px 14px;
      background:#090d14; border-bottom:1px solid #1c2434;
      align-items:start;
    }

    /* Threat level */
    .threat-card {
      display:flex; flex-direction:column; align-items:center; justify-content:center;
      padding:8px 18px; border-radius:8px; border:2px solid; min-width:110px;
      cursor:default; transition:filter .2s;
    }
    .threat-label { font-size:9px; text-transform:uppercase; letter-spacing:.1em; opacity:.7; margin-bottom:4px; }
    .threat-level { font-size:18px; font-weight:800; letter-spacing:.05em; }
    .threat-sub   { font-size:10px; opacity:.65; margin-top:3px; }
    .threat-green  { background:#061a09; border-color:#1a4020; color:#7ecb7e; }
    .threat-yellow { background:#1a1500; border-color:#3a2f00; color:#ffd66e; }
    .threat-orange { background:#1a0e00; border-color:#4a2800; color:#ffb060; }
    .threat-red    { background:#1a0505; border-color:#5c1010; color:#ff6b6b; }


    /* Stat comparison cards */
    .stat-card {
      background:#0f1521; border:1px solid #1c2434; border-radius:8px;
      padding:10px 14px; display:flex; flex-direction:column; justify-content:center;
    }
    .stat-title { font-size:10px; color:#4a6a8a; text-transform:uppercase;
                  letter-spacing:.07em; margin-bottom:5px; }
    .stat-row   { display:flex; align-items:baseline; gap:10px; }
    .stat-today { font-size:22px; font-weight:700; color:#c8dff5; }
    .stat-delta { font-size:12px; font-weight:600; }
    .stat-delta.up   { color:#ff9a9a; }   /* more alerts = bad */
    .stat-delta.down { color:#7ecb7e; }   /* fewer alerts = good */
    .stat-delta.msg-up   { color:#7ecb7e; }  /* more messages = good (more coverage) */
    .stat-delta.msg-down { color:#ffd66e; }
    .stat-delta.neutral  { color:#6a8aaa; }
    .stat-yest  { font-size:11px; color:#4a6a8a; margin-top:3px; }

    /* Backlog + Rules pills */
    .pill-stack {
      display:flex; flex-direction:column; gap:7px; justify-content:center;
    }
    .info-pill {
      display:flex; align-items:center; gap:8px; padding:6px 12px;
      border-radius:6px; border:1px solid; white-space:nowrap; font-size:12px;
    }
    .info-pill .pill-icon  { font-size:14px; }
    .info-pill .pill-label { color:#6a8aaa; font-size:10px; text-transform:uppercase; letter-spacing:.05em; }
    .info-pill .pill-val   { font-weight:700; font-size:14px; margin-left:auto; }
    .pill-backlog { background:#1a0808; border-color:#3a1010; color:#ff9a9a; }
    .pill-backlog .pill-val { color:#ff6b6b; }
    .pill-rules   { background:#0a1020; border-color:#1a2a40; color:#9aa8bd; }
    .pill-rules   .pill-val { color:#6ea8fe; }

    /* Top IPs mini table */
    .mini-card {
      background:#0f1521; border:1px solid #1c2434; border-radius:8px;
      padding:10px 12px; min-width:180px;
    }
    .mini-title { font-size:10px; color:#4a6a8a; text-transform:uppercase;
                  letter-spacing:.07em; margin-bottom:7px; }
    .mini-row   { display:flex; justify-content:space-between; align-items:center;
                  padding:2px 0; font-size:12px; border-bottom:1px solid #1c2434; }
    .mini-row:last-child { border-bottom:none; }
    .mini-ip    { color:#b8c7dc; font-family:monospace; font-size:11px; }
    .mini-count { font-weight:700; color:#f7b267; font-size:12px; }
    .mini-empty { color:#4a6a8a; font-size:11px; font-style:italic; }


    /* ── Severity tri-widget ── */
    .sev-card {
      background:#0f1521; border:1px solid #1c2434; border-radius:8px;
      padding:10px 14px; display:flex; flex-direction:column;
    }
    .sev-card-title {
      font-size:10px; color:#4a6a8a; text-transform:uppercase;
      letter-spacing:.07em; margin-bottom:8px;
    }
    .sev-segments {
      display:grid; grid-template-columns:1fr 1fr 1fr; gap:6px;
    }
    .sev-seg {
      display:flex; flex-direction:column; align-items:center; justify-content:center;
      border-radius:6px; padding:10px 4px; min-height:68px;
      cursor:pointer; text-decoration:none;
      border:2px solid; transition:filter .15s, transform .1s;
    }
    .sev-seg:hover { filter:brightness(1.3); transform:translateY(-1px); }
    .sev-seg-icon  { font-size:18px; margin-bottom:5px; line-height:1; }
    .sev-seg-val   { font-size:24px; font-weight:900; line-height:1; }
    .sev-seg-label { font-size:9px; text-transform:uppercase; letter-spacing:.08em;
                     margin-top:4px; opacity:.85; }
    /* Critical — vivid red */
    .sev-critical { background:#2a0808; border-color:#8b1a1a; color:#ff6b6b; }
    /* Error / High — coral */
    .sev-high     { background:#241008; border-color:#7a3010; color:#ff9060; }
    /* Warning / Mid — amber */
    .sev-mid      { background:#1e1400; border-color:#7a5500; color:#ffc040; }
  </style>
</head>
<body>
  <!-- Top Nav -->
  <nav class="top-nav">
    <a href="/" class="active">Dashboard</a>
    <a href="/correlation.html">Correlation Rules</a>
    <a href="/artifacts.html">Artifacts</a>
    <a href="/alerts.html">Alerts</a>
    <a href="/logs.html">Logs</a>
    <a href="/reports.html">Reports</a>
    <a href="/clients.html">Clients</a>
    <a href="/users.html">Users</a>
    <a href="/settings.html">Settings</a>

    <button id="reloadRulesBtn" class="btn small">Reload Rules</button>

    <!-- Notification Bell -->
    <div class="noti-wrap">
      <button id="notiBell" class="bell" aria-label="Notifications">
        <span class="bell-icon">🔔</span>
        <span id="notiBadge" class="badge">0</span>
      </button>
      <div id="notiMenu" class="dropdown hidden" role="menu" aria-hidden="true">
        <div class="dropdown-header">Notifications</div>
        <div id="notiList" class="dropdown-list"></div>
      </div>
    </div>

    <!-- EPS ticket -->
    <div class="eps-card" id="epsCard" aria-label="Event Rate (EPS)">EPS: --</div>
  </nav>

  <!-- Alert Ribbon -->
  <section id="alertRibbon" class="alert-ribbon"></section>

  <!-- ── Widget Strip — 3 × 2 grid ── -->
  <div class="widget-strip" id="widgetStrip">

    <!-- 1. Threat Level -->
    <div class="threat-card threat-green" id="threatCard">
      <div class="threat-label">Threat Level</div>
      <div class="threat-level" id="threatLevel">—</div>
      <div class="threat-sub"  id="threatSub">loading…</div>
    </div>

    <!-- 2. Alerts today vs yesterday -->
    <div class="stat-card">
      <div class="stat-title">Alerts Today</div>
      <div class="stat-row">
        <span class="stat-today" id="wAlertToday">—</span>
        <span class="stat-delta" id="wAlertDelta"></span>
      </div>
      <div class="stat-yest" id="wAlertYest"></div>
    </div>

    <!-- 3. Messages today vs yesterday -->
    <div class="stat-card">
      <div class="stat-title">Messages Today</div>
      <div class="stat-row">
        <span class="stat-today" id="wMsgToday">—</span>
        <span class="stat-delta" id="wMsgDelta"></span>
      </div>
      <div class="stat-yest" id="wMsgYest"></div>
    </div>

    <!-- 4. Backlog + Rules pills -->
    <div class="pill-stack">
      <div class="info-pill pill-backlog">
        <span class="pill-icon">⏳</span>
        <span class="pill-label">Ack Backlog</span>
        <span class="pill-val" id="wBacklog">—</span>
      </div>
      <div class="info-pill pill-rules">
        <span class="pill-icon">⚡</span>
        <span class="pill-label">Rules Active</span>
        <span class="pill-val" id="wRules">—</span>
      </div>
    </div>

    <!-- 5. Top 5 IPs (1h) -->
    <div class="mini-card">
      <div class="mini-title">Top IPs — Last Hour</div>
      <div id="wTopIPs"><div class="mini-empty">No alerts in last hour</div></div>
    </div>

    <!-- 6. Severity breakdown — tri-segment widget -->
    <div class="sev-card">
      <div class="sev-card-title">Today's Alerts by Severity</div>
      <div class="sev-segments">

        <!-- Critical -->
        <a class="sev-seg sev-critical" href="/alerts.html?severity=critical" title="View critical alerts">
          <span class="sev-seg-icon">🔴</span>
          <span class="sev-seg-val"  id="wSevCritical">—</span>
          <span class="sev-seg-label">Critical</span>
        </a>

        <!-- High / Error -->
        <a class="sev-seg sev-high" href="/alerts.html?severity=high" title="View high severity alerts">
          <span class="sev-seg-icon">🟠</span>
          <span class="sev-seg-val"  id="wSevHigh">—</span>
          <span class="sev-seg-label">Error</span>
        </a>

        <!-- Mid / Warning -->
        <a class="sev-seg sev-mid" href="/alerts.html?severity=mid" title="View medium severity alerts">
          <span class="sev-seg-icon">🟡</span>
          <span class="sev-seg-val"  id="wSevMid">—</span>
          <span class="sev-seg-label">Warning</span>
        </a>

      </div>
    </div>

  </div><!-- /.widget-strip -->

  <!-- Search Bar -->
  <section class="search-bar">
    <input id="logQuery" placeholder="Search logs… (message, IP, device, process)">
    <button id="searchBtn">Search</button>
  </section>

  <!-- Terminal directly under the search bar -->
  <section class="main-grid">
    <section class="terminal">
      <header>Live Logs</header>
      <pre id="liveLogs" class="console" aria-live="polite"></pre>
    </section>

    <!-- Right column: client health -->
    <aside class="side-panel">
      <header>Client Health</header>
      <div id="clientCards"></div>
    </aside>
  </section>

  <!-- Charts under the terminal -->
  <section class="charts-grid">
    <div class="chart-card">
      <div class="chart-title">Alerts by Severity (24h)</div>
      <canvas id="chartAlertsSeverity"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">Messages per Hour (24h)</div>
      <canvas id="chartMsgsPerHour"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">Correlation Hits by Use Case (7d)</div>
      <canvas id="chartCorrelationCases"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">Top Attacked Systems (7d)</div>
      <canvas id="chartTopIPs"></canvas>
    </div>
    <div class="chart-card">
      <div class="chart-title">Artifact Alerts by Severity (7d)</div>
      <canvas id="chartArtifactsSeverity"></canvas>
    </div>
  </section>

  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="/app.js"></script>
</body>
</html>
