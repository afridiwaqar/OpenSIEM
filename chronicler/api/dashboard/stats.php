<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
require_login();
require_perm('read');

$db = pdo();

function safe_query($db, $sql, $params = []) {
  try {
    $st = $db->prepare($sql);
    $st->execute($params);
    return $st->fetchAll(PDO::FETCH_ASSOC);
  } catch (Throwable $e) {
    // Log server-side and return empty
    error_log("dashboard/stats query failed: ".$e->getMessage());
    return [];
  }
}

// Alerts by severity (24h) via occurrences (preferred)
$alertsBySeverity = [];
$rows = safe_query($db, "
  SELECT a.severity, COUNT(*)::int AS c
  FROM alert_occurrences ao
  JOIN alerts a ON a.id = ao.alert_id_fk
  WHERE ao.occurred_at >= NOW() - INTERVAL '24 hours'
  GROUP BY a.severity
");
foreach ($rows as $r) $alertsBySeverity[$r['severity']] = (int)$r['c'];

// Fallback: if occurrences empty, use alerts table (approximate, active only)
if (!$alertsBySeverity) {
  $rows = safe_query($db, "
    SELECT severity, COUNT(*)::int AS c
    FROM alerts
    WHERE is_active = true
    GROUP BY severity
  ");
  foreach ($rows as $r) $alertsBySeverity[$r['severity']] = (int)$r['c'];
}

// Alerts per hour (24h) via occurrences
$alertsPerHour = safe_query($db, "
  SELECT to_char(date_trunc('hour', ao.occurred_at), 'YYYY-MM-DD HH24:00') AS h, COUNT(*)::int AS c
  FROM alert_occurrences ao
  WHERE ao.occurred_at >= NOW() - INTERVAL '24 hours'
  GROUP BY 1 ORDER BY 1
");

// Messages per hour (24h) from message + calendar
$messagesPerHour = safe_query($db, "
  SELECT to_char(date_trunc('hour', (c.date + c.\"time\")), 'YYYY-MM-DD HH24:00') AS h, COUNT(*)::int AS c
  FROM message m
  JOIN calendar c ON c.data_id = m.date
  WHERE (c.date + c.\"time\") >= NOW() - INTERVAL '24 hours'
  GROUP BY 1 ORDER BY 1
");

// Correlation hits by case (7d)
$correlationByCase = safe_query($db, "
  SELECT COALESCE(NULLIF(regexp_replace(a.admin_note, '.*\"case_name\":\"([^\"]+)\".*', '\\1'), a.admin_note), 'UNKNOWN') AS case_name,
         COUNT(*)::int AS c
  FROM alert_occurrences ao
  JOIN alerts a ON a.id = ao.alert_id_fk
  WHERE a.alert_type = 'correlation'
    AND ao.occurred_at >= NOW() - INTERVAL '7 days'
  GROUP BY 1
  ORDER BY c DESC
  LIMIT 12
");

// Top attacked systems by IP (7d)
$topIPs = safe_query($db, "
  SELECT COALESCE(a.source_ip::text, 'unknown') AS ip, COUNT(*)::int AS c
  FROM alert_occurrences ao
  JOIN alerts a ON a.id = ao.alert_id_fk
  WHERE ao.occurred_at >= NOW() - INTERVAL '7 days'
  GROUP BY ip
  ORDER BY c DESC
  LIMIT 12
");

// Artifact alerts by severity (7d)
$artifactBySeverity = [];
$rows = safe_query($db, "
  SELECT a.severity, COUNT(*)::int AS c
  FROM alert_occurrences ao
  JOIN alerts a ON a.id = ao.alert_id_fk
  WHERE a.alert_type = 'artifact'
    AND ao.occurred_at >= NOW() - INTERVAL '7 days'
  GROUP BY a.severity
");
foreach ($rows as $r) $artifactBySeverity[$r['severity']] = (int)$r['c'];

json_out([
  'ok' => true,
  'alertsBySeverity24h' => $alertsBySeverity,
  'alertsPerHour24h'    => $alertsPerHour,
  'messagesPerHour24h'  => $messagesPerHour,
  'correlationByCase7d' => $correlationByCase,
  'topIPs7d'            => $topIPs,
  'artifactBySeverity7d'=> $artifactBySeverity
]);
