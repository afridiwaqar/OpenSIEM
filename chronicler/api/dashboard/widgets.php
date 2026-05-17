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

function sq($db, $sql, $p = []) {
    try {
        $st = $db->prepare($sql); $st->execute($p);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) { error_log('widgets: '.$e->getMessage()); return []; }
}
function sq1($db, $sql, $p = []) { $r = sq($db,$sql,$p); return $r[0] ?? []; }

// Active (unacknowledged) alerts right now
$thr = sq1($db, "
    SELECT
        COUNT(*) FILTER (WHERE severity='critical')::int AS critical,
        COUNT(*) FILTER (WHERE severity='high')::int     AS high,
        COUNT(*) FILTER (WHERE severity='mid')::int      AS mid,
        COUNT(*) FILTER (WHERE severity='low')::int      AS low,
        COUNT(*)::int                                    AS total
    FROM alerts WHERE is_active = true
");

$sevToday = sq1($db, "
    SELECT
        COUNT(*) FILTER (WHERE severity='critical')::int AS critical,
        COUNT(*) FILTER (WHERE severity='high')::int     AS high,
        COUNT(*) FILTER (WHERE severity='mid')::int      AS mid,
        COUNT(*) FILTER (WHERE severity='low')::int      AS low
    FROM alerts
    WHERE is_active = true
       OR id IN (
           SELECT DISTINCT alert_id_fk
           FROM alert_occurrences
           WHERE occurred_at >= CURRENT_DATE
       )
");

$level = 'green';
if     (($thr['critical'] ?? 0) > 0) $level = 'red';
elseif (($thr['high']     ?? 0) > 0) $level = 'orange';
elseif (($thr['mid']      ?? 0) > 5) $level = 'yellow';

$today = sq1($db, "
    SELECT COUNT(*)::int AS c FROM alert_occurrences
    WHERE occurred_at >= CURRENT_DATE
");
$yesterday = sq1($db, "
    SELECT COUNT(*)::int AS c FROM alert_occurrences
    WHERE occurred_at >= CURRENT_DATE - INTERVAL '1 day'
      AND occurred_at  < CURRENT_DATE
");
$todayMsgs = sq1($db, "
    SELECT COUNT(*)::int AS c FROM message m
    JOIN calendar c ON c.data_id = m.date
    WHERE (c.date + c.\"time\") >= CURRENT_DATE
");
$yestMsgs = sq1($db, "
    SELECT COUNT(*)::int AS c FROM message m
    JOIN calendar c ON c.data_id = m.date
    WHERE (c.date + c.\"time\") >= CURRENT_DATE - INTERVAL '1 day'
      AND (c.date + c.\"time\")  < CURRENT_DATE
");

$backlog = sq1($db, "
    SELECT COUNT(*)::int AS c
    FROM alerts a
    WHERE a.is_active = true
      AND (SELECT MIN(ao.occurred_at) FROM alert_occurrences ao
           WHERE ao.alert_id_fk = a.id) < NOW() - INTERVAL '2 hours'
");

$rulesTotal = sq1($db, "SELECT COUNT(*)::int AS c FROM use_cases");
$rulesFired = sq1($db, "
    SELECT COUNT(DISTINCT
        COALESCE(NULLIF(regexp_replace(a.admin_note,
            '.*\"case_name\":\"([^\"]+)\".*','\\1'), a.admin_note), 'UNKNOWN')
    )::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE a.alert_type = 'correlation'
      AND ao.occurred_at >= NOW() - INTERVAL '24 hours'
");

$topIPs1h = sq($db, "
    SELECT COALESCE(a.source_ip::text,'unknown') AS ip,
           COUNT(*)::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE ao.occurred_at >= NOW() - INTERVAL '1 hour'
    GROUP BY ip ORDER BY c DESC LIMIT 5
");

json_out([
    'ok'           => true,
    'threat_level' => $level,
    'threat_counts'=> $thr,          // active alerts only (for threat level card)
    'sev_today'    => $sevToday,     // all alerts today (for severity tri-widget)
    'today_alerts' => (int)($today['c']     ?? 0),
    'yest_alerts'  => (int)($yesterday['c'] ?? 0),
    'today_msgs'   => (int)($todayMsgs['c'] ?? 0),
    'yest_msgs'    => (int)($yestMsgs['c']  ?? 0),
    'backlog'      => (int)($backlog['c']   ?? 0),
    'rules_total'  => (int)($rulesTotal['c'] ?? 0),
    'rules_fired'  => (int)($rulesFired['c'] ?? 0),
    'top_ips_1h'   => $topIPs1h,
]);
