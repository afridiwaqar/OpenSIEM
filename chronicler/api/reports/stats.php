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

$db      = pdo();
$hours   = max(1, min(720, (int)($_GET['hours'] ?? 168))); // default 7d, max 30d
$interval = $hours . ' hours';

function sq($db, $sql, $params = []) {
    try {
        $st = $db->prepare($sql);
        $st->execute($params);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        error_log('reports/stats: ' . $e->getMessage());
        return [];
    }
}
function sq1($db, $sql, $params = []) {
    $r = sq($db, $sql, $params);
    return $r[0] ?? [];
}

$kpi = sq1($db, "
    SELECT
        COUNT(*)::int                                              AS total_alerts,
        COUNT(*) FILTER (WHERE is_active  = true)::int            AS active_alerts,
        COUNT(*) FILTER (WHERE is_active  = false)::int           AS acked_alerts,
        COUNT(*) FILTER (WHERE severity   = 'critical')::int      AS critical_count,
        COUNT(*) FILTER (WHERE severity   = 'high')::int          AS high_count,
        COUNT(*) FILTER (WHERE severity   = 'mid')::int           AS mid_count,
        COUNT(*) FILTER (WHERE severity   = 'low')::int           AS low_count,
        COUNT(*) FILTER (WHERE alert_type = 'correlation')::int   AS correlation_count,
        COUNT(*) FILTER (WHERE alert_type = 'artifact')::int      AS artifact_count
    FROM alerts
");

$bucket = $hours <= 48  ? '1 hour'
        : ($hours <= 168 ? '6 hours' : '1 day');

$alertVolume = sq($db, "
    SELECT
        to_char(date_trunc(:b, ao.occurred_at), 'YYYY-MM-DD HH24:MI') AS ts,
        COUNT(*)::int AS c
    FROM alert_occurrences ao
    WHERE ao.occurred_at >= NOW() - INTERVAL '$interval'
    GROUP BY 1
    ORDER BY 1
", [':b' => $bucket]);

$alertsBySev = [];
foreach (sq($db, "
    SELECT a.severity, COUNT(*)::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE ao.occurred_at >= NOW() - INTERVAL '$interval'
    GROUP BY a.severity
") as $r) $alertsBySev[$r['severity']] = (int)$r['c'];

$msgVolume = sq($db, "
    SELECT
        to_char(date_trunc(:b, (c.date + c.\"time\")), 'YYYY-MM-DD HH24:MI') AS ts,
        COUNT(*)::int AS c
    FROM message m
    JOIN calendar c ON c.data_id = m.date
    WHERE (c.date + c.\"time\") >= NOW() - INTERVAL '$interval'
    GROUP BY 1
    ORDER BY 1
", [':b' => $bucket]);

$msgKpi = sq1($db, "
    SELECT COUNT(*)::int AS total_messages
    FROM message m
    JOIN calendar c ON c.data_id = m.date
    WHERE (c.date + c.\"time\") >= NOW() - INTERVAL '$interval'
");

$topIPs = sq($db, "
    SELECT COALESCE(a.source_ip::text,'unknown') AS ip, COUNT(*)::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE ao.occurred_at >= NOW() - INTERVAL '$interval'
    GROUP BY ip ORDER BY c DESC LIMIT 10
");

$correlationByCase = sq($db, "
    SELECT
        COALESCE(NULLIF(regexp_replace(a.admin_note,
            '.*\"case_name\":\"([^\"]+)\".*','\\1'), a.admin_note), 'UNKNOWN') AS case_name,
        COUNT(*)::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE a.alert_type = 'correlation'
      AND ao.occurred_at >= NOW() - INTERVAL '$interval'
    GROUP BY 1 ORDER BY c DESC LIMIT 12
");

$artifactBySev = [];
foreach (sq($db, "
    SELECT a.severity, COUNT(*)::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE a.alert_type = 'artifact'
      AND ao.occurred_at >= NOW() - INTERVAL '$interval'
    GROUP BY a.severity
") as $r) $artifactBySev[$r['severity']] = (int)$r['c'];

$unackedCritical = sq($db, "
    SELECT id, alert_id, alert_type, source_ip::text AS source_ip,
           count, admin_note,
           (SELECT MIN(ao.occurred_at) FROM alert_occurrences ao WHERE ao.alert_id_fk = a.id)
               AS first_seen,
           (SELECT MAX(ao.occurred_at) FROM alert_occurrences ao WHERE ao.alert_id_fk = a.id)
               AS last_seen
    FROM alerts a
    WHERE is_active = true AND severity IN ('critical','high')
    ORDER BY severity DESC, count DESC
    LIMIT 20
");

$mttaRow = sq1($db, "
    SELECT ROUND(AVG(
        EXTRACT(EPOCH FROM (a.acknowledged_time -
            (SELECT MIN(ao.occurred_at) FROM alert_occurrences ao WHERE ao.alert_id_fk = a.id)
        )) / 60
    ))::int AS mtta_minutes
    FROM alerts a
    WHERE a.is_active = false
      AND a.acknowledged_time IS NOT NULL
      AND a.acknowledged_time >= NOW() - INTERVAL '$interval'
");

$alertsByType = sq($db, "
    SELECT alert_type, COUNT(*)::int AS c
    FROM alerts
    GROUP BY alert_type
    ORDER BY c DESC
");

$topIOCs = sq($db, "
    SELECT
        COALESCE(NULLIF(regexp_replace(a.admin_note,
            '.*\"artifact\":\"([^\"]+)\".*','\\1'), a.admin_note), '—') AS artifact,
        a.severity,
        COUNT(*)::int AS c
    FROM alert_occurrences ao
    JOIN alerts a ON a.id = ao.alert_id_fk
    WHERE a.alert_type = 'artifact'
      AND ao.occurred_at >= NOW() - INTERVAL '$interval'
    GROUP BY artifact, a.severity
    ORDER BY c DESC
    LIMIT 10
");

json_out([
    'ok'              => true,
    'period_hours'    => $hours,
    'generated_at'    => date('c'),
    'kpi'             => $kpi,
    'msg_kpi'         => $msgKpi,
    'mtta_minutes'    => (int)($mttaRow['mtta_minutes'] ?? 0),
    'alert_volume'    => $alertVolume,
    'msg_volume'      => $msgVolume,
    'alerts_by_sev'   => $alertsBySev,
    'alerts_by_type'  => $alertsByType,
    'top_ips'         => $topIPs,
    'correlation'     => $correlationByCase,
    'artifact_by_sev' => $artifactBySev,
    'top_iocs'        => $topIOCs,
    'unacked_critical'=> $unackedCritical,
]);
