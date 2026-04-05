<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../config/auth.php';
require_login();
require_perm('read');

$stmt = pdo()->prepare("
    SELECT
        MAX(id)                                          AS id,
        alert_type,
        source_ip::text                                  AS source_ip,
        SUM(COALESCE(count, 1))                          AS hit_count,
        -- pick the highest severity in the group
        CASE
            WHEN bool_or(severity = 'critical') THEN 'critical'
            WHEN bool_or(severity = 'high')     THEN 'high'
            WHEN bool_or(severity = 'mid')      THEN 'mid'
            ELSE 'low'
        END                                              AS severity,
        MAX(acknowledged_time)                           AS acknowledged_time,
        COUNT(*)                                         AS alert_count
    FROM alerts
    WHERE is_active = true
    GROUP BY source_ip, alert_type
    ORDER BY MAX(id) DESC
    LIMIT 20
");
$stmt->execute();
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($rows as &$r) {
    $r['id']          = (int)$r['id'];
    $r['hit_count']   = (int)$r['hit_count'];
    $r['alert_count'] = (int)$r['alert_count'];
}
unset($r);

json_out(['ok' => true, 'count' => count($rows), 'items' => $rows]);
