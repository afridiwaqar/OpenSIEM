<?php
// /var/www/chronicler/api/logs/systems.php
//   GET                -> list of known systems for the dropdown
//   GET ?ip=<address>  -> detail strip for one system
// Systems come from watcher_health (every sender is recorded there). We never
// SELECT DISTINCT over the device table: it holds one row per log line.
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/_lib.php';

require_login();
require_perm('read');
header('Content-Type: application/json');

$db = pdo();
$ip = trim($_GET['ip'] ?? '');

try {
    $db->exec("SET statement_timeout = 10000");

    // open alerts per IP (host() strips the /32 that inet::text would add)
    $open = [];
    foreach ($db->query("SELECT host(source_ip) AS ip, COUNT(*) AS n FROM alerts
                          WHERE is_active = true AND source_ip IS NOT NULL
                          GROUP BY host(source_ip)")->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $open[$r['ip']] = (int)$r['n'];
    }

    // The hostname lookup uses idx_device_ip_id. Without that index it would scan the
    // whole device table once per system, so we only do it when the index exists.
    $has_idx = (bool)$db->query("SELECT to_regclass('public.idx_device_ip_id') IS NOT NULL")->fetchColumn();

    if ($ip === '') {
        $host_sql = $has_idx
            ? "LEFT JOIN LATERAL (SELECT NULLIF(NULLIF(d.device_name, ''), 'Unknown') AS host
                                    FROM device d WHERE d.device_ip = w.source_ip AND d.device_id > 0
                                   ORDER BY d.device_id DESC LIMIT 1) h ON true"
            : "LEFT JOIN LATERAL (SELECT NULL::text AS host) h ON true";
        $rows = $db->query("SELECT w.source_ip, w.client_name, w.is_online, w.last_heartbeat_at, h.host
                              FROM watcher_health w $host_sql
                             ORDER BY COALESCE(NULLIF(w.client_name, ''), h.host) NULLS LAST, w.source_ip")
                   ->fetchAll(PDO::FETCH_ASSOC);
        $systems = array_map(fn($r) => [
            'ip'          => $r['source_ip'],
            'name'        => $r['client_name'] ?: '',
            'host'        => $r['host'] ?: '',
            'online'      => (bool)$r['is_online'],
            'last_seen'   => $r['last_heartbeat_at'],
            'open_alerts' => $open[$r['source_ip']] ?? 0,
        ], $rows);
        echo json_encode(['ok' => true, 'systems' => $systems, 'host_lookup' => $has_idx]);
        exit;
    }

    // ---- detail for one system ----
    $w = $db->prepare("SELECT source_ip, client_name, is_online, last_heartbeat_at,
                              last_message_at, marked_offline_at
                         FROM watcher_health WHERE source_ip = :ip");
    $w->execute([':ip' => $ip]);
    $sys = $w->fetch(PDO::FETCH_ASSOC);

    // events in the last 5 minutes (bounded id range, so this stays cheap)
    $lo = $db->query('SELECT data_id FROM calendar
                       WHERE data_id > 0 AND (date + "time") >= (now()::timestamp - interval \'5 minutes\')
                       ORDER BY (date + "time") ASC LIMIT 1')->fetchColumn();
    $events5 = 0;
    if ($lo !== false && $lo !== null) {
        $c = $db->prepare('SELECT COUNT(*) FROM message m JOIN device d ON d.device_id = m.device_id
                            WHERE m.date >= ' . (int)$lo . ' AND d.device_ip = :ip');
        $c->execute([':ip' => $ip]);
        $events5 = (int)$c->fetchColumn();
    }

    $host = '';
    if ($has_idx) {
        $h = $db->prepare("SELECT NULLIF(NULLIF(device_name, ''), 'Unknown') FROM device
                            WHERE device_ip = :ip AND device_id > 0 ORDER BY device_id DESC LIMIT 1");
        $h->execute([':ip' => $ip]);
        $host = (string)($h->fetchColumn() ?: '');
    }

    $a = $db->prepare("SELECT id, severity, status, is_active, admin_note FROM alerts
                        WHERE host(source_ip) = :ip ORDER BY id DESC LIMIT 5");
    $a->execute([':ip' => $ip]);
    $alerts = array_map(function ($r) {
        $n = json_decode($r['admin_note'] ?? '', true);
        return ['id' => (int)$r['id'], 'severity' => $r['severity'], 'status' => $r['status'],
                'active' => (bool)$r['is_active'],
                'case_name' => is_array($n) ? ($n['case_name'] ?? '') : ''];
    }, $a->fetchAll(PDO::FETCH_ASSOC));

    echo json_encode(['ok' => true, 'system' => [
        'ip'          => $ip,
        'name'        => $sys['client_name'] ?? '',
        'host'        => $host,
        'known'       => (bool)$sys,
        'online'      => $sys ? (bool)$sys['is_online'] : null,
        'last_seen'   => $sys['last_heartbeat_at'] ?? null,
        'last_event'  => $sys['last_message_at'] ?? null,
        'events_5m'   => $events5,
        'open_alerts' => $open[$ip] ?? 0,
        'alerts'      => $alerts,
    ]]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
