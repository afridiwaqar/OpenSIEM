<?php
// /var/www/chronicler/api/logs/live.php
// Live tail with full context (time, IP, host, process, source) on every line.
//   GET since=<message_id>   only rows newer than this id, oldest first
//       ip=<address>         restrict to one system (optional)
//       limit=<n>            default 100, max 500
// Returns rows oldest-first plus max_id: pass it back as `since` on the next poll.
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/_lib.php';

require_login();
require_perm('read');
header('Content-Type: application/json');

$db    = pdo();
$limit = min(500, max(1, (int)($_GET['limit'] ?? 100)));
$ip    = trim($_GET['ip'] ?? '');
$since = (isset($_GET['since']) && ctype_digit((string)$_GET['since'])) ? (int)$_GET['since'] : null;
if (strlen($ip) > 64) json_fail(400, 'Invalid ip');

try {
    $db->exec("SET statement_timeout = 10000");
    $params = [];

    if ($since !== null) {
        // Polling for new rows: the id range is tiny, so an IP filter here is cheap.
        $sql = LOG_SELECT . " WHERE m.message_id > $since AND m.date > 0";   // date > 0: skip restored-from-archive rows
        if ($ip !== '') { $sql .= ' AND d.device_ip = :ip'; $params[':ip'] = $ip; }
        $sql .= " ORDER BY m.message_id ASC LIMIT $limit";
        $asc = true;
    } elseif ($ip !== '') {
        // First load for one system: take that system's newest device rows via
        // idx_device_ip_id, then join to message. NOTE: this relies on the current
        // collector writing exactly one device row per log line. If device rows are
        // ever de-duplicated, switch this to a bounded message_id range instead.
        $sql = LOG_SELECT . " WHERE m.date > 0 AND m.device_id IN (SELECT device_id FROM device
                  WHERE device_ip = :ip AND device_id > 0 ORDER BY device_id DESC LIMIT $limit)
                  ORDER BY m.message_id DESC";
        $params[':ip'] = $ip;
        $asc = false;
    } else {
        $sql = LOG_SELECT . " WHERE m.date > 0 ORDER BY m.message_id DESC LIMIT $limit";
        $asc = false;
    }

    $st = $db->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    if (!$asc) $rows = array_reverse($rows);
    $rows = array_map('fmt_row', $rows);

    if ($rows) {
        $max_id = $rows[count($rows) - 1]['id'];
    } elseif ($since !== null) {
        $max_id = $since;
    } else {
        $max_id = (int)$db->query('SELECT COALESCE(MAX(message_id), 0) FROM message')->fetchColumn();
    }
    echo json_encode(['ok' => true, 'rows' => $rows, 'max_id' => $max_id]);

} catch (PDOException $e) {
    http_response_code($e->getCode() === '57014' ? 408 : 500);
    echo json_encode(['ok' => false, 'error' => $e->getCode() === '57014'
        ? 'Live view timed out. Try again.' : $e->getMessage()]);
}
