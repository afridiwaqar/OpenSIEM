<?php
// /var/www/chronicler/api/alerts/get_alerts.php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('read');

header('Content-Type: application/json');

$db       = pdo();
$severity = $_GET['severity'] ?? '';
$type     = $_GET['type']     ?? '';
$active   = $_GET['active']   ?? '';
$hours    = (int)($_GET['hours']    ?? 0);
$status   = $_GET['status']   ?? '';
$search   = trim($_GET['search']   ?? '');
$page     = max(1, (int)($_GET['page']     ?? 1));
$per_page = min(250, max(10, (int)($_GET['per_page'] ?? 50)));
$offset   = ($page - 1) * $per_page;

$where  = ['1=1'];
$params = [];

if ($severity) {
    $where[]  = 'a.severity = ?';
    $params[] = $severity;
}
if ($type) {
    $where[]  = 'a.alert_type = ?';
    $params[] = $type;
}
if ($active !== '') {
    $where[]  = 'a.is_active = ?';
    $params[] = $active === 'true' ? 'true' : 'false';
}
if ($hours > 0) {
    $where[]  = "a.acknowledged_time >= now() - interval '{$hours} hours'
                 OR (a.acknowledged_time IS NULL)";
}
if ($status) {
    $where[]  = 'a.status = ?';
    $params[] = $status;
}
if ($search) {
    $where[]  = "(a.source_ip::text ILIKE ? OR a.admin_note ILIKE ?)";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
}

$where_sql = implode(' AND ', $where);

try {
    // Total count
    $count_stmt = $db->prepare(
        "SELECT COUNT(*) FROM alerts a WHERE {$where_sql}"
    );
    $count_stmt->execute($params);
    $total = (int)$count_stmt->fetchColumn();

    // Fetch page
    $stmt = $db->prepare(
        "SELECT
            a.id, a.alert_id, a.alert_type, a.severity,
            a.is_active, a.count, a.source_ip, a.admin_note,
            a.status, a.assigned_to, a.assigned_at,
            a.acknowledged_time, a.resolved_at,
            l.username AS assigned_username
         FROM alerts a
         LEFT JOIN login l ON l.user_id = a.assigned_to
         WHERE {$where_sql}
         ORDER BY
             CASE WHEN a.status IN ('open','investigating') THEN 0 ELSE 1 END,
             a.id DESC
         LIMIT {$per_page} OFFSET {$offset}"
    );
    $stmt->execute($params);
    $alerts = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'ok'          => true,
        'alerts'      => $alerts,
        'total'       => $total,
        'page'        => $page,
        'per_page'    => $per_page,
        'total_pages' => (int)ceil($total / $per_page),
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
