<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['administrator']);

header('Content-Type: application/json');

$action     = $_GET['action']     ?? 'list';
$date_from  = $_GET['date_from']  ?? '';
$date_to    = $_GET['date_to']    ?? '';
$filter_action = $_GET['filter_action'] ?? '';
$page       = max(1, (int)($_GET['page'] ?? 1));
$per        = 50;
$offset     = ($page - 1) * $per;
$export_csv = isset($_GET['export_csv']);

try {
$db = pdo();

    $where  = ['1=1'];
    $params = [];

    if ($date_from) {
        $where[]  = 'occurred_at >= ?';
        $params[] = $date_from . ' 00:00:00';
    }
    if ($date_to) {
        $where[]  = 'occurred_at <= ?';
        $params[] = $date_to . ' 23:59:59';
    }
    if ($filter_action) {
        $where[]  = 'action = ?';
        $params[] = $filter_action;
    }

    $where_sql = implode(' AND ', $where);

    $total_stmt = $db->prepare(
        "SELECT COUNT(*) FROM archive_audit_log WHERE {$where_sql}"
    );
    $total_stmt->execute($params);
    $total = (int)$total_stmt->fetchColumn();

    $data_params = array_merge($params, [$per, $offset]);
    $data_stmt   = $db->prepare(
        "SELECT id, occurred_at, action, performed_by,
                partition_date, table_name, detail, success, error_msg
         FROM archive_audit_log
         WHERE {$where_sql}
         ORDER BY occurred_at DESC
         LIMIT ? OFFSET ?"
    );
    $data_stmt->execute($data_params);
    $rows = $data_stmt->fetchAll(PDO::FETCH_ASSOC);

    $distinct_actions = $db->query(
        "SELECT DISTINCT action FROM archive_audit_log ORDER BY action"
    )->fetchAll(PDO::FETCH_COLUMN);

    if ($export_csv) {
        $filename = 'opensiem_archive_audit.csv';
        header('Content-Type: text/csv');
        header("Content-Disposition: attachment; filename=\"{$filename}\"");
        $out = fopen('php://output', 'w');
        fputcsv($out, ['id','occurred_at','action','performed_by',
                       'partition_date','table_name','success','error_msg','detail']);
        foreach ($rows as $r) {
            fputcsv($out, [
                $r['id'], $r['occurred_at'], $r['action'], $r['performed_by'],
                $r['partition_date'], $r['table_name'], $r['success'] ? '1' : '0',
                $r['error_msg'], $r['detail'],
            ]);
        }
        fclose($out);
        exit;
    }

    echo json_encode([
        'ok'             => true,
        'total'          => $total,
        'page'           => $page,
        'pages'          => (int)ceil($total / $per),
        'rows'           => $rows,
        'distinct_actions' => $distinct_actions,
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
