<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['viewer', 'operator', 'administrator']);

header('Content-Type: application/json');

try {
$db = pdo();

    $policy = $db->query("SELECT * FROM archive_policy WHERE id = 1")
                 ->fetch(PDO::FETCH_ASSOC);

    $storage = $db->query(
        "SELECT id, name, backend_type, last_tested_at, last_test_ok, last_test_msg
         FROM archive_storage_config WHERE is_active = true LIMIT 1"
    )->fetch(PDO::FETCH_ASSOC);

    $last_run = $db->query(
        "SELECT * FROM archive_audit_log
         WHERE action = 'archive_completed'
         ORDER BY occurred_at DESC LIMIT 1"
    )->fetch(PDO::FETCH_ASSOC);

    $counts = $db->query(
        "SELECT state, COUNT(*) as n, SUM(row_count) as rows,
                SUM(file_size_bytes) as bytes
         FROM archive_manifest
         GROUP BY state"
    )->fetchAll(PDO::FETCH_ASSOC);

    $state_map = [];
    foreach ($counts as $c) {
        $state_map[$c['state']] = [
            'count' => (int)$c['n'],
            'rows'  => (int)$c['rows'],
            'bytes' => (int)$c['bytes'],
        ];
    }

    $total_bytes = $db->query(
        "SELECT COALESCE(SUM(file_size_bytes), 0) FROM archive_manifest
         WHERE state IN ('verified','deleted_from_hot')"
    )->fetchColumn();

    $oldest = $db->query(
        "SELECT MIN(partition_date) FROM archive_manifest
         WHERE state IN ('verified','deleted_from_hot')"
    )->fetchColumn();

    $newest = $db->query(
        "SELECT MAX(partition_date) FROM archive_manifest
         WHERE state IN ('verified','deleted_from_hot')"
    )->fetchColumn();

    $monthly_avg = $db->query(
        "SELECT AVG(monthly) FROM (
             SELECT DATE_TRUNC('month', partition_date) as m,
                    SUM(file_size_bytes) as monthly
             FROM archive_manifest
             WHERE state IN ('verified','deleted_from_hot')
             GROUP BY m
             ORDER BY m DESC LIMIT 6
         ) t"
    )->fetchColumn();

    $active_rehydrations = $db->query(
        "SELECT id, date_from, date_to, tables, state,
                rows_imported, auto_release_at, created_at
         FROM archive_rehydration
         WHERE state = 'active'
         ORDER BY created_at DESC"
    )->fetchAll(PDO::FETCH_ASSOC);

    $storage_threshold_bytes =
        ($policy['storage_alert_threshold_gb'] ?? 100) * 1024 * 1024 * 1024;

    echo json_encode([
        'ok'      => true,
        'policy'  => $policy,
        'storage' => $storage,
        'archive' => [
            'total_bytes'   => (int)$total_bytes,
            'total_gb'      => round($total_bytes / (1024**3), 2),
            'oldest_date'   => $oldest,
            'newest_date'   => $newest,
            'monthly_avg_bytes' => (int)$monthly_avg,
            'states'        => $state_map,
            'over_threshold'=> (int)$total_bytes > $storage_threshold_bytes,
        ],
        'last_run'            => $last_run,
        'active_rehydrations' => $active_rehydrations,
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
