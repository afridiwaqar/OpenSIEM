<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['viewer', 'operator', 'administrator']);

header('Content-Type: application/json');

// Hard timeout — return partial data rather than a 504
set_time_limit(15);

$debug   = [];
$t_start = microtime(true);

function elapsed() {
    global $t_start;
    return round((microtime(true) - $t_start) * 1000) . 'ms';
}

function safe_query($db, $label, $sql, $mode = 'fetch') {
    global $debug;
    $t0 = microtime(true);
    try {
        $stmt = $db->query($sql);
        $result = ($mode === 'fetch')
            ? $stmt->fetch(PDO::FETCH_ASSOC)
            : (($mode === 'fetchAll')
                ? $stmt->fetchAll(PDO::FETCH_ASSOC)
                : $stmt->fetchColumn());
        $ms = round((microtime(true) - $t0) * 1000);
        $debug[] = "{$label}: {$ms}ms OK";
        return $result;
    } catch (Exception $e) {
        $ms = round((microtime(true) - $t0) * 1000);
        $debug[] = "{$label}: {$ms}ms ERROR: " . $e->getMessage();
        return null;
    }
}

try {
    $db = pdo();
    $debug[] = 'db_connect: ' . elapsed();

    $policy = safe_query($db, 'policy',
        "SELECT * FROM archive_policy WHERE id = 1");

    $storage = safe_query($db, 'storage',
        "SELECT id, name, backend_type, last_tested_at, last_test_ok, last_test_msg
         FROM archive_storage_config WHERE is_active = true LIMIT 1");

    $last_run = safe_query($db, 'last_run',
        "SELECT * FROM archive_audit_log
         WHERE action = 'archive_completed'
         ORDER BY occurred_at DESC LIMIT 1");

    $counts = safe_query($db, 'counts',
        "SELECT state, COUNT(*) as n, SUM(row_count) as rows,
                SUM(file_size_bytes) as bytes
         FROM archive_manifest
         GROUP BY state",
        'fetchAll');

    $state_map = [];
    foreach (($counts ?: []) as $c) {
        $state_map[$c['state']] = [
            'count' => (int)$c['n'],
            'rows'  => (int)$c['rows'],
            'bytes' => (int)$c['bytes'],
        ];
    }

    $total_bytes = safe_query($db, 'total_bytes',
        "SELECT COALESCE(SUM(file_size_bytes), 0) FROM archive_manifest
         WHERE state IN ('verified','deleted_from_hot')",
        'fetchColumn') ?? 0;

    $oldest = safe_query($db, 'oldest',
        "SELECT MIN(partition_date) FROM archive_manifest
         WHERE state IN ('verified','deleted_from_hot')",
        'fetchColumn');

    $newest = safe_query($db, 'newest',
        "SELECT MAX(partition_date) FROM archive_manifest
         WHERE state IN ('verified','deleted_from_hot')",
        'fetchColumn');

    $monthly_avg = safe_query($db, 'monthly_avg',
        "SELECT AVG(monthly) FROM (
             SELECT DATE_TRUNC('month', partition_date) as m,
                    SUM(file_size_bytes) as monthly
             FROM archive_manifest
             WHERE state IN ('verified','deleted_from_hot')
             GROUP BY m
             ORDER BY m DESC LIMIT 6
         ) t",
        'fetchColumn') ?? 0;

    $active_rehydrations = safe_query($db, 'rehydrations',
        "SELECT id, date_from, date_to, tables, state,
                rows_imported, auto_release_at, created_at
         FROM archive_rehydration
         WHERE state = 'active'
         ORDER BY created_at DESC",
        'fetchAll') ?? [];

    $storage_threshold_bytes =
        (($policy['storage_alert_threshold_gb'] ?? 100)) * 1024 * 1024 * 1024;

    $debug[] = 'total_elapsed: ' . elapsed();

    echo json_encode([
        'ok'      => true,
        'policy'  => $policy,
        'storage' => $storage,
        'archive' => [
            'total_bytes'       => (int)$total_bytes,
            'total_gb'          => round($total_bytes / (1024**3), 2),
            'oldest_date'       => $oldest,
            'newest_date'       => $newest,
            'monthly_avg_bytes' => (int)$monthly_avg,
            'states'            => $state_map,
            'over_threshold'    => (int)$total_bytes > $storage_threshold_bytes,
        ],
        'last_run'            => $last_run,
        'active_rehydrations' => $active_rehydrations,
        '_debug'              => $debug,
    ]);

} catch (Exception $e) {
    $debug[] = 'FATAL: ' . $e->getMessage();
    http_response_code(500);
    echo json_encode([
        'ok'     => false,
        'error'  => $e->getMessage(),
        '_debug' => $debug,
    ]);
}