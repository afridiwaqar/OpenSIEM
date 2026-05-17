<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_GET['action'] ?? '';

try {
$db = pdo();

    switch ($action) {

        // ── Start a rehydration ────────────────────────────────────────────
        case 'start':
            require_perm('archive_role', ['operator','administrator']);

            $date_from       = $body['date_from']       ?? '';
            $date_to         = $body['date_to']         ?? '';
            $tables          = $body['tables']          ?? ['messages'];
            $auto_release_days = (int)($body['auto_release_days'] ?? 7);

            if (!$date_from || !$date_to) {
                http_response_code(400);
                echo json_encode(['ok' => false,
                                  'error' => 'date_from and date_to required']);
                exit;
            }

            $d_from = DateTime::createFromFormat('Y-m-d', $date_from);
            $d_to   = DateTime::createFromFormat('Y-m-d', $date_to);
            if (!$d_from || !$d_to || $d_from > $d_to) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'Invalid date range']);
                exit;
            }

            $existing = $db->prepare(
                "SELECT id FROM archive_rehydration
                 WHERE state = 'active'
                   AND date_from <= ? AND date_to >= ?"
            );
            $existing->execute([$date_to, $date_from]);
            if ($existing->fetch()) {
                http_response_code(409);
                echo json_encode(['ok'    => false,
                                  'error' => 'An active rehydration already overlaps this date range']);
                exit;
            }

            $auto_release_at = (new DateTime())
                ->modify("+{$auto_release_days} days")
                ->format('Y-m-d H:i:s');

            $stmt = $db->prepare(
                "INSERT INTO archive_rehydration
                 (date_from, date_to, tables, state, started_by, auto_release_at)
                 VALUES (?, ?, ?, 'pending', ?, ?)
                 RETURNING id"
            );
            $stmt->execute([
                $date_from, $date_to,
                '{' . implode(',', array_map('addslashes', $tables)) . '}',
                $_SESSION['username'] ?? 'unknown',
                $auto_release_at,
            ]);
            $job_id = $stmt->fetchColumn();

            $db->prepare(
                "INSERT INTO archive_audit_log
                 (action, performed_by, detail)
                 VALUES ('rehydration_started', ?, ?)"
            )->execute([
                $_SESSION['username'] ?? 'unknown',
                json_encode(['job_id' => $job_id, 'date_from' => $date_from,
                             'date_to' => $date_to, 'tables' => $tables]),
            ]);

            $result = _run_rehydration($job_id);
            echo json_encode($result);
            break;

        // ── Estimate size before rehydrating ──────────────────────────────
        case 'estimate':
            require_perm('archive_role', ['operator','administrator']);

            $date_from = $body['date_from'] ?? '';
            $date_to   = $body['date_to']   ?? '';
            $tables    = $body['tables']    ?? ['messages'];

            $placeholders = implode(',', array_fill(0, count($tables), '?'));
            $params = array_merge([$date_from, $date_to], $tables);

            $stmt = $db->prepare(
                "SELECT
                     SUM(row_count)       AS total_rows,
                     SUM(file_size_bytes) AS total_bytes,
                     COUNT(*)             AS partitions
                 FROM archive_manifest
                 WHERE partition_date BETWEEN ? AND ?
                   AND table_name IN ({$placeholders})
                   AND state IN ('verified','deleted_from_hot')"
            );
            $stmt->execute($params);
            $est = $stmt->fetch(PDO::FETCH_ASSOC);

            $bytes        = (int)($est['total_bytes'] ?? 0);
            $rows         = (int)($est['total_rows']  ?? 0);
            $partitions   = (int)($est['partitions']  ?? 0);
            $est_minutes  = max(1, round($bytes / (1024 * 1024 * 50)));

            echo json_encode([
                'ok'              => true,
                'total_rows'      => $rows,
                'total_bytes'     => $bytes,
                'total_gb'        => round($bytes / (1024**3), 2),
                'partitions'      => $partitions,
                'est_minutes_min' => $est_minutes,
                'est_minutes_max' => $est_minutes + 2,
            ]);
            break;

        // ── List active and recent rehydrations ────────────────────────────
        case 'list':
            require_perm('archive_role', ['viewer','operator','administrator']);

            $rows = $db->query(
                "SELECT id, date_from, date_to, tables, state,
                        rows_imported, started_by, auto_release_at,
                        created_at, completed_at, released_at, error_msg
                 FROM archive_rehydration
                 ORDER BY created_at DESC
                 LIMIT 50"
            )->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode(['ok' => true, 'rehydrations' => $rows]);
            break;

        // ── Release a rehydration early ────────────────────────────────────
        case 'release':
            require_perm('archive_role', ['operator','administrator']);

            $job_id = (int)($body['id'] ?? 0);
            if (!$job_id) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'id required']);
                exit;
            }

            $job = $db->prepare(
                "SELECT * FROM archive_rehydration WHERE id = ? AND state = 'active'"
            );
            $job->execute([$job_id]);
            $row = $job->fetch(PDO::FETCH_ASSOC);

            if (!$row) {
                http_response_code(404);
                echo json_encode(['ok' => false,
                                  'error' => 'Active rehydration not found']);
                exit;
            }

            $db->prepare(
                "UPDATE archive_rehydration
                 SET state = 'releasing', released_at = now() WHERE id = ?"
            )->execute([$job_id]);

            $result = _run_release($job_id, $row);

            $db->prepare(
                "INSERT INTO archive_audit_log
                 (action, performed_by, detail)
                 VALUES ('rehydration_released', ?, ?)"
            )->execute([
                $_SESSION['username'] ?? 'unknown',
                json_encode(['job_id' => $job_id]),
            ]);

            echo json_encode($result);
            break;

        default:
            http_response_code(400);
            echo json_encode(['ok' => false,
                              'error' => "Unknown action: {$action}"]);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}


function _run_rehydration(int $job_id): array {
    $script = '/opt/opensiem/run_rehydrate.py';
    $cmd    = "python3 " . escapeshellarg($script) .
              " --job " . (int)$job_id . " 2>&1";
    $output = shell_exec($cmd);
    $result = json_decode($output, true);
    if (!$result) {
        return ['ok' => false, 'error' => 'Rehydration script failed', 'raw' => $output];
    }
    return $result;
}


function _run_release(int $job_id, array $row): array {
    $script = '/opt/opensiem/run_rehydrate.py';
    $cmd    = "python3 " . escapeshellarg($script) .
              " --release " . (int)$job_id . " 2>&1";
    $output = shell_exec($cmd);
    $result = json_decode($output, true);
    if (!$result) {
        return ['ok' => false, 'error' => 'Release script failed', 'raw' => $output];
    }
    return $result;
}
