<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['operator','administrator']);

header('Content-Type: application/json');

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_GET['action'] ?? '';

try {
$db = pdo();

    switch ($action) {

        // ── Manual archive run ─────────────────────────────────────────────
        case 'run':
            require_perm('archive_role', ['administrator']);
            $target_date = $body['date'] ?? date('Y-m-d', strtotime('-1 day'));

            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $target_date)) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'Invalid date format']);
                exit;
            }

            $db->prepare(
                "INSERT INTO archive_audit_log (action, performed_by, partition_date, detail)
                 VALUES ('manual_archive_triggered', ?, ?, ?)"
            )->execute([
                $_SESSION['username'] ?? 'unknown',
                $target_date,
                json_encode(['requested_by' => $_SESSION['username'] ?? 'unknown']),
            ]);

            $result = _run_python_archiver($target_date);
            echo json_encode($result);
            break;

        // ── Verify integrity of one or all partitions ──────────────────────
        case 'verify':
            $manifest_id  = (int)($body['manifest_id'] ?? 0);
            $verify_all   = (bool)($body['all'] ?? false);

            if ($manifest_id) {
                $row = $db->prepare(
                    "SELECT id, file_path, sha256_hash, table_name, partition_date
                     FROM archive_manifest WHERE id = ?"
                );
                $row->execute([$manifest_id]);
                $partition = $row->fetch(PDO::FETCH_ASSOC);

                if (!$partition) {
                    http_response_code(404);
                    echo json_encode(['ok' => false, 'error' => 'Partition not found']);
                    exit;
                }

                $result = _verify_single($db, $partition);
                echo json_encode(['ok' => true, 'results' => [$result]]);

            } elseif ($verify_all) {
                require_perm('archive_role', ['administrator']);
                $rows = $db->query(
                    "SELECT id, file_path, sha256_hash, table_name, partition_date
                     FROM archive_manifest
                     WHERE state IN ('verified','deleted_from_hot')
                       AND sha256_hash IS NOT NULL
                     ORDER BY partition_date DESC"
                )->fetchAll(PDO::FETCH_ASSOC);

                $results = [];
                foreach ($rows as $partition) {
                    $results[] = _verify_single($db, $partition);
                }
                echo json_encode(['ok' => true, 'results' => $results,
                                  'total' => count($results)]);
            } else {
                http_response_code(400);
                echo json_encode(['ok' => false,
                                  'error' => 'Provide manifest_id or all=true']);
            }
            break;

        // ── List partitions with filters ───────────────────────────────────
        case 'list':
            require_perm('archive_role', ['viewer','operator','administrator']);

            $state      = $_GET['state']      ?? '';
            $date_from  = $_GET['date_from']  ?? '';
            $date_to    = $_GET['date_to']    ?? '';
            $table_name = $_GET['table_name'] ?? '';
            $page       = max(1, (int)($_GET['page'] ?? 1));
            $per        = 50;
            $offset     = ($page - 1) * $per;

            $where = ['1=1'];
            $params = [];

            if ($state) {
                $where[]  = 'state = ?';
                $params[] = $state;
            }
            if ($date_from) {
                $where[]  = 'partition_date >= ?';
                $params[] = $date_from;
            }
            if ($date_to) {
                $where[]  = 'partition_date <= ?';
                $params[] = $date_to;
            }
            if ($table_name) {
                $where[]  = 'table_name = ?';
                $params[] = $table_name;
            }

            $where_sql = implode(' AND ', $where);

            $count_stmt = $db->prepare(
                "SELECT COUNT(*) FROM archive_manifest WHERE {$where_sql}"
            );
            $count_stmt->execute($params);
            $total = (int)$count_stmt->fetchColumn();

            $data_stmt = $db->prepare(
                "SELECT id, partition_date, table_name, state, row_count,
                        file_size_bytes, sha256_hash, compression, encrypted,
                        frozen, partial, rows_exported, rows_total,
                        created_at, verified_at, deleted_at, error_msg
                 FROM archive_manifest
                 WHERE {$where_sql}
                 ORDER BY partition_date DESC, table_name
                 LIMIT {$per} OFFSET {$offset}"
            );
            $data_stmt->execute($params);
            $rows = $data_stmt->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode([
                'ok'       => true,
                'total'    => $total,
                'page'     => $page,
                'pages'    => (int)ceil($total / $per),
                'partitions' => $rows,
            ]);
            break;

        // ── Delete a failed partition entry ────────────────────────────────
        case 'delete_failed':
            require_perm('archive_role', ['administrator']);
            $manifest_id = (int)($body['manifest_id'] ?? 0);

            $stmt = $db->prepare(
                "DELETE FROM archive_manifest
                 WHERE id = ? AND state IN ('failed','verify_failed')"
            );
            $stmt->execute([$manifest_id]);

            echo json_encode(['ok' => true, 'deleted' => $stmt->rowCount()]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => "Unknown action: {$action}"]);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}


function _verify_single(PDO $db, array $partition): array {
    $policy   = $db->query("SELECT archive_path FROM archive_policy WHERE id = 1")
                   ->fetch(PDO::FETCH_ASSOC);
    $base     = $policy['archive_path'] ?? '/var/opensiem/archive';
    $full     = $base . '/' . $partition['file_path'];

    $result = [
        'manifest_id'    => (int)$partition['id'],
        'partition_date' => $partition['partition_date'],
        'table_name'     => $partition['table_name'],
        'ok'             => false,
        'error'          => null,
    ];

    if (!file_exists($full)) {
        $result['error'] = 'File not found on disk';
        $db->prepare(
            "UPDATE archive_manifest SET state = 'verify_failed',
             error_msg = 'File not found during verification' WHERE id = ?"
        )->execute([$partition['id']]);
        return $result;
    }

    $actual = hash_file('sha256', $full);
    if ($actual !== $partition['sha256_hash']) {
        $result['error'] = "Hash mismatch — expected {$partition['sha256_hash']}, got {$actual}";
        $db->prepare(
            "UPDATE archive_manifest SET state = 'verify_failed',
             error_msg = ? WHERE id = ?"
        )->execute([$result['error'], $partition['id']]);
        return $result;
    }

    $db->prepare(
        "UPDATE archive_manifest SET state = 'verified',
         verified_at = now() WHERE id = ?"
    )->execute([$partition['id']]);

    $result['ok']   = true;
    $result['hash'] = $actual;
    return $result;
}


function _run_python_archiver(string $target_date): array {
    $script = '/home/waqar/OpenSIEM/run_archive.py';

    if (!file_exists($script)) {
        return [
            'ok'    => false,
            'error' => "Archiver script not found at {$script}, Correct the path at of run_archive.py in api/archive/run.php ",
        ];
    }

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $proc = proc_open(
        "python3 " . escapeshellarg($script) . " --date " . escapeshellarg($target_date),
        $descriptors,
        $pipes
    );

    if (!is_resource($proc)) {
        return ['ok' => false, 'error' => 'Failed to start archiver process'];
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit_code = proc_close($proc);

    if (empty(trim($stdout))) {
        return [
            'ok'    => false,
            'error' => 'Archiver produced no output',
            'stderr'=> trim($stderr),
            'hint'  => 'Check that pyarrow is installed (pip install pyarrow) and all files are deployed to /opt/opensiem/',
        ];
    }

    $result = json_decode(trim($stdout), true);
    if (!$result) {
        return [
            'ok'    => false,
            'error' => 'Archiver output was not valid JSON',
            'raw'   => trim($stdout),
            'stderr'=> trim($stderr),
        ];
    }

    if (!empty($stderr)) {
        $result['warnings'] = trim($stderr);
    }

    return $result;
}
