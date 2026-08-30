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
            set_time_limit(280);
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

            // Serialize this whole check-then-insert against any other
            // concurrent 'start' request. Without this, two requests
            // arriving close together can both pass the overlap check
            // before either has inserted its row, letting two rehydration
            // jobs collide on the same partitions (this is what produced
            // the job 8 / job 9 deadlock). Released automatically at
            // connection close (end of request).
            $db->exec("SELECT pg_advisory_lock(hashtext('archive_rehydration_start'))");

            $existing = $db->prepare(
                "SELECT id FROM archive_rehydration
                 WHERE state IN ('pending','active')
                   AND date_from <= ? AND date_to >= ?"
            );
            $existing->execute([$date_to, $date_from]);
            if ($existing->fetch()) {
                $db->exec("SELECT pg_advisory_unlock(hashtext('archive_rehydration_start'))");
                http_response_code(409);
                echo json_encode(['ok'    => false,
                                  'error' => 'A pending or active rehydration already overlaps this date range']);
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

            $db->exec("SELECT pg_advisory_unlock(hashtext('archive_rehydration_start'))");

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
                        created_at, completed_at, released_at, error_msg,
                        partitions_total, partitions_done
                 FROM archive_rehydration
                 ORDER BY created_at DESC
                 LIMIT 50"
            )->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode(['ok' => true, 'rehydrations' => $rows]);
            break;

        // ── Release a rehydration early ────────────────────────────────────
        case 'release':
            set_time_limit(280);
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

        // ── Cancel a pending/running rehydration ─────────────────────────────
        case 'cancel':
            // NOTE: using require_perm('update') here deliberately, not
            // require_perm('archive_role', [...]) like the rest of this
            // file. auth.php's real require_perm() only takes one argument
            // (create/read/update/delete, mapped to the user_permissions
            // table) — the archive_role calls elsewhere silently drop
            // their second argument and only work at all because your
            // account has role='admin', which bypasses the check entirely.
            // Worth fixing file-wide separately; flagging so this new code
            // doesn't quietly inherit the same bug.
            require_perm('update');

            $job_id = (int)($body['id'] ?? 0);
            if (!$job_id) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'id required']);
                exit;
            }

            $job = $db->prepare(
                "SELECT id, pid, state FROM archive_rehydration
                 WHERE id = ? AND state IN ('pending','running')"
            );
            $job->execute([$job_id]);
            $row = $job->fetch(PDO::FETCH_ASSOC);

            if (!$row) {
                http_response_code(404);
                echo json_encode(['ok' => false,
                                  'error' => 'No pending or running rehydration with that id']);
                exit;
            }

            $pid = (int)($row['pid'] ?? 0);

            if ($pid > 0 && posix_kill($pid, 0)) {
                // Process is alive — ask it to stop cleanly. run_archive.py
                // catches SIGTERM and finishes its current commit batch
                // before exiting, so this won't leave an aborted
                // transaction behind like a hard kill would.
                // Signal 15 = SIGTERM. Using the raw number rather than
                // the SIGTERM constant since that constant is defined by
                // the pcntl extension, not posix — posix_kill() itself
                // only needs posix (confirmed installed), but the
                // constant would fatal with an undefined-constant error
                // if pcntl isn't loaded.
                posix_kill($pid, 15);
                $db->prepare(
                    "UPDATE archive_rehydration
                     SET error_msg = 'Cancellation requested — waiting for process to stop'
                     WHERE id = ?"
                )->execute([$job_id]);
                $msg = 'Cancellation requested. The job will finish its current batch and stop shortly — refresh to see updated status.';
            } else {
                // No live process (e.g. a stale job from before PID
                // tracking existed, or it already exited). Mark it
                // cancelled directly so it stops showing as stuck.
                $db->prepare(
                    "UPDATE archive_rehydration
                     SET state = 'cancelled', completed_at = now(),
                         error_msg = 'Cancelled — no running process found (stale job)'
                     WHERE id = ?"
                )->execute([$job_id]);
                $msg = 'No running process was found for this job — marked as cancelled.';
            }

            $db->prepare(
                "INSERT INTO archive_audit_log
                 (action, performed_by, detail)
                 VALUES ('rehydration_cancelled', ?, ?)"
            )->execute([
                $_SESSION['username'] ?? 'unknown',
                json_encode(['job_id' => $job_id, 'pid' => $pid]),
            ]);

            echo json_encode(['ok' => true, 'msg' => $msg]);
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


// function _run_rehydration(int $job_id): array {
//     $script = '/opt/opensiem/run_archive.py';

//     if (!file_exists($script)) {
//         return [
//             'ok'    => false,
//             'error' => "run_archive.py not found at {$script}",
//         ];
//     }

//     $descriptors = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
//     $proc = proc_open(
//         "python3 " . escapeshellarg($script) . " --job " . (int)$job_id,
//         $descriptors, $pipes
//     );

//     if (!is_resource($proc)) {
//         return ['ok' => false, 'error' => 'Failed to start rehydration process'];
//     }

//     fclose($pipes[0]);
//     $stdout = stream_get_contents($pipes[1]);
//     $stderr = stream_get_contents($pipes[2]);
//     fclose($pipes[1]);
//     fclose($pipes[2]);
//     proc_close($proc);

//     $result = json_decode(trim($stdout), true);
//     if (!$result) {
//         return [
//             'ok'    => false,
//             'error' => 'Rehydration script produced no output',
//             'stderr'=> trim($stderr),
//             'hint'  => 'Check that pyarrow and psycopg2 are installed: pip install pyarrow psycopg2-binary',
//         ];
//     }
//     if (!empty($stderr)) $result['warnings'] = trim($stderr);
//     return $result;
// }

function _run_rehydration(int $job_id): array {
    $script = '/opt/opensiem/run_archive.py';
    if (!file_exists($script)) {
        return ['ok' => false, 'error' => "run_archive.py not found at {$script}"];
    }

    $log = '/var/log/opensiem/rehydrate_' . $job_id . '.log';
    $cmd = 'nohup python3 ' . escapeshellarg($script) .
           ' --job ' . (int)$job_id .
           ' > ' . escapeshellarg($log) . ' 2>&1 & echo $!';

    exec($cmd, $output);

    // run_archive.py also writes its own PID via os.getpid() as soon as
    // it starts — this capture just closes the brief window between job
    // creation and that self-write, so 'cancel' works even if clicked in
    // that split second. Both end up storing the same PID.
    $pid = (int)($output[0] ?? 0);
    if ($pid > 0) {
        $db = pdo();
        $db->prepare("UPDATE archive_rehydration SET pid = ? WHERE id = ?")
           ->execute([$pid, $job_id]);
    }

    return ['ok' => true, 'job_id' => $job_id, 'state' => 'pending',
            'msg' => 'Rehydration started in background — poll action=list for status'];
}

function _run_release(int $job_id, array $row): array {
    $script = '/opt/opensiem/run_archive.py';

    if (!file_exists($script)) {
        return [
            'ok'    => false,
            'error' => "run_archive.py not found at {$script}",
        ];
    }

    $descriptors = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
    $proc = proc_open(
        "python3 " . escapeshellarg($script) . " --release " . (int)$job_id,
        $descriptors, $pipes
    );

    if (!is_resource($proc)) {
        return ['ok' => false, 'error' => 'Failed to start release process'];
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    $result = json_decode(trim($stdout), true);
    if (!$result) {
        return [
            'ok'    => false,
            'error' => 'Release script produced no output',
            'stderr'=> trim($stderr),
        ];
    }
    if (!empty($stderr)) $result['warnings'] = trim($stderr);
    return $result;
}
