<?php
require_once __DIR__ . '/../config/auth.php';
require_once __DIR__ . '/../config/db.php';

require_login();

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$db     = pdo();

try {
    if ($method === 'GET') {
        $action = $_GET['action'] ?? 'list';

        if ($action === 'list') {
            $rows = $db->query(
                "SELECT id, client_name, source_ip, last_heartbeat_at,
                        last_message_at, offline_threshold_minutes, is_online,
                        marked_offline_at, alert_id_fk
                 FROM watcher_health
                 ORDER BY is_online ASC, last_heartbeat_at DESC"
            )->fetchAll(PDO::FETCH_ASSOC);

            $settings = $db->query(
                "SELECT * FROM watcher_health_settings WHERE id = 1"
            )->fetch(PDO::FETCH_ASSOC);

            echo json_encode([
                'ok' => true,
                'watchers' => $rows,
                'settings' => $settings,
                'summary' => [
                    'total'   => count($rows),
                    'online'  => count(array_filter($rows, fn($r) => $r['is_online'])),
                    'offline' => count(array_filter($rows, fn($r) => !$r['is_online'])),
                ],
            ]);

        } elseif ($action === 'settings') {
            $row = $db->query(
                "SELECT * FROM watcher_health_settings WHERE id = 1"
            )->fetch(PDO::FETCH_ASSOC);
            echo json_encode(['ok' => true, 'settings' => $row]);

        } else {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => "Unknown action: {$action}"]);
        }

    } elseif ($method === 'POST') {
        $body   = json_decode(file_get_contents('php://input'), true) ?? [];
        $action = $body['action'] ?? '';

        if ($action === 'set_threshold') {
            require_perm('role', ['admin']);
            $source_ip = trim($body['source_ip'] ?? '');
            $minutes   = $body['threshold_minutes'] ?? null;

            if (!$source_ip) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'source_ip required']);
                exit;
            }

            $minutes = ($minutes === null || $minutes === '') ? null : (int)$minutes;

            $stmt = $db->prepare(
                "UPDATE watcher_health
                 SET offline_threshold_minutes = ?, updated_at = now()
                 WHERE source_ip = ?"
            );
            $stmt->execute([$minutes, $source_ip]);

            echo json_encode(['ok' => true, 'updated' => $stmt->rowCount()]);

        } elseif ($action === 'set_global_settings') {
            require_perm('role', ['admin']);
            $default_minutes = (int)($body['default_offline_threshold_minutes'] ?? 5);
            $check_interval   = (int)($body['check_interval_seconds'] ?? 60);
            $enabled          = filter_var($body['enabled'] ?? true, FILTER_VALIDATE_BOOLEAN);

            $stmt = $db->prepare(
                "UPDATE watcher_health_settings
                 SET default_offline_threshold_minutes = ?,
                     check_interval_seconds = ?,
                     enabled = ?,
                     updated_at = now()
                 WHERE id = 1"
            );
            $stmt->execute([$default_minutes, $check_interval, $enabled ? 'true' : 'false']);

            echo json_encode(['ok' => true]);

        } elseif ($action === 'remove') {
            require_perm('role', ['admin']);
            $source_ip = trim($body['source_ip'] ?? '');
            $stmt = $db->prepare("DELETE FROM watcher_health WHERE source_ip = ?");
            $stmt->execute([$source_ip]);
            echo json_encode(['ok' => true, 'removed' => $stmt->rowCount()]);

        } elseif ($action === 'check_now') {
            // Forces an immediate offline check for all watchers, instead of
            // waiting for the background thread's next poll cycle.
            require_perm('role', ['admin']);

            $settings = $db->query(
                "SELECT default_offline_threshold_minutes FROM watcher_health_settings WHERE id = 1"
            )->fetch(PDO::FETCH_ASSOC);
            $default_minutes = (int)($settings['default_offline_threshold_minutes'] ?? 5);

            $rows = $db->query(
                "SELECT id, client_name, source_ip, last_heartbeat_at,
                        offline_threshold_minutes, is_online
                 FROM watcher_health
                 WHERE is_online = true"
            )->fetchAll(PDO::FETCH_ASSOC);

            $marked_offline = [];

            foreach ($rows as $row) {
                $threshold = $row['offline_threshold_minutes'] ?? $default_minutes;
                $stmt = $db->prepare(
                    "SELECT EXTRACT(EPOCH FROM (now() - last_heartbeat_at)) / 60 AS minutes_silent
                     FROM watcher_health WHERE id = ?"
                );
                $stmt->execute([$row['id']]);
                $minutes_silent = (float)$stmt->fetchColumn();

                if ($minutes_silent > $threshold) {
                    $db->prepare(
                        "UPDATE watcher_health
                         SET is_online = false, marked_offline_at = now()
                         WHERE id = ?"
                    )->execute([$row['id']]);

                    $marked_offline[] = [
                        'client_name'    => $row['client_name'] ?: $row['source_ip'],
                        'source_ip'      => $row['source_ip'],
                        'minutes_silent' => round($minutes_silent, 1),
                        'threshold'      => $threshold,
                    ];
                }
            }

            // Raise alerts via the Python alarm system for anything just marked offline.
            // We shell out to a tiny inline script rather than reimplementing
            // alarm_system's dedup/email logic in PHP.
            if (!empty($marked_offline)) {
                $payload = base64_encode(json_encode($marked_offline));
                $cmd = "python3 -c \"
import sys, json, base64
sys.path.insert(0, '/opt/opensiem')
from alarm_system import alarm_system
items = json.loads(base64.b64decode('{$payload}'))
for w in items:
    alarm_system.raise_alarm(
        case_name=f'Watcher offline: ' + w['client_name'],
        source_ip=w['source_ip'],
        severity='high',
        details=w,
        alert_type='watcher_health'
    )
\" 2>&1";
                shell_exec($cmd);
            }

            echo json_encode([
                'ok' => true,
                'checked' => count($rows),
                'marked_offline' => $marked_offline,
            ]);

        } else {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => "Unknown action: {$action}"]);
        }

    } else {
        http_response_code(405);
        echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
