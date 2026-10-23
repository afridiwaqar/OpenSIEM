<?php
// /var/www/chronicler/api/notifications.php
require_once __DIR__ . '/../config/auth.php';
require_once __DIR__ . '/../config/db.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_login();
header('Content-Type: application/json');

$db     = pdo();
$method = $_SERVER['REQUEST_METHOD'];

$user = current_user();
$uid  = (int)($user['user_id'] ?? 0);

try {
    if ($method === 'GET') {
        require_perm('read');

        $rows = $db->prepare(
            "SELECT n.id, n.message, n.alert_id, n.read_at, n.created_at
               FROM ui_notifications n
              WHERE n.user_id = ?
              ORDER BY n.created_at DESC
              LIMIT 30"
        );
        $rows->execute([$uid]);
        $notifications = $rows->fetchAll(PDO::FETCH_ASSOC);

        $count = $db->prepare(
            "SELECT COUNT(*)
               FROM ui_notifications
              WHERE user_id = ? AND read_at IS NULL"
        );
        $count->execute([$uid]);
        $unreadCount = (int)$count->fetchColumn();

        $alertsQuery = $db->query(
            "SELECT a.id, a.alert_id, a.alert_type, a.severity, a.status,
                    a.is_active, a.count, a.source_ip, a.assigned_at,
                    a.acknowledged_time, l.username AS assigned_username
               FROM alerts a
               LEFT JOIN login l ON l.user_id = a.assigned_to
              ORDER BY a.id DESC"
        );
        $alerts = $alertsQuery->fetchAll(PDO::FETCH_ASSOC);

        foreach ($notifications as &$n) {
            $n['is_unread'] = is_null($n['read_at']);
        }
        unset($n);

        echo json_encode([
            'ok'            => true,
            'unread_count'  => $unreadCount,
            'user_id'       => $uid,
            'alerts'        => $alerts,
            'notifications' => $notifications,
            'items'         => $notifications
        ]);

    } elseif ($method === 'POST') {
        $body   = json_decode(file_get_contents('php://input'), true) ?? [];
        $action = $body['action'] ?? '';

        if ($action === 'mark_read') {
            $nid = (int)($body['id'] ?? 0);
            $db->prepare(
                "UPDATE ui_notifications SET read_at = now()
                  WHERE id = ? AND user_id = ? AND read_at IS NULL"
            )->execute([$nid, $uid]);
            echo json_encode(['ok' => true]);

        } elseif ($action === 'mark_all_read') {
            $db->prepare(
                "UPDATE ui_notifications SET read_at = now()
                  WHERE user_id = ? AND read_at IS NULL"
            )->execute([$uid]);
            echo json_encode(['ok' => true]);

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