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

// Check all common session keys for robustness
$uid    = (int)($_SESSION['user_id'] ?? $_SESSION['id'] ?? $_SESSION['uid'] ?? 0);

try {
    if ($method === 'GET') {
        try {
            $rows = $db->prepare(
                "SELECT n.id, n.message, n.alert_id, n.created_at
                FROM ui_notifications n
                WHERE n.user_id = ?
                AND n.read_at IS NULL
                ORDER BY n.created_at DESC
                LIMIT 30"
            );
            $rows->execute([$uid]);
            $notifications = $rows->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            $notifications = [];
        }

        // Return BOTH keys ('notifications' for alerts.js and 'items'/'count' for correlation.js)
        echo json_encode([
            'ok'            => true,
            'count'         => count($notifications),
                         'notifications' => $notifications,
                         'items'         => $notifications
        ]);

    } elseif ($method === 'POST') {
        $body   = json_decode(file_get_contents('php://input'), true) ?? [];
        $action = $body['action'] ?? '';

        if ($action === 'mark_read') {
            $nid = (int)($body['id'] ?? 0);
            try {
                $db->prepare(
                    "UPDATE ui_notifications SET read_at = now()
                WHERE id = ? AND user_id = ?"
                )->execute([$nid, $uid]);
            } catch (Exception $e) { /* table may not exist */ }
            echo json_encode(['ok' => true]);

        } elseif ($action === 'mark_all_read') {
            try {
                $db->prepare(
                    "UPDATE ui_notifications SET read_at = now()
                WHERE user_id = ? AND read_at IS NULL"
                )->execute([$uid]);
            } catch (Exception $e) { /* table may not exist */ }
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
