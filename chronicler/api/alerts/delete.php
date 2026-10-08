<?php
// /var/www/chronicler/api/alerts/delete.php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('delete');
header('Content-Type: application/json');

$body = json_decode(file_get_contents('php://input'), true) ?? [];
$id   = (int)($body['id'] ?? 0);

if (!$id) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'id required']);
    exit;
}

try {
    pdo()->prepare("DELETE FROM alerts WHERE id = ?")->execute([$id]);
    echo json_encode(['ok' => true]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
