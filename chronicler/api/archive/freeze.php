<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['administrator']);

header('Content-Type: application/json');

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_GET['action'] ?? '';

try {
$db = pdo();

    switch ($action) {

        case 'freeze':
            $manifest_id = (int)($body['manifest_id'] ?? 0);
            $reason      = trim($body['reason'] ?? '');

            if (!$manifest_id) {
                http_response_code(400);
                echo json_encode(['ok' => false, 'error' => 'manifest_id required']);
                exit;
            }

            $stmt = $db->prepare(
                "UPDATE archive_manifest
                 SET frozen = true, frozen_by = ?, frozen_reason = ?,
                     frozen_at = now()
                 WHERE id = ? AND frozen = false"
            );
            $stmt->execute([
                $_SESSION['username'] ?? 'unknown', $reason, $manifest_id
            ]);

            if ($stmt->rowCount() === 0) {
                echo json_encode(['ok' => false,
                                  'error' => 'Partition not found or already frozen']);
                exit;
            }

            $db->prepare(
                "INSERT INTO archive_audit_log
                 (action, performed_by, manifest_id, detail)
                 VALUES ('partition_frozen', ?, ?, ?)"
            )->execute([
                $_SESSION['username'] ?? 'unknown', $manifest_id,
                json_encode(['reason' => $reason]),
            ]);

            echo json_encode(['ok' => true]);
            break;

        case 'unfreeze':
            $manifest_id = (int)($body['manifest_id'] ?? 0);

            $stmt = $db->prepare(
                "UPDATE archive_manifest
                 SET frozen = false, frozen_by = null, frozen_reason = null,
                     frozen_at = null
                 WHERE id = ? AND frozen = true"
            );
            $stmt->execute([$manifest_id]);

            $db->prepare(
                "INSERT INTO archive_audit_log
                 (action, performed_by, manifest_id, detail)
                 VALUES ('partition_unfrozen', ?, ?, ?)"
            )->execute([
                $_SESSION['username'] ?? 'unknown', $manifest_id, '{}',
            ]);

            echo json_encode(['ok' => true, 'unfrozen' => $stmt->rowCount()]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => "Unknown action: {$action}"]);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
