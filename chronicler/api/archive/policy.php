<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];

try {
$db = pdo();

    if ($method === 'GET') {
        require_perm('archive_role', ['viewer','operator','administrator']);
        $row = $db->query("SELECT * FROM archive_policy WHERE id = 1")
                  ->fetch(PDO::FETCH_ASSOC);
        echo json_encode(['ok' => true, 'policy' => $row]);

    } elseif ($method === 'POST') {
        require_perm('archive_role', ['administrator']);
        $body = json_decode(file_get_contents('php://input'), true) ?? [];

        $allowed = [
            'enabled','hot_retention_days','cold_retention_days',
            'run_time','compression','encrypt_at_rest',
            'verify_after_export','delete_after_verify',
            'partial_export_behaviour','storage_alert_threshold_gb',
            'archive_messages','archive_alerts','archive_alert_occurrences',
            'alerts_retention_days',
        ];

        $bool_fields = [
            'enabled', 'encrypt_at_rest', 'verify_after_export',
            'delete_after_verify', 'archive_messages', 'archive_alerts',
            'archive_alert_occurrences',
        ];
        $int_fields = [
            'hot_retention_days', 'cold_retention_days',
            'storage_alert_threshold_gb', 'alerts_retention_days',
        ];

        $sets = [];
        $vals = [];
        foreach ($allowed as $col) {
            if (!array_key_exists($col, $body)) continue;
            $val = $body[$col];

            if (in_array($col, $bool_fields)) {
                $val = filter_var($val, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                if ($val === null) $val = false;
                $val = $val ? 'true' : 'false';
            } elseif (in_array($col, $int_fields)) {
                $val = (int)$val;
            } else {
                $val = (string)$val;
            }

            $sets[] = "{$col} = ?";
            $vals[] = $val;
        }

        if (empty($sets)) {
            echo json_encode(['ok' => true, 'msg' => 'Nothing to update']);
            exit;
        }

        $sets[] = "updated_at = now()";
        $sets[] = "updated_by = ?";
        $vals[] = $_SESSION['username'] ?? 'unknown';

        $stmt = $db->prepare(
            "UPDATE archive_policy SET " . implode(', ', $sets) . " WHERE id = 1"
        );
        $stmt->execute($vals);

        $db->prepare(
            "INSERT INTO archive_audit_log (action, performed_by, detail)
             VALUES ('policy_updated', ?, ?)"
        )->execute([
            $_SESSION['username'] ?? 'system',
            json_encode(['changed' => array_keys(array_intersect_key($body,
                         array_flip($allowed)))]),
        ]);

        $updated = $db->query("SELECT * FROM archive_policy WHERE id = 1")
                      ->fetch(PDO::FETCH_ASSOC);
        echo json_encode(['ok' => true, 'policy' => $updated]);

    } else {
        http_response_code(405);
        echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}
