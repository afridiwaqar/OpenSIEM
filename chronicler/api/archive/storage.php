<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['administrator']);

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$db = pdo();

$action = $body['action'] ?? $_GET['action'] ?? '';

try {
    switch ($action) {

        case 'save':
            _save_storage($db, $body);
            break;

        case 'test':
            _test_storage($body);
            break;

        case 'activate':
            $id = (int)($body['id'] ?? 0);
            $db->exec("UPDATE archive_storage_config SET is_active = false");
            $stmt = $db->prepare(
                "UPDATE archive_storage_config SET is_active = true WHERE id = :id"
            );
            $stmt->execute([':id' => $id]);
            _audit_log($db, 'storage_backend_activated', ['id' => $id]);
            echo json_encode(['ok' => true]);
            break;

        case 'list':
            $rows = $db->query(
                "SELECT id, name, backend_type, is_active, config_json,
                        last_tested_at, last_test_ok, last_test_msg
                 FROM archive_storage_config ORDER BY id"
            )->fetchAll(PDO::FETCH_ASSOC);
            // Decode config_json so JS can use it to populate the edit form
            foreach ($rows as &$row) {
                $row['config'] = json_decode($row['config_json'] ?? '{}', true);
                unset($row['config_json']);
            }
            echo json_encode(['ok' => true, 'backends' => $rows]);
            break;

        case 'get':
            $id  = (int)($_GET['id'] ?? 0);
            $row = $db->prepare(
                "SELECT id, name, backend_type, is_active, config_json
                 FROM archive_storage_config WHERE id = ?"
            );
            $row->execute([$id]);
            $r = $row->fetch(PDO::FETCH_ASSOC);
            if (!$r) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Not found']); exit; }
            $r['config'] = json_decode($r['config_json'] ?? '{}', true);
            unset($r['config_json']);
            echo json_encode(['ok' => true, 'backend' => $r]);
            break;

        case 'delete':
            $id = (int)($body['id'] ?? 0);
            $db->prepare("DELETE FROM archive_storage_config WHERE id = :id AND is_active = false")
               ->execute([':id' => $id]);
            echo json_encode(['ok' => true]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => "Unknown action: {$action}"]);
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}


function _save_storage(PDO $db, array $body): void {
    $name         = trim($body['name'] ?? '');
    $backend_type = $body['backend_type'] ?? '';
    $config       = $body['config'] ?? [];
    $credentials  = $body['credentials'] ?? [];
    $id           = (int)($body['id'] ?? 0);

    if (!$name || !$backend_type) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'name and backend_type required']);
        return;
    }

    if (!in_array($backend_type, ['local', 'sftp', 's3'])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid backend_type']);
        return;
    }

    $config_json    = json_encode($config);
    $credentials_enc = null;

    if (!empty($credentials)) {
        $credentials_enc = _encrypt_credentials($credentials);
    }

    if ($id) {
        $stmt = $db->prepare(
            "UPDATE archive_storage_config
             SET name = :name, backend_type = :bt, config_json = :cfg,
                 credentials_enc = COALESCE(:cred, credentials_enc),
                 updated_at = now()
             WHERE id = :id"
        );
        $stmt->execute([
            ':name' => $name, ':bt' => $backend_type,
            ':cfg'  => $config_json, ':cred' => $credentials_enc,
            ':id'   => $id,
        ]);
    } else {
        $stmt = $db->prepare(
            "INSERT INTO archive_storage_config
             (name, backend_type, config_json, credentials_enc)
             VALUES (:name, :bt, :cfg, :cred)
             RETURNING id"
        );
        $stmt->execute([
            ':name' => $name, ':bt' => $backend_type,
            ':cfg'  => $config_json, ':cred' => $credentials_enc,
        ]);
        $id = $stmt->fetchColumn();
    }

    _audit_log($db, 'storage_config_saved', [
        'id' => $id, 'name' => $name, 'backend_type' => $backend_type
    ]);

    echo json_encode(['ok' => true, 'id' => (int)$id]);
}


function _test_storage(array $body): void {
    $backend_type = $body['backend_type'] ?? '';
    $config       = $body['config']       ?? [];
    $credentials  = $body['credentials']  ?? [];

    // Possible locations for the test script
    $candidates = [
        '/opt/opensiem/test_storage_backend.py',
        '/home/waqar/OpenSIEM/test_storage_backend.py',
        dirname(__FILE__) . '/../../../test_storage_backend.py',
    ];
    $script = null;
    foreach ($candidates as $c) {
        if (file_exists($c)) { $script = $c; break; }
    }

    if (!$script) {
        echo json_encode([
            'ok'    => false,
            'error' => 'test_storage_backend.py not found. Deploy it to /opt/opensiem/test_storage_backend.py',
            'steps' => [],
        ]);
        return;
    }

    $tmp = tempnam(sys_get_temp_dir(), 'opensiem_storage_test_');
    file_put_contents($tmp, json_encode([
        'backend_type' => $backend_type,
        'config'       => $config,
        'credentials'  => $credentials,
    ]));

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    // $proc = proc_open(
    //     "python3 " . escapeshellarg($script) . " " . escapeshellarg($tmp),
    //     $descriptors, $pipes
    // );

    $proc = proc_open(
    "timeout --kill-after=5 20 python3 " . escapeshellarg($script) . " " . escapeshellarg($tmp),
    $descriptors, $pipes
    );

    if (!is_resource($proc)) {
        @unlink($tmp);
        echo json_encode(['ok' => false, 'error' => 'Failed to start test script process', 'steps' => []]);
        return;
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    @unlink($tmp);  // delete AFTER Python has finished reading it

    $result = json_decode(trim($stdout), true);
    if (!$result) {
        echo json_encode([
            'ok'    => false,
            'error' => 'Test script produced no output',
            'detail'=> trim($stderr) ?: 'No error details available',
            'hint'  => 'Check python3 is available and pyarrow/paramiko/boto3 installed',
            'steps' => [],
        ]);
        return;
    }

    if (!empty($stderr)) {
        $result['warnings'] = trim($stderr);
    }

    // Persist test result so the backend card shows up-to-date status
    if (!empty($body['id'])) {
        try {
            $db = pdo();
            $db->prepare(
                "UPDATE archive_storage_config
                 SET last_tested_at = now(), last_test_ok = ?, last_test_msg = ?
                 WHERE id = ?"
            )->execute([
                $result['ok'] ? 'true' : 'false',
                $result['error'] ?? ($result['ok'] ? 'All checks passed' : 'Unknown error'),
                (int)$body['id'],
            ]);
        } catch (Exception $e) { /* non-fatal */ }
    }

    echo json_encode($result);
}


function _encrypt_credentials(array $creds): string {
    $key_path = '/etc/opensiem/certs/archive.key';
    if (!file_exists($key_path)) {
        return base64_encode(json_encode($creds));
    }
    $cmd    = "python3 -c \"
import sys, json, base64
sys.path.insert(0, '/opt/opensiem')
from archive_storage import encrypt_credentials
print(encrypt_credentials(json.loads(sys.stdin.read())))
\"";
    $proc = proc_open($cmd, [0 => ['pipe','r'], 1 => ['pipe','w']], $pipes);
    fwrite($pipes[0], json_encode($creds));
    fclose($pipes[0]);
    $enc = trim(stream_get_contents($pipes[1]));
    fclose($pipes[1]);
    proc_close($proc);
    return $enc ?: base64_encode(json_encode($creds));
}


function _audit_log(PDO $db, string $action, array $detail = []): void {
    $stmt = $db->prepare(
        "INSERT INTO archive_audit_log (action, performed_by, detail)
         VALUES (:action, :by, :detail)"
    );
    $stmt->execute([
        ':action' => $action,
        ':by'     => $_SESSION['username'] ?? 'unknown',
        ':detail' => json_encode($detail),
    ]);
}