<?php
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';

require_login();
require_perm('archive_role', ['viewer', 'operator', 'administrator']);

header('Content-Type: application/json');

$date_from  = $_GET['date_from']  ?? '';
$date_to    = $_GET['date_to']    ?? '';
$device_ip  = trim($_GET['device_ip']  ?? '');
$device_name= trim($_GET['device_name']?? '');
$action     = trim($_GET['action']     ?? '');
$level      = trim($_GET['level']      ?? '');
$user       = trim($_GET['user']       ?? '');
$source     = trim($_GET['source']     ?? '');
$message_q  = trim($_GET['message_q']  ?? '');
$export_csv = isset($_GET['export_csv']);
$page       = max(1, (int)($_GET['page'] ?? 1));
$per_page   = min(500, max(25, (int)($_GET['per_page'] ?? 100)));

if (!$date_from || !$date_to) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'date_from and date_to are required']);
    exit;
}

$d_from = DateTime::createFromFormat('Y-m-d', $date_from);
$d_to   = DateTime::createFromFormat('Y-m-d', $date_to);

if (!$d_from || !$d_to || $d_from > $d_to) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Invalid date range']);
    exit;
}

if ($d_to->diff($d_from)->days > 365) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Date range cannot exceed 365 days']);
    exit;
}

try {
$db = pdo();

    $policy = $db->query("SELECT * FROM archive_policy WHERE id = 1")
                 ->fetch(PDO::FETCH_ASSOC);

    $archive_path = $policy['archive_path'] ?? '/var/opensiem/archive';

    $partitions = $db->prepare(
        "SELECT DISTINCT file_path, partition_date
         FROM archive_manifest
         WHERE partition_date BETWEEN :d1 AND :d2
           AND state IN ('verified', 'deleted_from_hot')
         ORDER BY partition_date"
    );
    $partitions->execute([':d1' => $date_from, ':d2' => $date_to]);
    $partition_files = $partitions->fetchAll(PDO::FETCH_ASSOC);

    if (empty($partition_files)) {
        echo json_encode([
            'ok'        => true,
            'results'   => [],
            'total'     => 0,
            'page'      => $page,
            'pages'     => 0,
            'partitions_scanned' => 0,
            'query_ms'  => 0,
        ]);
        exit;
    }

    $file_paths = array_map(function($r) use ($archive_path) {
        return $archive_path . '/' . $r['file_path'];
    }, $partition_files);

    $existing = array_filter($file_paths, 'file_exists');

    if (empty($existing)) {
        echo json_encode([
            'ok'        => true,
            'results'   => [],
            'total'     => 0,
            'page'      => $page,
            'pages'     => 0,
            'partitions_scanned' => 0,
            'query_ms'  => 0,
            'warning'   => 'Partition files not found on local path. Remote backends require rehydration first.',
        ]);
        exit;
    }

    $glob_pattern = escapeshellarg(
        $archive_path . '/opensiem_messages/**/*.parquet'
    );

    $where_parts = [
        "log_date >= DATE '{$date_from}'",
        "log_date <= DATE '{$date_to}'",
    ];

    $param_bindings = [];

    if ($device_ip) {
        $safe = addslashes($device_ip);
        $where_parts[] = "device_ip = '{$safe}'";
    }
    if ($device_name) {
        $safe = addslashes($device_name);
        $where_parts[] = "device_name ILIKE '%{$safe}%'";
    }
    if ($action) {
        $safe = addslashes($action);
        $where_parts[] = "action = '{$safe}'";
    }
    if ($level) {
        $safe = addslashes($level);
        $where_parts[] = "level = '{$safe}'";
    }
    if ($user) {
        $safe = addslashes($user);
        $where_parts[] = "user = '{$safe}'";
    }
    if ($source) {
        $safe = addslashes($source);
        $where_parts[] = "source_name ILIKE '%{$safe}%'";
    }
    if ($message_q) {
        $safe = addslashes($message_q);
        $where_parts[] = "(message ILIKE '%{$safe}%' OR raw_message ILIKE '%{$safe}%')";
    }

    $where_sql = implode("\n  AND ", $where_parts);
    $offset    = ($page - 1) * $per_page;

    $file_list = "'" . implode("','", array_map('addslashes', $existing)) . "'";

    $count_sql = "
        SELECT COUNT(*) as total
        FROM read_parquet([{$file_list}])
        WHERE {$where_sql}
    ";

    $data_sql = "
        SELECT
            log_date, log_time, device_ip, device_name,
            source_name, action, level, user,
            hostname, client_ip, message, raw_message, attributes
        FROM read_parquet([{$file_list}])
        WHERE {$where_sql}
        ORDER BY log_date DESC, log_time DESC
        LIMIT {$per_page} OFFSET {$offset}
    ";

    $t0 = microtime(true);

    $duckdb_result = _run_duckdb($count_sql, $data_sql);

    $query_ms = round((microtime(true) - $t0) * 1000);

    if (!$duckdb_result['ok']) {
        http_response_code(500);
        echo json_encode([
            'ok'    => false,
            'error' => $duckdb_result['error'],
        ]);
        exit;
    }

    $total = (int)($duckdb_result['total'] ?? 0);
    $pages = $total > 0 ? (int)ceil($total / $per_page) : 0;

    if ($export_csv) {
        require_perm('archive_role', ['operator', 'administrator']);
        _output_csv($duckdb_result['rows'], $date_from, $date_to);
        exit;
    }

    echo json_encode([
        'ok'                 => true,
        'results'            => $duckdb_result['rows'],
        'total'              => $total,
        'page'               => $page,
        'pages'              => $pages,
        'partitions_scanned' => count($existing),
        'query_ms'           => $query_ms,
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
}


function _run_duckdb(string $count_sql, string $data_sql): array {
    $tmp_count = tempnam(sys_get_temp_dir(), 'duck_count_');
    $tmp_data  = tempnam(sys_get_temp_dir(), 'duck_data_');

    $script = <<<SQL
.mode json
.output {$tmp_count}
{$count_sql};
.output {$tmp_data}
{$data_sql};
SQL;

    $tmp_script = tempnam(sys_get_temp_dir(), 'duck_script_');
    file_put_contents($tmp_script, $script);

    $cmd    = "duckdb -init /dev/null < " . escapeshellarg($tmp_script) . " 2>&1";
    $output = shell_exec($cmd);
    $code   = 0;

    @unlink($tmp_script);

    if ($output && stripos($output, 'Error') !== false) {
        @unlink($tmp_count);
        @unlink($tmp_data);
        return ['ok' => false, 'error' => trim($output)];
    }

    $count_raw = @file_get_contents($tmp_count);
    $data_raw  = @file_get_contents($tmp_data);
    @unlink($tmp_count);
    @unlink($tmp_data);

    $count_rows = json_decode($count_raw, true) ?: [];
    $total      = $count_rows[0]['total'] ?? 0;

    $data_rows = json_decode($data_raw, true) ?: [];

    return ['ok' => true, 'total' => $total, 'rows' => $data_rows];
}


function _output_csv(array $rows, string $date_from, string $date_to): void {
    $filename = "opensiem_archive_{$date_from}_to_{$date_to}.csv";
    header('Content-Type: text/csv');
    header("Content-Disposition: attachment; filename=\"{$filename}\"");

    $out = fopen('php://output', 'w');
    if (!empty($rows)) {
        fputcsv($out, array_keys($rows[0]));
        foreach ($rows as $row) {
            fputcsv($out, $row);
        }
    }
    fclose($out);
}
