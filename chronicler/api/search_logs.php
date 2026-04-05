<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../config/auth.php';
require_login();
require_perm('read');

$in    = json_decode(file_get_contents('php://input'), true) ?: [];
$q     = trim($in['q']     ?? '');
$regex = !empty($in['regex']);
$flags = trim($in['flags'] ?? '');

if ($q === '') {
    json_out(['ok' => true, 'results' => []]);
    return;
}

$db = pdo();

try {
    if ($regex) {
        $caseInsensitive = str_contains($flags, 'i');
        $op  = $caseInsensitive ? '~*' : '~';

        $stmt = $db->prepare(
            "SELECT message_id, message
               FROM message
              WHERE message $op :q
              ORDER BY message_id DESC
              LIMIT 300"
        );
        $stmt->execute([':q' => $q]);
    } else {
        $useIlike = (
            preg_match('/^[\d.:\-\/\\\\]+$/', $q) ||
            strlen($q) < 4
        );

        if ($useIlike) {
            $stmt = $db->prepare(
                "SELECT message_id, message
                   FROM message
                  WHERE message ILIKE :q
                  ORDER BY message_id DESC
                  LIMIT 300"
            );
            $stmt->execute([':q' => '%' . $q . '%']);
        } else {
            $stmt = $db->prepare(
                "SELECT message_id, message
                   FROM message
                  WHERE to_tsvector('english', message) @@ plainto_tsquery('english', :q)
                  ORDER BY message_id DESC
                  LIMIT 300"
            );
            $stmt->execute([':q' => $q]);
        }
    }

    $rows    = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $results = [];

    foreach ($rows as $r) {
        $txt   = $r['message'] ?? '';
        $level = 'info';
        if (stripos($txt, 'critical') !== false)                                      $level = 'critical';
        elseif (stripos($txt, 'error') !== false || stripos($txt, 'failed') !== false) $level = 'high';
        elseif (stripos($txt, 'warning') !== false || stripos($txt, 'brute') !== false) $level = 'mid';
        $results[] = ['id' => $r['message_id'], 'text' => $txt, 'level' => $level];
    }

    json_out(['ok' => true, 'results' => $results]);

} catch (Throwable $e) {
    $msg = $e->getMessage();
    $msg = strtok($msg, "\n");
    json_out(['ok' => false, 'error' => 'Query error: ' . $msg]);
}
