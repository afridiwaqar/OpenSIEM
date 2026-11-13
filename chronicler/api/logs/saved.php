<?php
// /var/www/chronicler/api/logs/saved.php
// Saved searches, per user, optionally shared with the whole team.
//   GET                          -> own searches + shared ones
//   POST {action:"save", name, definition, shared}   (CSRF token required)
//   POST {action:"delete", id}                       (owner or admin only)
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/_lib.php';

require_login();
require_perm('read');
header('Content-Type: application/json');

$db  = pdo();
$me  = current_user();
$uid = (int)($me['user_id'] ?? 0);
if ($uid <= 0) json_fail(401, 'No user in session');

// Keep only the keys the Logs page understands; bound every length.
function clean_definition($d): array {
    if (!is_array($d)) json_fail(400, 'definition must be an object');
    $str = fn($v, $n) => substr(trim((string)($v ?? '')), 0, $n);
    $out = [
        'system' => $str($d['system'] ?? '', 64),
        'range'  => isset(RANGE_PRESETS[$d['range'] ?? '']) ? $d['range'] : 'custom',
        'from'   => $str($d['from'] ?? '', 32),
        'to'     => $str($d['to'] ?? '', 32),
        'logic'  => strtoupper($d['logic'] ?? 'AND') === 'OR' ? 'OR' : 'AND',
        'q'      => $str($d['q'] ?? '', 200),
        'qmode'  => in_array($d['qmode'] ?? '', ['contains', 'regex', 'regex_i'], true) ? $d['qmode'] : 'contains',
        'filters' => [],
    ];
    $f = $d['filters'] ?? [];
    if (!is_array($f) || count($f) > 10) json_fail(400, 'definition has too many filters');
    foreach ($f as $row) {
        if (!is_array($row)) continue;
        $out['filters'][] = ['f' => $str($row['f'] ?? '', 20), 'op' => $str($row['op'] ?? '', 20), 'v' => $str($row['v'] ?? '', 200)];
    }
    return $out;
}

try {
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $st = $db->prepare("SELECT s.id, s.name, s.definition, s.shared, s.user_id, l.username AS owner
                              FROM saved_searches s JOIN login l ON l.user_id = s.user_id
                             WHERE s.user_id = :u OR s.shared = true
                             ORDER BY (s.user_id = :u) DESC, lower(s.name)");
        $st->execute([':u' => $uid]);
        $rows = array_map(fn($r) => [
            'id' => (int)$r['id'], 'name' => $r['name'],
            'definition' => json_decode($r['definition'], true),
            'shared' => (bool)$r['shared'], 'owner' => $r['owner'],
            'mine' => ((int)$r['user_id'] === $uid),
        ], $st->fetchAll(PDO::FETCH_ASSOC));
        echo json_encode(['ok' => true, 'searches' => $rows]);
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_fail(405, 'Method not allowed');
    require_csrf();
    $in = json_decode(file_get_contents('php://input'), true) ?: [];

    switch ($in['action'] ?? '') {
        case 'save':
            $name = substr(trim((string)($in['name'] ?? '')), 0, 80);
            if ($name === '') json_fail(400, 'Give the search a name');
            $def = clean_definition($in['definition'] ?? null);
            $st = $db->prepare("INSERT INTO saved_searches (user_id, name, definition, shared)
                                VALUES (:u, :n, CAST(:d AS jsonb), :s)
                                ON CONFLICT (user_id, name)
                                DO UPDATE SET definition = EXCLUDED.definition, shared = EXCLUDED.shared
                                RETURNING id");
            $st->bindValue(':u', $uid, PDO::PARAM_INT);
            $st->bindValue(':n', $name);
            $st->bindValue(':d', json_encode($def));
            $st->bindValue(':s', !empty($in['shared']), PDO::PARAM_BOOL);
            $st->execute();
            echo json_encode(['ok' => true, 'id' => (int)$st->fetchColumn()]);
            break;

        case 'delete':
            $id = (int)($in['id'] ?? 0);
            $isAdmin = (($me['role'] ?? '') === 'admin');
            $st = $db->prepare("DELETE FROM saved_searches WHERE id = :id AND (user_id = :u OR :a)");
            $st->bindValue(':id', $id, PDO::PARAM_INT);
            $st->bindValue(':u', $uid, PDO::PARAM_INT);
            $st->bindValue(':a', $isAdmin, PDO::PARAM_BOOL);
            $st->execute();
            echo json_encode(['ok' => true, 'deleted' => $st->rowCount()]);
            break;

        default:
            json_fail(400, 'Unknown action');
    }
} catch (PDOException $e) {
    if ($e->getCode() === '42P01') {
        json_fail(500, 'Saved searches are not set up yet. Run logs_search_migration.sql.');
    }
    json_fail(500, $e->getMessage());
}
