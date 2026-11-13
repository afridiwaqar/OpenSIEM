<?php
// /var/www/chronicler/api/logs/search.php
// Advanced log search. GET parameters:
//   range      15m | 1h | 6h | 24h | 7d | 30d      (or from + to, server time)
//   filters    JSON array of {f, op, v}              (see _lib.php filter_fields)
//   logic      AND | OR   (how the filter rows combine; default AND)
//   system     exact IP; always ANDed with the filters (system drill-down)
//   must       JSON array of filters that are ALWAYS ANDed (the quick-search box)
//   limit      rows per page (10-500, default 100)
//   before     opaque cursor from the previous page (next_before)
//   count=1    also return a capped match count (first page only)
//   format     json (default) | csv   (csv = up to 5000 rows, download)
require_once __DIR__ . '/../../config/auth.php';
require_once __DIR__ . '/../../config/db.php';
require_once __DIR__ . '/_lib.php';

require_login();
require_perm('read');

$db  = pdo();
$fmt = ($_GET['format'] ?? 'json') === 'csv' ? 'csv' : 'json';
if ($fmt === 'json') header('Content-Type: application/json');

$limit  = $fmt === 'csv' ? 5000 : min(500, max(10, (int)($_GET['limit'] ?? 100)));
$before = trim((string)($_GET['before'] ?? ''));          // opaque cursor from the previous page
$logic  = strtoupper($_GET['logic'] ?? 'AND') === 'OR' ? 'OR' : 'AND';
$system = trim($_GET['system'] ?? '');

$filters = [];
if (!empty($_GET['filters'])) {
    $filters = json_decode($_GET['filters'], true);
    if (!is_array($filters)) json_fail(400, 'filters must be a JSON array');
}
$must = [];
if (!empty($_GET['must'])) {
    $must = json_decode($_GET['must'], true);
    if (!is_array($must)) json_fail(400, 'must must be a JSON array');
    if (count($must) > 5) json_fail(400, 'Too many quick filters (max 5)');
}

try {
    // Safety net: an unbounded search must never be able to hang the server again.
    $db->exec("SET statement_timeout = 20000");

    // Validate any regex up front (cheap), so a bad pattern is reported even
    // when the chosen time window happens to contain no logs.
    foreach (array_merge($must, $filters) as $f) {
        if (is_array($f) && in_array($f['op'] ?? '', ['regex', 'regex_i'], true) && isset($f['v'])) {
            $db->prepare("SELECT '' ~ :p")->execute([':p' => (string)$f['v']]);
        }
    }

    $range = resolve_range($db, $_GET);
    $out = ['ok' => true, 'rows' => [], 'has_more' => false, 'next_before' => null,
            'range' => ['from' => $range['from'], 'to' => $range['to'],
                        'server_time' => $range['server_time'],
                        'beyond_hot' => $range['beyond_hot'], 'hot_days' => $range['hot_days']]];

    // Two branches, merged by time:
    //   A  live rows      (positive calendar ids): fast id-range scan, newest first
    //   B  restored rows  (negative calendar ids): found by exact timestamp
    // Restored rows get new ids, so they cannot be located by an id range. Searching them separately
    // is what keeps the results complete after a rehydration.
    $liveOk = ($range['lo'] !== null && $range['hi'] !== null && $range['lo'] <= $range['hi']);
    $tsFrom = ts_literal($range['from']);
    $tsTo   = ts_literal($range['to']);

    // opaque cursor: "<live cal id>|<restored ts>|<restored cal id>"
    $curL = 0; $curRts = ''; $curRid = 0;
    if ($before !== '') {
        $pp = explode('|', $before, 3);
        $curL   = ctype_digit($pp[0] ?? '') ? (int)$pp[0] : 0;
        $curRts = $pp[1] ?? '';
        $curRid = isset($pp[2]) && preg_match('/^-?\d+$/', $pp[2]) ? (int)$pp[2] : 0;
        if ($curRts !== '') $curRtsLit = ts_literal($curRts);
    }

    // shared conditions, built once per branch (PDO cannot reuse a named parameter in one statement)
    $params = [];
    $condA = []; $condB = [];
    if ($system !== '') { $condA[] = 'd.device_ip = :sysa'; $condB[] = 'd.device_ip = :sysb'; $params[':sysa'] = $params[':sysb'] = $system; }
    foreach (['a' => &$condA, 'b' => &$condB] as $k => &$cond) {
        $mw = build_filters($must,    'AND',  $params, "m$k");  if ($mw) $cond[] = $mw;
        $fw = build_filters($filters, $logic, $params, "p$k");  if ($fw) $cond[] = $fw;
    }
    unset($cond);

    $whereA = array_merge([$liveOk ? "m.date BETWEEN {$range['lo']} AND {$range['hi']}" : 'FALSE'],
                          $curL ? ["m.date < $curL"] : [], $condA);
    $whereB = array_merge(['m.date < 0', "(c.date + c.\"time\") BETWEEN $tsFrom AND $tsTo"],
                          $curRts !== '' ? ["((c.date + c.\"time\") < $curRtsLit OR ((c.date + c.\"time\") = $curRtsLit AND m.date < $curRid))"] : [],
                          $condB);
    $lim = $limit + 1;
    $sqlA = '(' . log_select() . ' WHERE ' . implode(' AND ', $whereA) . " ORDER BY m.date DESC LIMIT $lim)";
    $sqlB = '(' . log_select() . ' WHERE ' . implode(' AND ', $whereB) . " ORDER BY (c.date + c.\"time\") DESC, m.date DESC LIMIT $lim)";
    $sql  = "SELECT * FROM ($sqlA UNION ALL $sqlB) u ORDER BY u.ts DESC, u.cal_id DESC LIMIT $lim";

    $st = $db->prepare($sql);
    $st->execute($params);
    $raw = $st->fetchAll(PDO::FETCH_ASSOC);

    $has_more = count($raw) > $limit;
    if ($has_more) array_pop($raw);
    $rows = array_map('fmt_row', $raw);

    if ($fmt === 'csv') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="opensiem_logs_' . date('Ymd_His') . '.csv"');
        $o = fopen('php://output', 'w');
        $safe = fn($v) => (is_string($v) && $v !== '' && strpos("=+-@\t\r", $v[0]) !== false) ? "'" . $v : $v;
        fputcsv($o, ['time', 'ip', 'host', 'source', 'process', 'severity', 'message'], ',', '"', '');
        foreach ($rows as $r) {
            fputcsv($o, array_map($safe, [$r['ts'], $r['ip'], $r['host'], $r['source'],
                                          $r['process'], $r['sev'], $r['message']]), ',', '"', '');
        }
        fclose($o);
        exit;
    }

    // next cursor: each branch resumes where this page stopped consuming it
    $nL = $curL; $nRts = $curRts; $nRid = $curRid;
    foreach ($rows as $r) {
        if ($r['re']) { $nRts = $r['ts']; $nRid = $r['cur']; }
        else          { $nL = $r['cur']; }
    }
    $out['rows']        = $rows;
    $out['has_more']    = $has_more;
    $out['next_before'] = $has_more ? "$nL|$nRts|$nRid" : null;

    if (!empty($_GET['count']) && $before === '') {
        $fromJoin = LOG_FROM . ' JOIN calendar c ON c.data_id = m.date';
        $cA = 'SELECT 1' . $fromJoin . ' WHERE ' . implode(' AND ', array_merge([$liveOk ? "m.date BETWEEN {$range['lo']} AND {$range['hi']}" : 'FALSE'], $condA)) . ' LIMIT 10001';
        $cB = 'SELECT 1' . $fromJoin . ' WHERE ' . implode(' AND ', array_merge(['m.date < 0', "(c.date + c.\"time\") BETWEEN $tsFrom AND $tsTo"], $condB)) . ' LIMIT 10001';
        $cs = $db->prepare("SELECT (SELECT count(*) FROM ($cA) a) + (SELECT count(*) FROM ($cB) b)");
        $cs->execute($params);
        $n = (int)$cs->fetchColumn();
        $out['count'] = ['n' => min($n, 10000), 'capped' => $n > 10000];
    }
    echo json_encode($out);

} catch (PDOException $e) {
    if ($e->getCode() === '2201B') {   // invalid_regular_expression
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Invalid regular expression: ' . preg_replace('/^invalid regular expression:\s*/i', '', preg_replace('/^.*ERROR:\s*/s', '', $e->getMessage()))]);
    } elseif ($e->getCode() === '57014') {   // query_canceled by statement_timeout
        http_response_code(408);
        echo json_encode(['ok' => false, 'timeout' => true,
            'error' => 'The search took too long and was stopped. Narrow the time range or add a more specific filter (for example a system or an IP).']);
    } else {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
}
