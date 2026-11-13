<?php
// /var/www/chronicler/api/logs/_lib.php
// Shared helpers for /api/logs/*.  This file is an include, not an endpoint.

// ---------------------------------------------------------------------------
// Severity is NOT stored in the database. It is estimated from keywords in the
// message text. The same list drives the severity FILTER (SQL) and the
// severity BADGE (PHP), so the two can never disagree. Edit the list here.
// Order matters: the first matching level wins.
// ---------------------------------------------------------------------------
const LOG_SEVERITY_KEYWORDS = [
    'critical' => ['critical', 'fatal', 'panic', 'emergency'],
    'high'     => ['error', 'failed', 'failure', 'denied', 'unauthorized'],
    'mid'      => ['warn', 'refused', 'invalid user', 'timeout', 'timed out'],
];
const LOG_SEVERITY_LEVELS = ['critical', 'high', 'mid', 'info'];

function sev_of(string $text): string {
    $t = strtolower($text);
    foreach (LOG_SEVERITY_KEYWORDS as $level => $words) {
        foreach ($words as $w) {
            if (strpos($t, $w) !== false) return $level;
        }
    }
    return 'info';
}

// SQL CASE expression equivalent to sev_of(). Keywords are constants above
// (never user input), so inlining them is safe.
function sev_case_sql(string $col = 'm.message'): string {
    $parts = [];
    foreach (LOG_SEVERITY_KEYWORDS as $level => $words) {
        $likes = array_map(fn($w) => "$col ILIKE '%" . str_replace("'", "''", $w) . "%'", $words);
        $parts[] = "WHEN (" . implode(' OR ', $likes) . ") THEN '$level'";
    }
    return "(CASE " . implode(' ', $parts) . " ELSE 'info' END)";
}

// message.message holds JSON like {"message": "text"}. Return the plain text.
function decode_message(?string $raw): string {
    if ($raw === null) return '';
    if ($raw !== '' && $raw[0] === '{') {
        $j = json_decode($raw, true);
        if (is_array($j) && isset($j['message']) && is_string($j['message'])) return $j['message'];
    }
    return $raw;
}

// Rehydrated (restored-from-archive) log lines are stored with NEGATIVE calendar ids, live lines with
// positive ones. That keeps the fast id-range search sound for live data and lets restored rows be
// found separately by exact timestamp. See rehydration_marker_migration.sql.
function is_rehydrated_cal_id($id): bool { return $id !== null && (int)$id < 0; }

function fmt_row(array $r): array {
    $text = decode_message($r['message'] ?? '');
    return [
        'id'      => (int)$r['message_id'],
        'cur'     => isset($r['cal_id']) ? (int)$r['cal_id'] : null,
        'ts'      => trim(($r['date'] ?? '') . ' ' . substr((string)($r['time'] ?? ''), 0, 8)),
        'ip'      => $r['device_ip']    ?? '',
        'host'    => $r['device_name']  ?? '',
        'source'  => $r['source_name']  ?? '',
        'process' => $r['process_name'] ?? '',
        'pid'     => isset($r['pid']) ? (int)$r['pid'] : null,
        'sev'     => sev_of($text),
        'message' => $text,
        're'      => isset($r['cal_id']) && (int)$r['cal_id'] < 0,   // restored from the archive, not live
    ];
}

function json_fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}

function hot_retention_days(PDO $db): int {
    try {
        $v = $db->query("SELECT hot_retention_days FROM archive_policy WHERE id = 1")->fetchColumn();
        return $v ? (int)$v : 90;
    } catch (Exception $e) { return 90; }
}

// ---------------------------------------------------------------------------
// Time range -> calendar.data_id bounds.
// calendar rows are written at INGEST time and data_id only grows, so a time
// range can be turned into an id range using the existing (date + time)
// expression index. message.date is the calendar data_id, so the main query
// can then range-scan idx_message_date instead of touching 236M rows.
// ---------------------------------------------------------------------------
const RANGE_PRESETS = ['15m' => '15 minutes', '1h' => '1 hour', '6h' => '6 hours',
                       '24h' => '24 hours',   '7d' => '7 days', '30d' => '30 days'];

function resolve_range(PDO $db, array $q): array {
    $now = $db->query("SELECT now()::timestamp(0)")->fetchColumn();
    $preset = $q['range'] ?? '';
    if ($preset !== '' && isset(RANGE_PRESETS[$preset])) {
        $from = $db->query("SELECT (now() - interval '" . RANGE_PRESETS[$preset] . "')::timestamp(0)")->fetchColumn();
        $to   = $now;
    } elseif (!empty($q['from']) && !empty($q['to'])) {
        try {
            $from = (new DateTime($q['from']))->format('Y-m-d H:i:s');
            $to   = (new DateTime($q['to']))->format('Y-m-d H:i:s');
        } catch (Exception $e) { json_fail(400, 'Invalid from/to date'); }
        if ($from > $to) json_fail(400, 'Start time is after end time');
    } else {
        json_fail(400, 'A time range is required (range preset, or from and to)');
    }
    $hot    = hot_retention_days($db);
    $cutoff = $db->query("SELECT (now() - interval '$hot days')::timestamp(0)")->fetchColumn();
    if ($from < $cutoff) {
        // cap at 90 days of span as a safety net; the statement timeout is the real guard
    }
    $st = $db->prepare(
        'SELECT (SELECT data_id FROM calendar WHERE data_id > 0 AND (date + "time") >= CAST(:f AS timestamp)
                  ORDER BY (date + "time") ASC  LIMIT 1) AS lo,
                (SELECT data_id FROM calendar WHERE data_id > 0 AND (date + "time") <= CAST(:t AS timestamp)
                  ORDER BY (date + "time") DESC LIMIT 1) AS hi');
    $st->execute([':f' => $from, ':t' => $to]);
    $b = $st->fetch(PDO::FETCH_ASSOC);
    return [
        'from' => $from, 'to' => $to, 'server_time' => $now,
        'lo' => $b['lo'] !== null ? (int)$b['lo'] : null,
        'hi' => $b['hi'] !== null ? (int)$b['hi'] : null,
        'beyond_hot' => ($from < $cutoff), 'hot_days' => $hot,
    ];
}

// ---------------------------------------------------------------------------
// Filter builder.  Each filter is {f: field, op: operator, v: value}.
// Everything is whitelisted; values are always bound as parameters.
// ---------------------------------------------------------------------------
function filter_fields(): array {
    return [
        'ip'       => ['expr' => 'd.device_ip',   'ops' => ['is', 'is_not', 'starts_with']],
        'hostname' => ['expr' => 'd.device_name', 'ops' => ['is', 'is_not', 'contains', 'not_contains']],
        'source'   => ['expr' => 'ls.source_name','ops' => ['is', 'is_not', 'contains', 'not_contains']],
        'process'  => ['expr' => 'p.process_name','ops' => ['is', 'is_not', 'contains', 'not_contains']],
        'message'  => ['expr' => 'm.message',     'ops' => ['contains', 'not_contains', 'regex', 'regex_i']],
        'severity' => ['expr' => sev_case_sql(),  'ops' => ['is', 'is_not']],
    ];
}

function like_escape(string $v): string {
    return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $v);
}

function build_filters(array $filters, string $logic, array &$params, string $prefix = 'p'): string {
    if (!$filters) return '';
    if (count($filters) > 10) json_fail(400, 'Too many filters (max 10)');
    $fields = filter_fields();
    $parts  = [];
    foreach ($filters as $i => $f) {
        $field = $f['f'] ?? '';
        $op    = $f['op'] ?? '';
        $val   = isset($f['v']) ? trim((string)$f['v']) : '';
        if (!isset($fields[$field]))              json_fail(400, "Unknown filter field: $field");
        if (!in_array($op, $fields[$field]['ops'], true)) json_fail(400, "Operator '$op' not valid for $field");
        if ($val === '')                          json_fail(400, "Filter " . ($i + 1) . " ($field) has no value");
        if (strlen($val) > 200)                   json_fail(400, "Filter value too long");
        $e = $fields[$field]['expr'];
        $k = ":{$prefix}$i";
        if ($field === 'severity') {
            if (!in_array($val, LOG_SEVERITY_LEVELS, true)) json_fail(400, "Unknown severity: $val");
            $parts[] = $op === 'is' ? "$e = $k" : "$e <> $k";
            $params[$k] = $val;
            continue;
        }
        switch ($op) {
            case 'is':           $parts[] = "$e = $k";                          $params[$k] = $val; break;
            case 'is_not':       $parts[] = "$e IS DISTINCT FROM $k";           $params[$k] = $val; break;
            case 'starts_with':  $parts[] = "$e LIKE $k";                       $params[$k] = like_escape($val) . '%'; break;
            case 'contains':     $parts[] = "$e ILIKE $k";                      $params[$k] = '%' . like_escape($val) . '%'; break;
            case 'not_contains': $parts[] = "($e IS NULL OR $e NOT ILIKE $k)";  $params[$k] = '%' . like_escape($val) . '%'; break;
            // Regex runs against the STORED text, which is JSON ({"message": "..."}), so ^ and $ match the wrapper.
            case 'regex':        $parts[] = "$e ~ $k";                        $params[$k] = $val; break;
            case 'regex_i':      $parts[] = "$e ~* $k";                       $params[$k] = $val; break;
        }
    }
    $glue = strtoupper($logic) === 'OR' ? ' OR ' : ' AND ';
    return '(' . implode($glue, $parts) . ')';
}

const LOG_FROM =
    ' FROM message m
       JOIN device d   ON d.device_id = m.device_id
  LEFT JOIN process p  ON p.process_id = m.process_id
  LEFT JOIN "Log_Source" ls ON ls.source_id = m.log_source';

// Column list + joins (the timestamp is always selected).
function log_select(): string {
    return 'SELECT m.message_id, m.date AS cal_id, m.message, d.device_ip, d.device_name,
            p.process_name, p.pid, ls.source_name, c.date, c."time", (c.date + c."time") AS ts'
        . LOG_FROM . '
       JOIN calendar c ON c.data_id = m.date';
}
// kept for live.php, which only ever needs the plain live columns
const LOG_SELECT =
    'SELECT m.message_id, m.date AS cal_id, m.message, d.device_ip, d.device_name,
            p.process_name, p.pid, ls.source_name, c.date, c."time"'
    . LOG_FROM . '
       JOIN calendar c ON c.data_id = m.date';

function ts_literal(string $s): string {          // strictly validated before it is ever inlined into SQL
    if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $s)) json_fail(400, 'Invalid timestamp');
    return "CAST('$s' AS timestamp)";
}
