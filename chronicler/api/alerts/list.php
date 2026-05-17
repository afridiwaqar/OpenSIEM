<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
require_login();
require_perm('read');

$page      = max(1, intval($_GET['page'] ?? 1));
$per_page  = max(10, min(200, intval($_GET['per_page'] ?? 50)));
$offset    = ($page - 1) * $per_page;

$severity  = $_GET['severity']   ?? '';  // '' or 'low'/'mid'/'high'/'critical'
$type      = $_GET['type']       ?? '';  // '' or 'correlation'/'artifact'/etc
$active    = $_GET['active']     ?? '';  // '' or 'true'/'false'
$search    = trim($_GET['q']     ?? '');
$hours     = intval($_GET['hours'] ?? 0); // Last N hours

$where = [];
$args = [];

if ($severity !== '') {
    $where[] = "a.severity = :severity";
    $args[':severity'] = $severity;
}
if ($type !== '') {
    $where[] = "a.alert_type = :type";
    $args[':type'] = $type;
}
if ($active === 'true')  { $where[] = "a.is_active = true";  }
if ($active === 'false') { $where[] = "a.is_active = false"; }

if ($hours > 0) {
    $where[] = "a.id IN (SELECT alert_id_fk FROM alert_occurrences WHERE occurred_at >= NOW() - INTERVAL '$hours hours')";
}

if ($search !== '') {
    $where[] = "(a.source_ip::text ILIKE :q OR a.admin_note ILIKE :q)";
    $args[':q'] = "%$search%";
}

$where_sql = $where ? ("WHERE " . implode(" AND ", $where)) : "";

$db = pdo();
$count = $db->prepare("SELECT COUNT(*) FROM alerts a $where_sql");
$count->execute($args);
$total = (int)$count->fetchColumn();

$sql = "
  SELECT a.id, a.alert_id, a.alert_type, a.severity, a.is_active, a.count,
         a.source_ip, a.admin_note, a.acknowledged_time,
         COALESCE((SELECT MAX(occurred_at) FROM alert_occurrences WHERE alert_id_fk=a.id), NULL) AS last_seen
  FROM alerts a
  $where_sql
  ORDER BY a.id DESC
  LIMIT :limit OFFSET :offset
";
$st = $db->prepare($sql);
foreach ($args as $k => $v) $st->bindValue($k, $v);
$st->bindValue(':limit', $per_page, PDO::PARAM_INT);
$st->bindValue(':offset', $offset, PDO::PARAM_INT);
$st->execute();
$rows = $st->fetchAll(PDO::FETCH_ASSOC);

json_out([
  'ok' => true,
  'page' => $page,
  'per_page' => $per_page,
  'total' => $total,
  'alerts' => $rows
]);
