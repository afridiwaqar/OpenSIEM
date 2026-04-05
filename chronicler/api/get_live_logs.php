<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__.'/../config/auth.php';
require_login();
require_perm('read');

$since = isset($_GET['since']) ? (int)$_GET['since'] : 0;
$db = pdo();

if ($since > 0) {
  $stmt = $db->prepare("
    SELECT message_id, message
    FROM message
    WHERE message_id > :since
    ORDER BY message_id ASC
    LIMIT 200
  ");
  $stmt->execute([':since'=>$since]);
} else {
  // First load: return the latest 200 rows (ascending)
  $stmt = $db->query("
    SELECT message_id, message
    FROM (
      SELECT message_id, message
      FROM message
      ORDER BY message_id DESC
      LIMIT 200
    ) t
    ORDER BY message_id ASC
  ");
}
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$logs = [];
foreach ($rows as $r) {
  $level = 'info';
  $txt = $r['message'] ?? '';
  if (stripos($txt,'critical')!==false) $level='critical';
  else if (stripos($txt,'error')!==false || stripos($txt,'failed')!==false) $level='high';
  else if (stripos($txt,'warning')!==false || stripos($txt,'brute')!==false) $level='mid';
  $logs[] = ['ts'=>$r['message_id'], 'text'=>$txt, 'level'=>$level];
}
json_out(['logs'=>$logs]);
