<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
require_login(); require_perm('read');

$id = intval($_GET['id'] ?? 0);
if (!$id) json_out(['ok'=>false,'error'=>'missing id'], 400);

$db = pdo();

$st = $db->prepare("
  SELECT id, alert_id, alert_type, severity, is_active, count,
         source_ip, acknowledged_time, admin_note, fk_msg_id
  FROM alerts
  WHERE id = :id
  LIMIT 1
");
$st->execute([':id'=>$id]);
$alert = $st->fetch(PDO::FETCH_ASSOC);
if (!$alert) json_out(['ok'=>false,'error'=>'not found'], 404);

$st2 = $db->prepare("
  SELECT ao.occurred_at,
         ao.fk_msg_id,
         ao.source_ip,
         ao.details,
         m.message AS message_text
  FROM alert_occurrences ao
  LEFT JOIN message m ON m.message_id = ao.fk_msg_id
  WHERE ao.alert_id_fk = :id
  ORDER BY ao.occurred_at ASC
");
$st2->execute([':id'=>$id]);
$occ_raw = $st2->fetchAll(PDO::FETCH_ASSOC);

$trail = [];
foreach ($occ_raw as $row) {
  $text = $row['message_text'];
  if (!$text) {
    $raw = $row['details'];
    if ($raw) {
      try {
        $j = json_decode($raw, true);
        $text = $j['raw_line'] ?? null;
      } catch (Throwable $e) { /* ignore */ }
    }
  }
  $trail[] = [
    'occurred_at' => $row['occurred_at'],
    'text'        => $text ?: null,
    'fk_msg_id'   => $row['fk_msg_id'],
    'source_ip'   => $row['source_ip']
  ];
}

json_out(['ok'=>true, 'alert'=>$alert, 'occurrences'=>$trail]);
