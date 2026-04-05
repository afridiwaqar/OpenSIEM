<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__.'/../../config/auth.php';
require_login();
require_perm('read');

$stmt = pdo()->prepare("
  SELECT a.id, a.alert_id, a.alert_type, a.severity, a.is_active, a.count,
         a.source_ip, a.admin_note, a.acknowledged_time,
         (SELECT MAX(occurred_at) FROM alert_occurrences ao WHERE ao.alert_id_fk = a.id) AS last_seen
  FROM alerts a
  WHERE a.alert_type='correlation'
  ORDER BY a.id DESC
  LIMIT 200
");
$stmt->execute();
json_out($stmt->fetchAll(PDO::FETCH_ASSOC));

