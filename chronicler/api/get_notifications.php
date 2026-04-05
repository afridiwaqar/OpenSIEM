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

$stmtC = pdo()->query("SELECT COUNT(*)::int AS c FROM alerts WHERE is_active=true");
$count = (int)$stmtC->fetch(PDO::FETCH_ASSOC)['c'];

$stmt = pdo()->query("
  SELECT id, alert_id, alert_type, severity, source_ip, admin_note
  FROM alerts
  WHERE is_active=true
  ORDER BY id DESC
  LIMIT 10
");
$items = $stmt->fetchAll(PDO::FETCH_ASSOC);

json_out(['ok'=>true, 'count'=>$count, 'items'=>$items]);
