<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__.'/../config/auth.php';
require_login();
require_perm('update');
require_csrf();

$in = json_decode(file_get_contents('php://input'), true) ?: [];
$id = (int)($in['id'] ?? 0);
if ($id) {
  $stmt = pdo()->prepare("UPDATE alerts SET is_active=false, acknowledged_time=NOW() WHERE id=:id");
  $stmt->execute([':id'=>$id]);
}
json_out(['ok'=>true]);
