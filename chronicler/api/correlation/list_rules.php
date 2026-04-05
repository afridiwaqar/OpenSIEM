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

$sqlUC = "SELECT case_id, case_name, entity_field FROM use_cases ORDER BY case_id ASC";
$ucs = pdo()->query($sqlUC)->fetchAll(PDO::FETCH_ASSOC);

$sqlSM = 'SELECT case_id_fk, msg_id, message, can_repeat, "order" FROM special_messages ORDER BY case_id_fk ASC, msg_id ASC';
$sms = pdo()->query($sqlSM)->fetchAll(PDO::FETCH_ASSOC);

$byCase = [];
foreach ($ucs as $u) { $u['rules']=[]; $byCase[$u['case_id']]=$u; }
foreach ($sms as $r) {
  $cid = (int)$r['case_id_fk'];
  if (isset($byCase[$cid])) $byCase[$cid]['rules'][] = [
    'msg_id'=>(int)$r['msg_id'],
    'message'=>$r['message'],
    'can_repeat'=> (bool)$r['can_repeat'],
    'order'=> (bool)$r['order']
  ];
}
json_out(array_values($byCase));
