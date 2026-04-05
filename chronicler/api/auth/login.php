<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
$in = json_decode(file_get_contents('php://input'), true) ?: [];
$id  = trim($in['id'] ?? '');       // username OR email
$pwd = (string)($in['password'] ?? '');
if ($id === '' || $pwd === '') json_out(['ok'=>false, 'error'=>'id/password required'], 400);

list($ok, $err) = login_user($id, $pwd);
if (!$ok) json_out(['ok'=>false, 'error'=>$err], 401);

json_out([
  'ok'=>true,
  'user'=>current_user(),
  'permissions'=>$_SESSION['permissions'],
  'csrf'=>csrf_token(),
]);
