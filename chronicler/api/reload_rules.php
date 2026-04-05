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

$ch = curl_init('http://127.0.0.1:51808/reload');
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_TIMEOUT => 3,
]);
$resp = curl_exec($ch);
$err  = curl_error($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
if ($err || $code !== 200) {
  json_out(['ok'=>false, 'error'=>$err ?: "HTTP $code"], 500);
}
echo $resp ?: json_encode(['ok'=>true]);
