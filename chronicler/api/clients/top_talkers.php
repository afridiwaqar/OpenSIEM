<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
require_login(); require_perm('read');

$path = '/etc/opensiem/stats/socket_clients.xml';
if (!is_readable($path)) json_out([]);

$xml = @simplexml_load_file($path);
$out = [];
if ($xml && isset($xml->Client)) {
  foreach ($xml->Client as $cl) {
    $out[] = [
      'address'  => (string)$cl->Address,
      'messages' => (int)$cl->Messages,
      'bytes'    => (int)$cl->Bytes
    ];
  }
  usort($out, fn($a,$b)=>$b['messages']<=>$a['messages']);
  $out = array_slice($out, 0, 20);
}
json_out($out);
