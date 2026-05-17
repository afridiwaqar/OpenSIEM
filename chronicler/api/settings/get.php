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

$confPath = '/etc/opensiem/opensiem.conf';

if (!file_exists($confPath)) {
    json_out(['ok'=>false,'error'=>'Config file not found: '.$confPath]);
    return;
}

$raw     = file($confPath, FILE_IGNORE_NEW_LINES);
$result  = [];
$section = null;

foreach ($raw as $line) {
    $trimmed = trim($line);
    if ($trimmed === '' || str_starts_with($trimmed, '#')) continue;

    if (preg_match('/^\[([^\]]+)\]$/', $trimmed, $m)) {
        $section = strtolower($m[1]);
        if (!isset($result[$section])) $result[$section] = [];
        continue;
    }

    if ($section !== null && preg_match('/^([^=]+)=(.*)$/', $trimmed, $m)) {
        $key = trim($m[1]);
        $val = trim($m[2]);
        $val = trim($val, '"\'');
        if (preg_match('/^(.*?)\s+#/', $val, $cm)) $val = rtrim($cm[1]);
        $result[$section][$key] = $val;
    }
}

json_out(['ok'=>true] + $result);
