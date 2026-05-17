<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
require_login();
require_csrf();

// Admin only
$u = current_user();
if (($u['role'] ?? '') !== 'admin') json_out(['ok'=>false,'error'=>'admin only']);

$in      = json_decode(file_get_contents('php://input'), true) ?: [];
$section = trim($in['section'] ?? '');
$values  = $in['values']  ?? [];

if (!$section || !is_array($values)) json_out(['ok'=>false,'error'=>'section and values required']);

$confPath = '/etc/opensiem/opensiem.conf';
$bakPath  = $confPath . '.bak';

if (!file_exists($confPath)) json_out(['ok'=>false,'error'=>'Config file not found: '.$confPath]);

$raw     = file($confPath, FILE_IGNORE_NEW_LINES);
$sections = [];
$order   = [];
$current = null;

foreach ($raw as $line) {
    $trimmed = trim($line);
    if (preg_match('/^\[([^\]]+)\]$/', $trimmed, $m)) {
        $current = strtolower($m[1]);
        if (!isset($sections[$current])) {
            $sections[$current] = ['lines' => [], 'order' => count($order)];
            $order[] = $current;
        }
    } elseif ($current !== null) {
        $sections[$current]['lines'][] = $line;
    }
}

function build_section_lines(array $values, string $section, array $existingLines): array {
    $existing = [];
    $parsed   = [];

    foreach ($existingLines as $i => $line) {
        $t = trim($line);
        if ($t === '' || str_starts_with($t, '#')) continue;
        if (preg_match('/^([^=]+)=(.*)$/', $t, $m)) {
            $k = trim($m[1]);
            $existing[$k] = $i;
            $parsed[$k]   = trim($m[2], " \t\"'");
        }
    }

    $lines = $existingLines;

    foreach ($values as $key => $val) {
        if ($val === null) continue;

        $val = (string)$val;

        if (isset($existing[$key])) {
            $origLine = $lines[$existing[$key]];
            $comment = '';
            if (preg_match('/\s+(#.*)$/', $origLine, $cm)) $comment = '  ' . $cm[1];
            $lines[$existing[$key]] = "$key = $val$comment";
        } else {
            $lines[] = "$key = $val";
        }
    }

    return $lines;
}

if (!isset($sections[$section])) {
    $sections[$section] = ['lines' => [], 'order' => count($order)];
    $order[] = $section;
}

$sections[$section]['lines'] = build_section_lines($values, $section, $sections[$section]['lines']);

if (!copy($confPath, $bakPath)) {
    json_out(['ok'=>false,'error'=>'Could not write backup file']);
}

$output = [];
foreach ($order as $sec) {
    $output[] = "[$sec]";
    foreach ($sections[$sec]['lines'] as $line) {
        $output[] = $line;
    }
    $output[] = '';
}

$written = file_put_contents($confPath, implode("\n", $output));
if ($written === false) {
    json_out(['ok'=>false,'error'=>'Could not write config file — check permissions']);
}

json_out(['ok'=>true]);
