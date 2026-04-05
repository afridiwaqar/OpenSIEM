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

$BASE = '/etc/opensiem/stats';
$ratesFile   = $BASE . '/socket_rates.xml';
$globalFile  = $BASE . '/socket_global.xml';
$clientsFile = $BASE . '/socket_clients.xml';

function safe_load_xml($path) {
    if (!is_readable($path)) return null;
    $xml = @simplexml_load_file($path);
    return $xml ?: null;
}

$eps    = null;
$mbps   = null;
$source = 'none';

// Primary: socket_rates.xml — <SocketRates><MessagesPerMinute>...<BytesPerSecond>...
if ($x = safe_load_xml($ratesFile)) {
    $mpm  = (float)($x->MessagesPerMinute ?? 0.0);
    $bps  = (float)($x->BytesPerSecond    ?? 0.0);
    $eps  = $mpm / 60.0;
    $mbps = ($bps * 8.0) / 1e6;
    $source = 'rates';
}

// Fallback: socket_global.xml — <SocketStats><TotalMessages>...<UptimeSeconds>...
if ($eps === null || $eps <= 0) {
    if ($g = safe_load_xml($globalFile)) {
        $total = (float)($g->TotalMessages  ?? 0.0);
        $upt   = max(1.0, (float)($g->UptimeSeconds ?? 1.0));
        $eps   = $total / $upt;
        $source = 'global';
    }
}

// Clients: socket_clients.xml — <Clients><Client><Address>...<Messages>...<Bytes>...
$clients = [];
if ($c = safe_load_xml($clientsFile)) {
    foreach ($c->Client as $cl) {
        $clients[] = [
            'address'  => (string)$cl->Address,
            'messages' => (int)$cl->Messages,
            'bytes'    => (int)$cl->Bytes,
        ];
    }
    usort($clients, fn($a, $b) => $b['messages'] <=> $a['messages']);
    $clients = array_slice($clients, 0, 5);
}

json_out([
    'ok'      => true,
    'eps'     => round($eps ?? 0, 2),
    'mbps'    => $mbps !== null ? round($mbps, 3) : null,
    'source'  => $source,
    'clients' => $clients,
]);
