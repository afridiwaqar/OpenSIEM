<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../config/auth.php';
require_login();
require_perm('read');

$xmlPath = '/etc/opensiem/stats/ClientStats.xml';

if (!file_exists($xmlPath)) {
    $xmlPath = __DIR__ . '/../shared/xml/ClientStats.xml';
}

if (!file_exists($xmlPath)) {
    json_out([]);
    return;
}

$xml = @simplexml_load_file($xmlPath);
$out = [];

if ($xml && isset($xml->System)) {
    foreach ($xml->System as $sys) {
        // CPU
        $cpuTotal = null; $cpuCores = [];
        if ($sys->CPUUsage) {
            $cpuTotal = (string)($sys->CPUUsage['Total'] ?? '');
            foreach ($sys->CPUUsage->children() as $core) {
                $cpuCores[] = (string)$core;
            }
        }

        // RAM
        $ramTotal = $ramUsed = $ramAvailable = $ramPct = null;
        if ($sys->RAMUsage) {
            $ramTotal     = (string)($sys->RAMUsage['Total']      ?? '');
            $ramUsed      = (string)($sys->RAMUsage['Used']       ?? '');
            $ramAvailable = (string)($sys->RAMUsage['Available']  ?? '');
            $ramPct       = (string)($sys->RAMUsage['Percentage'] ?? '');
        }

        // Disk
        $diskTotal = $diskUsed = $diskFree = $diskPct = null;
        if ($sys->DiskUsage) {
            $diskTotal = (string)($sys->DiskUsage['Total']      ?? '');
            $diskUsed  = (string)($sys->DiskUsage['Used']       ?? '');
            $diskFree  = (string)($sys->DiskUsage['Free']       ?? '');
            $diskPct   = (string)($sys->DiskUsage['Percentage'] ?? '');
        }

        // Services
        $services = [];
        if ($sys->ServiceStatus) {
            foreach ($sys->ServiceStatus->Service as $svc) {
                $services[] = [
                    'name'   => (string)($svc['Name']   ?? ''),
                    'status' => (string)($svc['Status'] ?? ''),
                ];
            }
        }

        $out[] = [
            'id'            => (string)($sys['ID']        ?? ''),
            'given_name'    => (string)($sys['GivenName'] ?? ''),
            'cpu_total'     => $cpuTotal,
            'cpu_cores'     => $cpuCores,
            'ram_total'     => $ramTotal,
            'ram_used'      => $ramUsed,
            'ram_available' => $ramAvailable,
            'ram_pct'       => $ramPct,
            'disk_total'    => $diskTotal,
            'disk_used'     => $diskUsed,
            'disk_free'     => $diskFree,
            'disk_pct'      => $diskPct,
            'services'      => $services,
        ];
    }
}

json_out($out);
