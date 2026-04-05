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

$in     = json_decode(file_get_contents('php://input'), true) ?: [];
$action = $in['action'] ?? 'create';

const VALID_SEV = ['low', 'mid', 'high'];

try {
    if ($action === 'create') {
        require_perm('create');

        $a   = trim($in['artifacts']  ?? '');
        $iv  = (int)($in['interval']  ?? 0);
        $sev = $in['severity']        ?? 'mid';
        $src = $in['source_url']      ?? null;

        if ($a === '') throw new Exception('artifact required');
        if (!in_array($sev, VALID_SEV, true))
            throw new Exception('Invalid severity. Must be low, mid, or high.');

        $stmt = pdo()->prepare(
            'INSERT INTO malicious_artifacts(artifacts, "interval", severity, source_url)
             VALUES(:a, :i, :s, :u)'
        );
        $stmt->execute([':a' => $a, ':i' => $iv, ':s' => $sev, ':u' => $src ?: null]);
        json_out(['ok' => true]);
        return;
    }

    if ($action === 'delete') {
        require_perm('delete');

        $a = trim($in['artifacts'] ?? '');
        if ($a === '') throw new Exception('artifact required');

        pdo()->prepare('DELETE FROM malicious_artifacts WHERE artifacts = :a')
             ->execute([':a' => $a]);
        json_out(['ok' => true]);
        return;
    }

    if ($action === 'update') {
        require_perm('update');

        $old = trim($in['old_artifacts'] ?? '');
        if ($old === '') throw new Exception('old_artifacts required');

        $a   = isset($in['artifacts'])  ? trim($in['artifacts'])  : null;
        $iv  = isset($in['interval'])   ? (int)$in['interval']    : null;
        $sev = isset($in['severity'])   ? $in['severity']         : null;
        $src = isset($in['source_url']) ? ($in['source_url'] ?: null) : null;

        if ($sev !== null && !in_array($sev, VALID_SEV, true))
            throw new Exception('Invalid severity. Must be low, mid, or high.');

        $stmt = pdo()->prepare(
            'UPDATE malicious_artifacts
                SET artifacts   = COALESCE(:a, artifacts),
                    "interval"  = COALESCE(:i, "interval"),
                    severity    = COALESCE(:s, severity),
                    source_url  = COALESCE(:u, source_url)
              WHERE artifacts = :old'
        );
        $stmt->execute([':a' => $a, ':i' => $iv, ':s' => $sev, ':u' => $src, ':old' => $old]);
        json_out(['ok' => true]);
        return;
    }

    throw new Exception('unknown action: ' . $action);

} catch (Exception $e) {
    json_out(['ok' => false, 'error' => $e->getMessage()], 400);
}
