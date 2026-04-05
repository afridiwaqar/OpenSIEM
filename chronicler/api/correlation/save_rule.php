<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__.'/../../config/auth.php';
require_login();
require_csrf();

function pg_bool($val): string {
    return (!empty($val) && $val !== 'false' && $val !== '0') ? 'true' : 'false';
}

function pg_int_bool($val): int {
    return (!empty($val) && $val !== 'false' && $val !== '0') ? 1 : 0;
}

$in     = json_decode(file_get_contents('php://input'), true) ?: [];
$action = $in['action'] ?? 'create_use_case';

try {
    if ($action === 'create_use_case') {
        require_perm('create');
        $name   = trim($in['case_name']    ?? '');
        $entity = trim($in['entity_field'] ?? 'ip');
        if ($name === '') throw new Exception('case_name required');

        $stmt = pdo()->prepare(
            "INSERT INTO use_cases(case_name, entity_field)
             VALUES(:n, :e)
             RETURNING case_id"
        );
        $stmt->execute([':n' => $name, ':e' => $entity]);
        $newId = $stmt->fetchColumn();
        json_out(['ok' => true, 'case_id' => (int)$newId]);
        return;
    }

    if ($action === 'delete_use_case') {
        require_perm('delete');
        $cid = (int)($in['case_id'] ?? 0);
        if (!$cid) throw new Exception('case_id required');
        pdo()->prepare("DELETE FROM special_messages WHERE case_id_fk=:c")->execute([':c' => $cid]);
        pdo()->prepare("DELETE FROM use_cases WHERE case_id=:c")->execute([':c' => $cid]);
        json_out(['ok' => true]);
        return;
    }

    if ($action === 'add_rule') {
        require_perm('create');
        $cid    = (int)($in['case_id'] ?? 0);
        $msg    = $in['message'] ?? '';
        if (!$cid) throw new Exception('case_id required');
        if ($msg === '') throw new Exception('message required');

        $repeat = pg_bool($in['can_repeat'] ?? false);   // 'true' | 'false'
        $order  = pg_int_bool($in['order']  ?? false);   // 1 | 0

        $stmt = pdo()->prepare(
            'INSERT INTO special_messages(case_id_fk, message, can_repeat, "order")
             VALUES(:c, :m, :r, :o)
             RETURNING msg_id'
        );
        $stmt->execute([':c' => $cid, ':m' => $msg, ':r' => $repeat, ':o' => $order]);
        json_out(['ok' => true, 'msg_id' => (int)$stmt->fetchColumn()]);
        return;
    }

    if ($action === 'delete_rule') {
        require_perm('delete');
        $msg_id = (int)($in['msg_id'] ?? 0);
        if (!$msg_id) throw new Exception('msg_id required');
        pdo()->prepare('DELETE FROM special_messages WHERE msg_id=:m')->execute([':m' => $msg_id]);
        json_out(['ok' => true]);
        return;
    }

    if ($action === 'update_rule') {
        require_perm('update');
        $msg_id = (int)($in['msg_id'] ?? 0);
        if (!$msg_id) throw new Exception('msg_id required');

        $msg    = isset($in['message'])    ? $in['message']              : null;
        $repeat = isset($in['can_repeat']) ? pg_bool($in['can_repeat'])  : null;
        $order  = isset($in['order'])      ? pg_int_bool($in['order'])   : null;

        $stmt = pdo()->prepare(
            'UPDATE special_messages
                SET message    = COALESCE(:m, message),
                    can_repeat = COALESCE(:r::boolean, can_repeat),
                    "order"    = COALESCE(:o, "order")
              WHERE msg_id = :id'
        );
        $stmt->execute([':m' => $msg, ':r' => $repeat, ':o' => $order, ':id' => $msg_id]);
        json_out(['ok' => true]);
        return;
    }

    if ($action === 'update_use_case') {
        require_perm('update');
        $cid    = (int)($in['case_id'] ?? 0);
        $name   = trim($in['case_name']    ?? '');
        $entity = trim($in['entity_field'] ?? 'ip');
        if (!$cid)  throw new Exception('case_id required');
        if (!$name) throw new Exception('case_name required');

        $stmt = pdo()->prepare(
            "UPDATE use_cases
                SET case_name    = :n,
                    entity_field = :e
              WHERE case_id = :c"
        );
        $stmt->execute([':n' => $name, ':e' => $entity, ':c' => $cid]);
        json_out(['ok' => true]);
        return;
    }

    throw new Exception('unknown action: ' . $action);

} catch (Exception $e) {
    json_out(['ok' => false, 'error' => $e->getMessage()], 400);
}
