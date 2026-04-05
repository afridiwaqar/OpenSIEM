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

$u = current_user();
if (($u['role'] ?? '') !== 'admin') json_out(['ok'=>false,'error'=>'admin only']);

$db  = pdo();
$in  = json_decode(file_get_contents('php://input'), true) ?: [];
$action = $in['action'] ?? '';

function b(mixed $v): string { return (!empty($v) && $v !== 'false' && $v !== '0') ? 'true' : 'false'; }

try {
  if ($action === 'create_user') {
    $username = trim($in['username'] ?? '');
    $email    = trim($in['email']    ?? '');
    $role     = $in['role']     ?? 'viewer';
    $password = $in['password'] ?? '';
    $perm     = $in['permissions'] ?? [];

    if ($username === '') throw new Exception('username required');
    if ($email    === '') throw new Exception('email required');
    if ($password === '') throw new Exception('password required');

    $hash = password_hash($password, PASSWORD_BCRYPT);

    $st = $db->prepare("
      INSERT INTO login(username, email, password_hash, role, is_active, is_verified)
      VALUES(:u, :e, :p, :r, true, true)
      RETURNING user_id
    ");
    $st->execute([':u'=>$username, ':e'=>$email, ':p'=>$hash, ':r'=>$role]);
    $uid = (int)$st->fetchColumn();

    $st = $db->prepare("
      INSERT INTO user_permissions(user_id, can_create, can_read, can_update, can_delete)
      VALUES(:id, :c::boolean, :r::boolean, :u::boolean, :d::boolean)
      ON CONFLICT (user_id) DO UPDATE
        SET can_create = EXCLUDED.can_create,
            can_read   = EXCLUDED.can_read,
            can_update = EXCLUDED.can_update,
            can_delete = EXCLUDED.can_delete
    ");
    $st->execute([
      ':id' => $uid,
      ':c'  => b($perm['can_create'] ?? false),
      ':r'  => b($perm['can_read']   ?? true),
      ':u'  => b($perm['can_update'] ?? false),
      ':d'  => b($perm['can_delete'] ?? false),
    ]);

    json_out(['ok'=>true, 'user_id'=>$uid]);
    return;
  }

  if ($action === 'update_user') {
    $uid      = (int)($in['user_id'] ?? 0);
    $username = trim($in['username'] ?? '');
    $email    = trim($in['email']    ?? '');
    $role     = $in['role']     ?? null;
    $password = $in['password'] ?? '';
    $perm     = $in['permissions'] ?? null;

    if (!$uid) throw new Exception('user_id required');

    if ($password !== '') {
      $hash = password_hash($password, PASSWORD_BCRYPT);
      $db->prepare("UPDATE login SET password_hash=:p WHERE user_id=:id")
         ->execute([':p'=>$hash, ':id'=>$uid]);
    }

    if ($username !== '' || $email !== '' || $role !== null) {
      $db->prepare("
        UPDATE login
        SET username = COALESCE(NULLIF(:u,''), username),
            email    = COALESCE(NULLIF(:e,''), email),
            role     = COALESCE(:r, role)
        WHERE user_id = :id
      ")->execute([':u'=>$username, ':e'=>$email, ':r'=>$role, ':id'=>$uid]);
    }

    if (is_array($perm)) {
      $st = $db->prepare("
        INSERT INTO user_permissions(user_id, can_create, can_read, can_update, can_delete)
        VALUES(:id, :c::boolean, :r::boolean, :u::boolean, :d::boolean)
        ON CONFLICT (user_id) DO UPDATE
          SET can_create = EXCLUDED.can_create,
              can_read   = EXCLUDED.can_read,
              can_update = EXCLUDED.can_update,
              can_delete = EXCLUDED.can_delete
      ");
      $st->execute([
        ':id' => $uid,
        ':c'  => b($perm['can_create'] ?? false),
        ':r'  => b($perm['can_read']   ?? true),
        ':u'  => b($perm['can_update'] ?? false),
        ':d'  => b($perm['can_delete'] ?? false),
      ]);
    }

    json_out(['ok'=>true]);
    return;
  }

  if ($action === 'delete_user') {
    $uid = (int)($in['user_id'] ?? 0);
    if (!$uid) throw new Exception('user_id required');
    if (($u['user_id'] ?? 0) === $uid) throw new Exception('cannot delete yourself');

    $db->prepare("DELETE FROM user_permissions WHERE user_id=:id")->execute([':id'=>$uid]);
    $db->prepare("DELETE FROM login WHERE user_id=:id")->execute([':id'=>$uid]);
    json_out(['ok'=>true]);
    return;
  }

  throw new Exception('unknown action');

} catch (Throwable $e) {
  json_out(['ok'=>false, 'error'=>$e->getMessage()]);
}
