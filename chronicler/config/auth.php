<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/session.php';

function json_out($data, int $code=200) {
  http_response_code($code);
  header('Content-Type: application/json');
  echo json_encode($data);
  exit;
}

function csrf_token() {
  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
  }
  return $_SESSION['csrf'];
}
function require_csrf() {
  $hdr = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
  if (!$hdr || !hash_equals($_SESSION['csrf'] ?? '', $hdr)) {
    json_out(['ok'=>false, 'error'=>'CSRF token invalid'], 403);
  }
}

function current_user() {
  return $_SESSION['user'] ?? null;
}

function require_login() {
  if (!current_user()) json_out(['ok'=>false, 'error'=>'auth required'], 401);
}

function require_perm(string $action) {
  $u = current_user();
  if (!$u) json_out(['ok'=>false, 'error'=>'auth required'], 401);
  if (($u['role'] ?? '') === 'admin') return;

  $perm = $_SESSION['permissions'] ?? [];
  $map = [
    'create' => 'can_create',
    'read'   => 'can_read',
    'update' => 'can_update',
    'delete' => 'can_delete',
  ];
  $key = $map[$action] ?? null;
  if (!$key || empty($perm[$key])) {
    json_out(['ok'=>false, 'error'=>"permission denied: {$action}"], 403);
  }
}

function load_permissions($user_id) {
  $stmt = pdo()->prepare("SELECT can_create, can_read, can_update, can_delete FROM user_permissions WHERE user_id=:id");
  $stmt->execute([':id'=>$user_id]);
  $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['can_create'=>0,'can_read'=>1,'can_update'=>0,'can_delete'=>0];
  $_SESSION['permissions'] = array_map('boolval', $row);
}

function find_user_for_login($identifier) {
  $stmt = pdo()->prepare("SELECT user_id, username, email, password_hash, role, is_active, is_verified FROM login WHERE username=:id OR email=:id LIMIT 1");
  $stmt->execute([':id'=>$identifier]);
  return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

function login_user($identifier, $password) {
  $u = find_user_for_login($identifier);
  if (!$u) return [false, 'user not found'];

  if (!$u['is_active']) return [false, 'account disabled'];

  if (!password_verify($password, $u['password_hash'])) {
    return [false, 'invalid credentials'];
  }
  $_SESSION['user'] = [
    'user_id' => (int)$u['user_id'],
    'username'=> $u['username'],
    'email'   => $u['email'],
    'role'    => $u['role'],
  ];
  load_permissions((int)$u['user_id']);
  csrf_token();
  return [true, null];
}

function logout_user() {
  $_SESSION = [];
  if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
  }
  session_destroy();
}
