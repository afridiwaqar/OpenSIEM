<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__ . '/../../config/auth.php';
require_login(); require_perm('read');

$sql = "
  SELECT l.user_id, l.username, l.email, l.role, l.is_active, l.is_verified,
         COALESCE(up.can_create,false) AS can_create,
         COALESCE(up.can_read,true) AS can_read,
         COALESCE(up.can_update,false) AS can_update,
         COALESCE(up.can_delete,false) AS can_delete
  FROM login l
  LEFT JOIN user_permissions up ON up.user_id = l.user_id
  ORDER BY l.user_id ASC
";
$rows = pdo()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
json_out($rows);
