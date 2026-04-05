<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
require_once __DIR__.'/../../config/auth.php';
require_login();
require_perm('read');

$stmt = pdo()->query("SELECT artifacts, \"interval\", severity, added_at, source_url FROM malicious_artifacts ORDER BY added_at DESC");
json_out($stmt->fetchAll(PDO::FETCH_ASSOC));
