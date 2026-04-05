<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/
function pdo() {
    static $pdo = null;
    if ($pdo) return $pdo;

    $dsn = "pgsql:host=127.0.0.1;port=5432;dbname=museum;options='--client_encoding=UTF8'";
    $user = "waqar";
    $pass = "12345";

    $pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    return $pdo;
}
