<?php
/*
 OpenSIEM - Security Information & Event Management
 Copyright (c) 2024–present
 Licensed under GNU GPL v3.0
 See LICENSE for details.
*/

session_name('chronicler_sid');

$cookieParams = [
  'lifetime' => 0,
  'path' => '/',
  'domain' => '',
  'secure' => false,       // set true when you enable HTTPS
  'httponly' => true,
  'samesite' => 'Lax',
];

if (PHP_VERSION_ID >= 70300) {
  session_set_cookie_params($cookieParams);
} else {
  session_set_cookie_params(
    $cookieParams['lifetime'],
    $cookieParams['path'].'; samesite='.$cookieParams['samesite'],
    $cookieParams['domain'],
    $cookieParams['secure'],
    $cookieParams['httponly']
  );
}

if (session_status() !== PHP_SESSION_ACTIVE) {
  session_start();
}
