<?php
require_once __DIR__ . '/../utilities/session.php';
sendSecurityHeaders();
if (!validateSession()) { http_response_code(401); exit; }
$file = $_GET['file'] ?? '';
if (!preg_match('/^[a-f0-9]{64}\.png$/D', $file)) { http_response_code(404); exit; }
$path = '/var/lib/moneyflow/avatars/' . $file;
if (!is_file($path)) { http_response_code(404); exit; }
header('Content-Type: image/png');
header('Content-Disposition: inline; filename="avatar.png"');
readfile($path);
