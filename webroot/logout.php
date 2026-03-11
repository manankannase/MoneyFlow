<?php
/**
 * Logout — destroy session and redirect to login
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';

sendSecurityHeaders();

destroySession();
header('Location: /login.php');
exit;
