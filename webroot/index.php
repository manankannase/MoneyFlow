<?php
/**
 * Index — redirect to dashboard or login
 */
require_once __DIR__ . '/../utilities/security.php';
require_once __DIR__ . '/../utilities/session.php';

sendSecurityHeaders();

$session = validateSession();
if ($session) {
    header('Location: /dashboard.php');
} else {
    header('Location: /login.php');
}
exit;
